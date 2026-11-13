//! Transactions (SPEC §8.0, INV-9): every writing command takes the exclusive
//! file lock `.own/lock` (LOCK_BUSY if taken, no waiting), journals its work in
//! `.own/txn/<id>/journal.json`, backs up anything it will modify, writes via
//! `.own/tmp/` + rename, and rolls back on failure.
//!
//! Durability: every journal write, every backup file and every `rename` is
//! `fsync`ed (file, then parent directory) *before* the work it protects is
//! considered done. The journal therefore survives a power loss, not only
//! `kill -9`: the recovery path never depends on data that is still in the page
//! cache.
//!
//! Signals: the SIGINT/SIGTERM handler is async-signal-safe — it only calls
//! `write(2)` and `_exit(2)`. It never takes a mutex, reads the journal or
//! touches the filesystem, because a signal can interrupt the very thread that
//! holds those locks (deadlock) and none of those calls are in POSIX's
//! async-signal-safe list. An interrupted run therefore leaves the journal in
//! `started` state, and the next writing command restores the backup and emits
//! `W_TXN_RECOVERED` — the same path as a crash or `kill -9`.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub struct Txn {
    // Debug manually: _lock is a File
    pub id: String,
    pub root: PathBuf,    // project root
    pub txn_dir: PathBuf, // .own/txn/<id>
    _lock: Option<fs::File>,
}

impl std::fmt::Debug for Txn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Txn").field("id", &self.id).finish()
    }
}

static SIG_HANDLER: OnceLock<()> = OnceLock::new();

fn install_signal_handler() {
    SIG_HANDLER.get_or_init(|| {
        // Async-signal-safe handler (INV-9 / SPEC §8.0). Everything except
        // `write(2)` and `_exit(2)` is forbidden here: the signal may interrupt
        // the thread that holds the active-txn mutex (deadlock) or the one
        // mid-`rename`, and `read`/`open`/`copy`/`remove_dir_all` are not in
        // POSIX's async-signal-safe list. So we do NOT roll back here — we
        // leave the journal in `started` state (already on stable storage) and
        // exit with the conventional 128+signal. The next writing command
        // restores the backup under the lock and emits `W_TXN_RECOVERED`.
        unsafe extern "C" fn handler(sig: i32) {
            let msg: &[u8] = match sig {
                libc::SIGINT => b"own: interrupted (SIGINT): transaction journal left in `started` state; the next writing command restores the backup\n",
                _ => b"own: interrupted (SIGTERM): transaction journal left in `started` state; the next writing command restores the backup\n",
            };
            unsafe {
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                libc::_exit(128 + sig);
            }
        }
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handler as *const () as libc::sighandler_t;
            sa.sa_flags = 0;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        }
    });
}

static ACTIVE_TXN: OnceLock<std::sync::Mutex<Option<PathBuf>>> = OnceLock::new();
fn active_txn() -> &'static std::sync::Mutex<Option<PathBuf>> {
    ACTIVE_TXN.get_or_init(|| std::sync::Mutex::new(None))
}

fn rollback_dir(txn_dir: &Path) -> std::io::Result<()> {
    let journal = txn_dir.join("journal.json");
    let content = fs::read_to_string(&journal)?;
    let v: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if v["state"] != "started" {
        return Ok(());
    }
    let root = PathBuf::from(
        v["root"]
            .as_str()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no root"))?,
    );
    let backup = txn_dir.join("backup");
    if let Some(files) = v["backup_files"].as_array() {
        for f in files {
            // new format: {"rel": "...", "flat": "..."}; legacy format: "flat"
            let (rel, flat) = match f {
                serde_json::Value::Object(o) => (
                    o.get("rel")
                        .and_then(|r| r.as_str())
                        .unwrap_or("")
                        .to_string(),
                    o.get("flat")
                        .and_then(|r| r.as_str())
                        .unwrap_or("")
                        .to_string(),
                ),
                serde_json::Value::String(s) => (s.replace("__", "/"), s.clone()),
                _ => continue,
            };
            if rel.is_empty() || flat.is_empty() {
                continue;
            }
            let src = backup.join(&flat);
            let dst = root.join(&rel);
            if src.exists() {
                if let Some(parent) = dst.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&src, &dst)?;
                // the restored bytes are what a later `verify` will read: make
                // them durable before the journal is dropped
                sync_path(&dst)?;
                if let Some(parent) = dst.parent() {
                    sync_dir(parent)?;
                }
            } else {
                let _ = fs::remove_file(&dst);
                if let Some(parent) = dst.parent() {
                    sync_dir(parent)?;
                }
            }
        }
    }
    // remove created dirs (vendor dirs added by this txn)
    if let Some(dirs) = v["created_dirs"].as_array() {
        for d in dirs {
            if let Some(rel) = d.as_str() {
                let p = root.join(rel);
                let _ = fs::remove_dir_all(&p);
                if let Some(parent) = p.parent() {
                    sync_dir(parent)?;
                }
            }
        }
    }
    Ok(())
}

impl Txn {
    /// Take the exclusive lock FIRST, then recover any `started` journal left
    /// by a crash, then start a new transaction. Returns Err("LOCK_BUSY") if
    /// the lock is taken. Recovery under the lock is what prevents a second
    /// `own` from rolling back a transaction the first one is still working on.
    pub fn begin(root: &Path) -> Result<Txn, String> {
        let own = root.join(".own");
        fs::create_dir_all(own.join("tmp")).map_err(|e| format!("IO_ERROR: {e}"))?;
        fs::create_dir_all(own.join("txn")).map_err(|e| format!("IO_ERROR: {e}"))?;
        // make the new directory entries themselves durable (best effort: the
        // strict fsync point is the journal write below)
        let _ = sync_dir(&own);
        let _ = sync_dir(&own.join("txn"));
        // exclusive lock — taken before any journal inspection
        let lock_path = own.join("lock");
        #[cfg(unix)]
        let lock_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o644)
            .open(&lock_path)
            .map_err(|e| format!("IO_ERROR: {e}"))?;
        #[cfg(not(unix))]
        let lock_file = File::create(&lock_path).map_err(|e| format!("IO_ERROR: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = lock_file.as_raw_fd();
            let mut fl = libc::flock {
                l_type: libc::F_WRLCK as i16,
                l_whence: libc::SEEK_SET as i16,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            };
            let r = unsafe { libc::fcntl(fd, libc::F_SETLK, &mut fl) };
            if r != 0 {
                return Err("LOCK_BUSY".to_string());
            }
        }
        // recovery of stale journals — only safe now that we hold the lock
        let txn_root = own.join("txn");
        if let Ok(rd) = fs::read_dir(&txn_root) {
            for e in rd.flatten() {
                let j = e.path().join("journal.json");
                if j.exists() {
                    if let Ok(content) = fs::read_to_string(&j) {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                            if v["state"] == "started" {
                                let _ = rollback_dir(&e.path());
                                let _ = fs::remove_dir_all(e.path());
                                eprintln!("warning: W_TXN_RECOVERED: rolled back unfinished transaction {}", e.file_name().to_string_lossy());
                            }
                        }
                    }
                }
            }
        }
        let id = format!("{:x}", randish());
        let txn_dir = txn_root.join(&id);
        fs::create_dir_all(txn_dir.join("backup")).map_err(|e| format!("IO_ERROR: {e}"))?;
        let journal = serde_json::json!({
            "state": "started",
            "id": id,
            "root": root.to_string_lossy(),
            "backup_files": [],
            "created_dirs": [],
        });
        write_journal(&txn_dir, &journal)?;
        install_signal_handler();
        *active_txn().lock().unwrap() = Some(txn_dir.clone());
        Ok(Txn {
            id,
            root: root.to_path_buf(),
            txn_dir,
            _lock: Some(lock_file),
        })
    }

    /// Back up `rel` (relative to root) before modifying it.
    pub fn backup(&self, rel: &str) -> Result<(), String> {
        let src = self.root.join(rel);
        // backup under a flat name: '/' -> "__" UNLESS the path already
        // contains a literal "__", in which case the name is suffixed with
        // "~<sha256-16>" so it round-trips unambiguously (e.g.
        // "@types+babel__core" must not decode to "@types+babel/core").
        let flat = if rel.contains("__") {
            format!("{}~{}", rel.replace('/', "__"), sha256_hex16(rel))
        } else {
            rel.replace('/', "__")
        };
        let dst = self.txn_dir.join("backup").join(&flat);
        if src.is_dir() {
            copy_dir(&src, &dst).map_err(|e| format!("IO_ERROR: {e}"))?;
            sync_tree(&dst).map_err(|e| format!("IO_ERROR: {e}"))?;
        } else if src.exists() {
            if let Some(p) = dst.parent() {
                fs::create_dir_all(p).map_err(|e| format!("IO_ERROR: {e}"))?;
            }
            fs::copy(&src, &dst).map_err(|e| format!("IO_ERROR: {e}"))?;
            sync_path(&dst).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        // journal stores the ORIGINAL relative path alongside the flat name.
        // It is written (and fsynced) only after the backup itself is durable:
        // recovery must never point at a backup that is not on disk yet.
        let mut j = read_journal(&self.txn_dir)?;
        j["backup_files"]
            .as_array_mut()
            .ok_or("IO_ERROR: journal")?
            .push(serde_json::json!({"rel": rel, "flat": flat}));
        write_journal(&self.txn_dir, &j)
    }

    pub fn note_created_dir(&self, rel: &str) -> Result<(), String> {
        let mut j = read_journal(&self.txn_dir)?;
        j["created_dirs"]
            .as_array_mut()
            .ok_or("IO_ERROR: journal")?
            .push(serde_json::Value::String(rel.to_string()));
        write_journal(&self.txn_dir, &j)
    }

    /// Write `content` to `rel` atomically: write to `.own/tmp/` then rename.
    pub fn write_file(&self, rel: &str, content: &[u8]) -> Result<(), String> {
        self.backup(rel)?;
        let tmp = self.root.join(".own/tmp").join(format!("{}.tmp", self.id));
        {
            let mut f = File::create(&tmp).map_err(|e| format!("IO_ERROR: {e}"))?;
            f.write_all(content).map_err(|e| format!("IO_ERROR: {e}"))?;
            // the temporary must be durable before the rename publishes it
            f.sync_all().map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        let dst = self.root.join(rel);
        if let Some(p) = dst.parent() {
            fs::create_dir_all(p).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        fs::rename(&tmp, &dst).map_err(|e| format!("IO_ERROR: rename across filesystems: {e}"))?;
        // the rename itself is durable only once its parent directory is synced
        if let Some(p) = dst.parent() {
            sync_dir(p).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        Ok(())
    }

    /// Rename a prepared directory (e.g. extracted vendor dir) into place.
    pub fn move_dir_into(&self, src_abs: &Path, rel: &str) -> Result<(), String> {
        self.backup(rel)?;
        let dst = self.root.join(rel);
        if dst.exists() {
            return Err("VENDOR_DIR_EXISTS".to_string());
        }
        if let Some(p) = dst.parent() {
            fs::create_dir_all(p).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        // the prepared tree must be on stable storage before it is published
        sync_tree(src_abs).map_err(|e| format!("IO_ERROR: {e}"))?;
        fs::rename(src_abs, &dst).map_err(|e| format!("IO_ERROR: {e}"))?;
        if let Some(p) = dst.parent() {
            sync_dir(p).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        self.note_created_dir(rel)?;
        Ok(())
    }

    pub fn commit(self) -> Result<(), String> {
        let mut j = read_journal(&self.txn_dir)?;
        j["state"] = serde_json::Value::String("committed".to_string());
        write_journal(&self.txn_dir, &j)?;
        *active_txn().lock().unwrap() = None;
        let parent = self.txn_dir.parent().map(|p| p.to_path_buf());
        fs::remove_dir_all(&self.txn_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
        if let Some(p) = parent {
            sync_dir(&p).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        Ok(())
    }

    pub fn rollback(&self) -> Result<(), String> {
        rollback_dir(&self.txn_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
        *active_txn().lock().unwrap() = None;
        let parent = self.txn_dir.parent().map(|p| p.to_path_buf());
        let _ = fs::remove_dir_all(&self.txn_dir);
        if let Some(p) = parent {
            sync_dir(&p).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        Ok(())
    }
}

fn read_journal(txn_dir: &Path) -> Result<serde_json::Value, String> {
    let c =
        fs::read_to_string(txn_dir.join("journal.json")).map_err(|e| format!("IO_ERROR: {e}"))?;
    serde_json::from_str(&c).map_err(|e| format!("PARSE_ERROR: {e}"))
}

fn write_journal(txn_dir: &Path, j: &serde_json::Value) -> Result<(), String> {
    let c = serde_json::to_string(j).map_err(|e| format!("IO_ERROR: {e}"))?;
    let path = txn_dir.join("journal.json");
    let mut f = File::create(&path).map_err(|e| format!("IO_ERROR: {e}"))?;
    f.write_all(c.as_bytes())
        .map_err(|e| format!("IO_ERROR: {e}"))?;
    // Durability (INV-9): the journal must be on stable storage before the work
    // it describes starts. Without this fsync a power loss can leave a modified
    // working tree with a journal that never made it to disk.
    f.sync_all().map_err(|e| format!("IO_ERROR: {e}"))?;
    drop(f);
    sync_dir(txn_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
    Ok(())
}

/// `fsync` a file so that its bytes are on stable storage.
fn sync_path(p: &Path) -> std::io::Result<()> {
    File::open(p)?.sync_all()
}

/// `fsync` a directory so that creations, renames and removals inside it are
/// durable (`fsync` on a directory is a no-op on platforms that refuse to open
/// one, e.g. Windows).
fn sync_dir(p: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(p)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        Ok(())
    }
}

/// `fsync` every regular file of a tree, depth first, then the directories.
/// Used before a prepared tree is renamed into place or is recorded as the
/// rollback copy of an existing tree.
fn sync_tree(dir: &Path) -> std::io::Result<()> {
    for e in fs::read_dir(dir)? {
        let e = e?;
        let ty = e.file_type()?;
        if ty.is_dir() {
            sync_tree(&e.path())?;
            sync_dir(&e.path())?;
        } else if ty.is_file() {
            sync_path(&e.path())?;
        }
    }
    sync_dir(dir)
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    copy_dir_inner(src, dst, &mut Vec::new())
}

/// Copy preserving the tree under `dst`, but each path component is sanitized
/// and capped so deep trees cannot exceed NAME_MAX (255).
fn copy_dir_inner(src: &Path, dst: &Path, prefix: &mut Vec<String>) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let ty = e.file_type()?;
        let mut name = e.file_name().to_string_lossy().replace('/', "__");
        if name.len() > 200 {
            let h: String = {
                use sha2::{Digest, Sha256};
                Sha256::digest(name.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            };
            name = format!("{}~{}", &name[..120], &h[..32]);
        }
        let d = dst.join(&name);
        prefix.push(name);
        if ty.is_dir() {
            copy_dir_inner(&e.path(), &d, prefix)?;
        } else {
            fs::copy(e.path(), &d)?;
        }
        prefix.pop();
    }
    Ok(())
}

fn randish() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    t ^ (pid << 32) ^ (t.rotate_left(17))
}

/// First 16 hex chars of the sha256 of `s` — used to disambiguate backup
/// names that contain a literal "__" (see `Txn::backup`).
fn sha256_hex16(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(s.as_bytes());
    h[..8].iter().map(|b| format!("{b:02x}")).collect()
}
