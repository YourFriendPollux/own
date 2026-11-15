//! Transactions (SPEC §8.0, INV-9): every writing command takes the exclusive
//! file lock `.own/lock` (LOCK_BUSY if taken, no waiting), journals its work in
//! `.own/txn/<id>/journal.json`, backs up anything it will modify, writes via
//! `.own/tmp/` + rename, and rolls back on failure.
//!
//! Durability ordering: backups and replacement journals are synced before
//! publishing changes; directory entries are synced before returning success.
//! Crash recovery is tested. Actual power-loss behavior also depends on the
//! filesystem and storage hardware and is not established by these tests.
//!
//! Signals: the SIGINT/SIGTERM handler is async-signal-safe — it only calls
//! `write(2)` and `_exit(2)`. It never takes a mutex, reads the journal or
//! touches the filesystem, because a signal can interrupt the very thread that
//! holds those locks (deadlock) and none of those calls are in POSIX's
//! async-signal-safe list. An interrupted run therefore leaves the journal in
//! `started` state, and the next writing command restores the backup and emits
//! `W_TXN_RECOVERED` — the same path as a crash or `kill -9`.

use crate::path_safety::{checked_absolute, checked_path, validate_relative};
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
    operation: std::sync::Mutex<()>,
    finished: std::sync::atomic::AtomicBool,
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

fn validate_mutation_path(rel: &str) -> std::io::Result<()> {
    validate_relative(rel)?;
    if rel == ".git"
        || rel.starts_with(".git/")
        || rel == ".own"
        || rel == ".own/lock"
        || rel.starts_with(".own/lock/")
        || rel == ".own/txn"
        || rel.starts_with(".own/txn/")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "transaction control path cannot be a mutation target",
        ));
    }
    Ok(())
}

fn take_exclusive_lock(file: &File) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = file.as_raw_fd();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let result = {
            // OFD locks conflict with legacy POSIX locks but belong to this
            // descriptor, not the process. Closing an unrelated fd is safe.
            let mut lock = libc::flock {
                l_type: libc::F_WRLCK as i16,
                l_whence: libc::SEEK_SET as i16,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            };
            unsafe { libc::fcntl(fd, libc::F_OFD_SETLK, &mut lock) }
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::EACCES) | Some(libc::EAGAIN)
        ) {
            return Err("LOCK_BUSY".into());
        }
        Err(format!("IO_ERROR: exclusive transaction lock: {error}"))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err("IO_ERROR: transaction locking is unsupported on this platform".into())
    }
}

fn rollback_dir(txn_dir: &Path, root: &Path) -> std::io::Result<()> {
    checked_absolute(root, txn_dir)?;
    let journal_path = txn_dir.join("journal.json");
    // The journal and the backup dir are ours, but a planted symlink must be
    // refused before any read: only real files/directories are accepted.
    for p in [&journal_path, &txn_dir.join("backup")] {
        match fs::symlink_metadata(p) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unsafe txn path component: {}", p.display()),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    checked_absolute(root, &journal_path)?;
    checked_absolute(root, &txn_dir.join("backup"))?;
    let content = fs::read_to_string(txn_dir.join("journal.json"))?;
    let v: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    validate_journal_root(&v, root)?;
    match v["state"].as_str() {
        Some("committed") => return Ok(()),
        Some("started") => {}
        _ => return Err(invalid_journal("invalid state")),
    }
    let backup = txn_dir.join("backup");
    // The backup dir is ours, but a planted symlink at that exact path must be
    // refused before any traversal into it.
    match fs::symlink_metadata(&backup) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe txn path component: {}", backup.display()),
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // Validate the complete journal and available originals before any removal.
    // Legacy entries have no existence flag: missing backup means absent path.
    let mut files = Vec::new();
    for f in v["backup_files"]
        .as_array()
        .ok_or_else(|| invalid_journal("no backup_files"))?
    {
        let (rel, flat, existed) = match f {
            serde_json::Value::Object(o) => (
                o.get("rel")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| invalid_journal("no rel"))?
                    .to_string(),
                o.get("flat")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| invalid_journal("no flat"))?
                    .to_string(),
                o.get("existed")
                    .map(|v| {
                        v.as_bool()
                            .ok_or_else(|| invalid_journal("invalid existed"))
                    })
                    .transpose()?,
            ),
            serde_json::Value::String(s) => (s.replace("__", "/"), s.clone(), None),
            _ => return Err(invalid_journal("invalid backup entry")),
        };
        validate_mutation_path(&rel)?;
        validate_relative(&flat)?;
        if Path::new(&flat).components().count() != 1 {
            return Err(invalid_journal("backup name is not flat"));
        }
        let dst = checked_path(root, &rel)?;
        // The backup copy lives in our own journal tree and may legitimately be
        // a symlink (copy_dir preserves it): validate it against the txn tree
        // instead of the project root, whose leaf rules would reject it.
        let src = checked_txn_path(txn_dir, &backup.join(flat))?;
        let present = match fs::symlink_metadata(&src) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e),
        };
        if existed == Some(true) && !present {
            return Err(invalid_journal("missing original backup"));
        }
        files.push((dst, src, existed != Some(false) && present));
    }
    let mut dirs = Vec::new();
    for d in v["created_dirs"]
        .as_array()
        .ok_or_else(|| invalid_journal("no created_dirs"))?
    {
        let rel = d
            .as_str()
            .ok_or_else(|| invalid_journal("invalid created dir"))?;
        validate_mutation_path(rel)?;
        dirs.push(checked_path(root, rel)?);
    }
    // A replaced tree can also be in created_dirs. Clean it before restoring.
    for p in dirs {
        remove_path(&p)?;
        sync_existing_parent(&p)?;
    }
    for (dst, src, restore) in files {
        remove_path(&dst)?;
        if restore {
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)?;
            }
            if src.is_dir() {
                copy_dir(&src, &dst)?;
                sync_tree(&dst)?;
            } else if fs::symlink_metadata(&src)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                // The original leaf was a symlink: restore the link itself,
                // never its target's content (fs::copy would follow it).
                #[cfg(unix)]
                {
                    std::os::unix::fs::symlink(fs::read_link(&src)?, &dst)?;
                    sync_existing_parent(&dst)?;
                }
                #[cfg(not(unix))]
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "cannot restore backup symlink on this platform",
                    ));
                }
            } else {
                fs::copy(&src, &dst)?;
                sync_path(&dst)?;
            }
        }
        sync_existing_parent(&dst)?;
    }
    Ok(())
}

fn invalid_journal(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Validate a path inside the transaction's own bookkeeping tree
/// (`.own/txn/<id>/...`). Unlike [`checked_path`] on the project root, the
/// leaf may be a symlink: `copy_dir` deliberately preserves symlinks in
/// backups, and recovery must be able to read them back.
fn checked_txn_path(txn_dir: &Path, path: &Path) -> std::io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let rel = absolute
        .strip_prefix(txn_dir)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path outside txn dir"))?
        .to_str()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path is not UTF-8")
        })?;
    validate_relative(rel)?;
    // Every existing ancestor component must be a real directory (no symlink
    // traversal); the leaf itself may be a regular file, directory or symlink.
    let mut p = txn_dir.to_path_buf();
    let parts: Vec<_> = Path::new(rel).components().collect();
    for (i, part) in parts.iter().enumerate() {
        p.push(part.as_os_str());
        match fs::symlink_metadata(&p) {
            Ok(md) => {
                let leaf = i + 1 == parts.len();
                if md.file_type().is_symlink() && !leaf {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unsafe txn path component: {}", p.display()),
                    ));
                }
                if !leaf && !md.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unsafe txn path component: {}", p.display()),
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(p)
}

fn validate_journal_root(j: &serde_json::Value, root: &Path) -> std::io::Result<()> {
    // Never use an untrusted journal root as the restoration destination.
    // Require the exact canonical spelling, not an alias or a relative path.
    let recorded = j["root"]
        .as_str()
        .ok_or_else(|| invalid_journal("no root"))?;
    if Some(recorded) != root.to_str() {
        return Err(invalid_journal(
            "journal root differs from locked canonical root",
        ));
    }
    Ok(())
}

fn remove_path(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn sync_existing_parent(path: &Path) -> std::io::Result<()> {
    let mut parent = path.parent();
    while let Some(p) = parent {
        match fs::metadata(p) {
            Ok(_) => return sync_dir(p),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => parent = p.parent(),
            Err(e) => return Err(e),
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
        // Preserve support for a not-yet-created project, then bind every
        // operation and recovery record to its canonical absolute root.
        fs::create_dir_all(root).map_err(|e| format!("IO_ERROR: {e}"))?;
        let root = fs::canonicalize(root).map_err(|e| format!("IO_ERROR: {e}"))?;
        if root.to_str().is_none() {
            return Err("IO_ERROR: project root is not UTF-8".into());
        }
        let own = root.join(".own");
        checked_path(&root, ".own/lock").map_err(|e| format!("IO_ERROR: {e}"))?;
        fs::create_dir_all(&own).map_err(|e| format!("IO_ERROR: {e}"))?;
        // Only the lock's parent may be created before exclusive ownership.
        sync_dir(&root).map_err(|e| format!("IO_ERROR: {e}"))?;
        sync_dir(&own).map_err(|e| format!("IO_ERROR: {e}"))?;
        // exclusive lock — taken before any journal inspection
        let lock_path = own.join("lock");
        #[cfg(unix)]
        let lock_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o644)
            .open(&lock_path)
            .map_err(|e| format!("IO_ERROR: {e}"))?;
        #[cfg(not(unix))]
        let lock_file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| format!("IO_ERROR: {e}"))?;
        take_exclusive_lock(&lock_file)?;
        // Staging and journal directories are inspected/created only under lock.
        for rel in [".own/tmp", ".own/txn"] {
            checked_path(&root, rel).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        fs::create_dir_all(own.join("tmp")).map_err(|e| format!("IO_ERROR: {e}"))?;
        fs::create_dir_all(own.join("txn")).map_err(|e| format!("IO_ERROR: {e}"))?;
        sync_dir(&own).map_err(|e| format!("IO_ERROR: {e}"))?;
        sync_dir(&own.join("txn")).map_err(|e| format!("IO_ERROR: {e}"))?;
        // recovery of stale journals — only safe now that we hold the lock
        let txn_root = own.join("txn");
        let entries = fs::read_dir(&txn_root).map_err(|e| format!("IO_ERROR: {e}"))?;
        let mut directories = entries
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| format!("IO_ERROR: {e}"))?;
        directories.sort();
        let mut journals = Vec::new();
        // First validate the entire collection. A corrupt later record must
        // not permit an earlier restoration to change the project.
        for dir in directories {
            checked_absolute(&root, &dir).map_err(|e| format!("IO_ERROR: {e}"))?;
            let j = dir.join("journal.json");
            // The journal lives in our own bookkeeping tree and may itself be
            // a symlink planted by an attacker: refuse it before reading.
            if fs::symlink_metadata(&j)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(format!(
                    "IO_ERROR: unsafe txn path component: {}",
                    j.display()
                ));
            }
            checked_absolute(&root, &j).map_err(|e| format!("IO_ERROR: {e}"))?;
            if !j.try_exists().map_err(|e| format!("IO_ERROR: {e}"))? {
                continue;
            }
            let v = read_journal(&dir)?;
            validate_journal_root(&v, &root).map_err(|e| format!("IO_ERROR: {e}"))?;
            let state = v["state"]
                .as_str()
                .filter(|state| matches!(*state, "started" | "committed"))
                .ok_or_else(|| format!("IO_ERROR: invalid journal state: {}", j.display()))?;
            journals.push((dir, state == "started"));
        }
        if journals.iter().filter(|(_, started)| *started).count() > 1 {
            return Err("IO_ERROR: multiple unfinished transactions; recovery order is ambiguous; journals retained".into());
        }
        for (dir, started) in journals {
            if started {
                rollback_dir(&dir, &root)
                    .map_err(|e| format!("IO_ERROR: recovery {}: {e}", dir.display()))?;
                fs::remove_dir_all(&dir).map_err(|e| format!("IO_ERROR: {e}"))?;
                sync_dir(&txn_root).map_err(|e| format!("IO_ERROR: {e}"))?;
                eprintln!(
                    "warning: W_TXN_RECOVERED: rolled back unfinished transaction {}",
                    dir.file_name().unwrap_or_default().to_string_lossy()
                );
            } else {
                // A durable commit is final: discard leftover bookkeeping,
                // never restore its backup after a cleanup interruption.
                fs::remove_dir_all(&dir).map_err(|e| format!("IO_ERROR: {e}"))?;
                sync_dir(&txn_root).map_err(|e| format!("IO_ERROR: {e}"))?;
            }
        }
        let id = format!("{:x}", randish());
        let txn_dir = txn_root.join(&id);
        fs::create_dir(&txn_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
        fs::create_dir_all(txn_dir.join("backup")).map_err(|e| format!("IO_ERROR: {e}"))?;
        // Sync the directory that contains <id>, not just <id> itself. Without
        // this, the durable journal could become unreachable after a crash.
        sync_dir(&txn_root).map_err(|e| format!("IO_ERROR: {e}"))?;
        let journal = serde_json::json!({
            "state": "started",
            "id": id,
            "root": root.to_str().unwrap(),
            "backup_files": [],
            "created_dirs": [],
        });
        write_journal(&txn_dir, &journal)?;
        install_signal_handler();
        Ok(Txn {
            id,
            root: root.to_path_buf(),
            txn_dir,
            _lock: Some(lock_file),
            operation: std::sync::Mutex::new(()),
            finished: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Back up `rel` (relative to root) before modifying it.
    pub fn backup(&self, rel: &str) -> Result<(), String> {
        let _operation = self.operation_guard()?;
        self.backup_inner(rel)
    }

    fn backup_inner(&self, rel: &str) -> Result<(), String> {
        validate_mutation_path(rel).map_err(|e| format!("IO_ERROR: {e}"))?;
        let src = checked_path(&self.root, rel).map_err(|e| format!("IO_ERROR: {e}"))?;
        self.check_metadata()?;
        let mut j = read_journal(&self.txn_dir)?;
        validate_journal_root(&j, &self.root).map_err(|e| format!("IO_ERROR: {e}"))?;
        let files = j["backup_files"].as_array().ok_or("IO_ERROR: journal")?;
        // The first durable entry wins, including when the path was absent.
        // Never replace its backup with an intermediate transaction state.
        if files.iter().any(|entry| match entry {
            serde_json::Value::Object(o) => o.get("rel").and_then(|v| v.as_str()) == Some(rel),
            serde_json::Value::String(flat) => flat.replace("__", "/") == rel,
            _ => false,
        }) {
            return Ok(());
        }
        let existed = match fs::symlink_metadata(&src) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(format!("IO_ERROR: {e}")),
        };
        // backup under a flat name: '/' -> "__" UNLESS the path already
        // contains a literal "__", in which case the name is suffixed with
        // "~<sha256-16>" so it round-trips unambiguously (e.g.
        // "@types+babel__core" must not decode to "@types+babel/core").
        let flat = if rel.contains("__") {
            format!("{}~{}", rel.replace('/', "__"), sha256_hex16(rel))
        } else {
            rel.replace('/', "__")
        };
        let dst = checked_absolute(&self.root, &self.txn_dir.join("backup").join(&flat))
            .map_err(|e| format!("IO_ERROR: {e}"))?;
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
        sync_dir(&self.txn_dir.join("backup")).map_err(|e| format!("IO_ERROR: {e}"))?;
        j["backup_files"]
            .as_array_mut()
            .ok_or("IO_ERROR: journal")?
            .push(serde_json::json!({"rel": rel, "flat": flat, "existed": existed}));
        write_journal(&self.txn_dir, &j)
    }

    pub fn note_created_dir(&self, rel: &str) -> Result<(), String> {
        let _operation = self.operation_guard()?;
        self.note_created_dir_inner(rel)
    }

    fn note_created_dir_inner(&self, rel: &str) -> Result<(), String> {
        validate_mutation_path(rel).map_err(|e| format!("IO_ERROR: {e}"))?;
        checked_path(&self.root, rel).map_err(|e| format!("IO_ERROR: {e}"))?;
        self.check_metadata()?;
        let mut j = read_journal(&self.txn_dir)?;
        validate_journal_root(&j, &self.root).map_err(|e| format!("IO_ERROR: {e}"))?;
        j["created_dirs"]
            .as_array_mut()
            .ok_or("IO_ERROR: journal")?
            .push(serde_json::Value::String(rel.to_string()));
        write_journal(&self.txn_dir, &j)
    }

    /// Write `content` to `rel` atomically: write to `.own/tmp/` then rename.
    pub fn write_file(&self, rel: &str, content: &[u8]) -> Result<(), String> {
        let _operation = self.operation_guard()?;
        self.backup_inner(rel)?;
        let tmp = self.root.join(".own/tmp").join(format!("{}.tmp", self.id));
        checked_absolute(&self.root, &tmp).map_err(|e| format!("IO_ERROR: {e}"))?;
        {
            let mut f = File::create(&tmp).map_err(|e| format!("IO_ERROR: {e}"))?;
            f.write_all(content).map_err(|e| format!("IO_ERROR: {e}"))?;
            // the temporary must be durable before the rename publishes it
            f.sync_all().map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        let dst = checked_path(&self.root, rel).map_err(|e| format!("IO_ERROR: {e}"))?;
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
        let _operation = self.operation_guard()?;
        let src_abs =
            checked_absolute(&self.root, src_abs).map_err(|e| format!("IO_ERROR: {e}"))?;
        if !src_abs.starts_with(self.root.join(".own/tmp")) || !src_abs.is_dir() {
            return Err("IO_ERROR: prepared source must be a directory under .own/tmp".into());
        }
        self.backup_inner(rel)?;
        let dst = checked_path(&self.root, rel).map_err(|e| format!("IO_ERROR: {e}"))?;
        if dst.exists() {
            return Err("VENDOR_DIR_EXISTS".to_string());
        }
        if let Some(p) = dst.parent() {
            fs::create_dir_all(p).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        // the prepared tree must be on stable storage before it is published
        sync_tree(&src_abs).map_err(|e| format!("IO_ERROR: {e}"))?;
        fs::rename(&src_abs, &dst).map_err(|e| format!("IO_ERROR: {e}"))?;
        if let Some(p) = dst.parent() {
            sync_dir(p).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        self.note_created_dir_inner(rel)?;
        Ok(())
    }

    pub fn commit(self) -> Result<(), String> {
        let _operation = self.operation_guard()?;
        self.check_metadata()?;
        let mut j = read_journal(&self.txn_dir)?;
        validate_journal_root(&j, &self.root).map_err(|e| format!("IO_ERROR: {e}"))?;
        j["state"] = serde_json::Value::String("committed".to_string());
        // If writing the commit record fails, retain the journal for recovery;
        // Drop must not treat a partially written commit as a successful one.
        self.finished
            .store(true, std::sync::atomic::Ordering::Relaxed);
        write_journal(&self.txn_dir, &j)?;
        let parent = self.txn_dir.parent().map(|p| p.to_path_buf());
        fs::remove_dir_all(&self.txn_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
        if let Some(p) = parent {
            sync_dir(&p).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        Ok(())
    }

    fn operation_guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, String> {
        // The process/descriptor lock is already held for this object's entire
        // lifetime. Never take it while holding this per-instance mutex.
        let guard = self
            .operation
            .lock()
            .map_err(|_| "IO_ERROR: transaction operation lock poisoned".to_string())?;
        if self.finished.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("IO_ERROR: transaction already finished".into());
        }
        Ok(guard)
    }

    fn check_metadata(&self) -> Result<(), String> {
        for path in [
            self.txn_dir.clone(),
            self.txn_dir.join("journal.json"),
            self.txn_dir.join("backup"),
            self.root.join(".own/tmp"),
        ] {
            checked_absolute(&self.root, &path).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        Ok(())
    }

    pub fn rollback(&self) -> Result<(), String> {
        let _operation = self.operation_guard()?;
        rollback_dir(&self.txn_dir, &self.root).map_err(|e| format!("IO_ERROR: {e}"))?;
        self.finished
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let parent = self.txn_dir.parent().map(|p| p.to_path_buf());
        fs::remove_dir_all(&self.txn_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
        if let Some(p) = parent {
            sync_dir(&p).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        Ok(())
    }
}

impl Drop for Txn {
    fn drop(&mut self) {
        if !self.finished.load(std::sync::atomic::Ordering::Relaxed) {
            if let Err(e) = self.rollback() {
                // Drop cannot return an error. Keep the started journal and
                // backups intact so the next writer fails closed or retries.
                eprintln!(
                    "warning: transaction rollback failed; journal retained at {}: {e}",
                    self.txn_dir.display()
                );
            }
        }
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
    let tmp = txn_dir.join(format!(".journal-{:x}.tmp", randish()));
    // Never truncate the current recovery record. An interrupted/failed write
    // leaves it intact, with at most an unreferenced temporary beside it.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("IO_ERROR: {e}"))?;
    f.write_all(c.as_bytes())
        .map_err(|e| format!("IO_ERROR: {e}"))?;
    // Durability (INV-9): the journal must be on stable storage before the work
    // it describes starts. Without this fsync a power loss can leave a modified
    // working tree with a journal that never made it to disk.
    f.sync_all().map_err(|e| format!("IO_ERROR: {e}"))?;
    drop(f);
    fs::rename(&tmp, &path).map_err(|e| format!("IO_ERROR: {e}"))?;
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
    fs::create_dir_all(dst)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let ty = e.file_type()?;
        // Each component already exists on this filesystem; flattening or
        // truncating it would make the rollback tree differ from the original.
        let d = dst.join(e.file_name());
        if ty.is_dir() {
            copy_dir(&e.path(), &d)?;
        } else if ty.is_symlink() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(fs::read_link(e.path())?, &d)?;
            #[cfg(not(unix))]
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot preserve backup symlink on this platform",
            ));
        } else {
            fs::copy(e.path(), &d)?;
        }
    }
    // Apply directory permissions after copying its children, so read-only
    // directories can still be copied without changing the saved permissions.
    fs::set_permissions(dst, fs::metadata(src)?.permissions())
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
