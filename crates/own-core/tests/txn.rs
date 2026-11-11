//! Transaction tests (SPEC §8.0, INV-9): commit, rollback, crash recovery,
//! LOCK_BUSY, kill -9 recovery via next writer.

use own_core::txn::Txn;
use std::fs;
use std::path::Path;
use std::process::Command;

fn fresh_root() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    fs::write(t.path().join("file.txt"), b"original\n").unwrap();
    t
}

#[test]
fn commit_keeps_changes_and_cleans_journal() {
    let t = fresh_root();
    let txn = Txn::begin(t.path()).unwrap();
    txn.write_file("file.txt", b"changed\n").unwrap();
    txn.commit().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "changed\n"
    );
    assert!(!t
        .path()
        .join(".own/txn")
        .read_dir()
        .unwrap()
        .next()
        .is_some());
}

#[test]
fn rollback_restores_backup() {
    let t = fresh_root();
    let txn = Txn::begin(t.path()).unwrap();
    txn.write_file("file.txt", b"changed\n").unwrap();
    txn.rollback().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "original\n"
    );
}

#[test]
fn rollback_removes_created_dirs() {
    let t = fresh_root();
    let txn = Txn::begin(t.path()).unwrap();
    let prep = t.path().join(".own/tmp/prep");
    fs::create_dir_all(&prep).unwrap();
    fs::write(prep.join("x"), b"1").unwrap();
    txn.move_dir_into(&prep, "vendor/own/pkg@1.0.0").unwrap();
    assert!(t.path().join("vendor/own/pkg@1.0.0/x").exists());
    txn.rollback().unwrap();
    assert!(!t.path().join("vendor/own/pkg@1.0.0").exists());
}

#[test]
fn lock_busy_when_held() {
    // flock is per-process on Linux: hold the lock from a child process
    let t = fresh_root();
    fs::create_dir_all(t.path().join(".own")).unwrap();
    let lockp = t.path().join(".own/lock");
    fs::write(&lockp, b"").unwrap();
    // hold an exclusive fcntl lock from a python child
    let py = "import fcntl,time,sys; f=open(sys.argv[1],'w'); l=fcntl.lockf(f, fcntl.LOCK_EX); print('LOCKED',flush=True); time.sleep(10)";
    let mut holder = Command::new("python3")
        .arg("-c")
        .arg(py)
        .arg(lockp.to_str().unwrap())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Read;
    let mut out = holder.stdout.take().unwrap();
    let mut buf = [0u8; 6];
    out.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"LOCKED");
    let e = Txn::begin(t.path()).unwrap_err();
    assert_eq!(e, "LOCK_BUSY");
    holder.kill().ok();
    holder.wait().ok();
}

#[test]
fn stale_started_journal_is_recovered_by_next_writer() {
    let t = fresh_root();
    // simulate crash: journal started + backup present, file already modified
    let own = t.path().join(".own");
    let txn_dir = own.join("txn").join("deadbeef");
    fs::create_dir_all(txn_dir.join("backup")).unwrap();
    fs::write(txn_dir.join("backup/file.txt"), b"original\n").unwrap();
    fs::write(
        txn_dir.join("journal.json"),
        r#"{"state":"started","id":"deadbeef","root":"__ROOT__","backup_files":["file.txt"],"created_dirs":[]}"#
            .replace("__ROOT__", &t.path().to_string_lossy()),
    )
    .unwrap();
    fs::write(t.path().join("file.txt"), b"crashed\n").unwrap();
    // next writer recovers
    let txn = Txn::begin(t.path()).unwrap();
    txn.commit().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "original\n"
    );
}

#[test]
fn kill9_recovery_in_child_process() {
    // child starts a txn, writes, then gets SIGKILL; parent then begins a new txn
    let t = fresh_root();
    let script = format!(
        r#"use own_core::txn::Txn; use std::path::Path; fn main() {{ let txn = Txn::begin(Path::new("{root}")).unwrap(); txn.write_file("file.txt", b"killed\n").unwrap(); println!("READY"); std::thread::sleep(std::time::Duration::from_secs(30)); }}"#,
        root = t.path().to_string_lossy()
    );
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), script).unwrap();
    let manifest = r#"[package]
name = "kill9child"
version = "0.0.0"
edition = "2021"
[dependencies]
own-core = { path = "__OWN__" }
serde_json = "1"
"#
    .replace(
        "__OWN__",
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("crates")
            .join("own-core")
            .to_string_lossy(),
    );
    fs::write(dir.path().join("Cargo.toml"), manifest).unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::rename(dir.path().join("main.rs"), dir.path().join("src/main.rs")).unwrap();
    let bin = dir.path().join("target/debug/kill9child");
    let status = Command::new("cargo")
        .args([
            "build",
            "--manifest-path",
            dir.path().join("Cargo.toml").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let mut child = Command::new(&bin)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // wait for READY
    use std::io::Read;
    let mut out = child.stdout.take().expect("child stdout");
    let mut buf = [0u8; 5];
    out.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"READY");
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "killed\n"
    );
    // parent (this process) recovers on next begin
    let txn = Txn::begin(t.path()).unwrap();
    txn.commit().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "original\n"
    );
}
