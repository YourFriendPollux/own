//! Transaction tests (SPEC §8.0, INV-9): commit, rollback, crash recovery,
//! LOCK_BUSY, kill -9 recovery via next writer.

use own_core::txn::Txn;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Serializes tests that deliberately leak or contend on the txn lock, so a
/// leaked fd in one test cannot make a parallel sibling fail with LOCK_BUSY.
static LOCK_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fresh_root() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    fs::write(t.path().join("file.txt"), b"original\n").unwrap();
    t
}

#[test]
fn lock_order_same_process_second_writer_cannot_recover_live_transaction() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = fresh_root();
    let first = Txn::begin(root.path()).unwrap();
    first.write_file("file.txt", b"in-progress\n").unwrap();
    let journal = fs::read(first.txn_dir.join("journal.json")).unwrap();
    let second = Txn::begin(root.path());
    assert!(
        matches!(second, Err(ref error) if error == "LOCK_BUSY"),
        "{second:?}"
    );
    assert_eq!(
        fs::read(root.path().join("file.txt")).unwrap(),
        b"in-progress\n"
    );
    assert_eq!(
        fs::read(first.txn_dir.join("journal.json")).unwrap(),
        journal
    );
    first.rollback().unwrap();
}

#[cfg(unix)]
#[test]
fn lock_order_closing_an_unrelated_descriptor_does_not_unlock_the_transaction() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = fresh_root();
    let txn = Txn::begin(root.path()).unwrap();
    drop(fs::File::open(root.path().join(".own/lock")).unwrap());
    let output = Command::new("python3").args(["-c", "import fcntl,sys; f=open(sys.argv[1],'r+'); lock=fcntl.lockf if sys.platform.startswith('linux') else fcntl.flock;\ntry:\n lock(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('ACQUIRED')\nexcept BlockingIOError:\n print('LOCK_BUSY')", root.path().join(".own/lock").to_str().unwrap()]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "LOCK_BUSY");
    txn.commit().unwrap();
}

#[test]
fn lock_order_contender_child() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let Some(root) = std::env::var_os("OWN_LOCK_ORDER_ROOT") else {
        return;
    };
    let result = Txn::begin(Path::new(&root));
    assert!(
        matches!(result, Err(ref error) if error == "LOCK_BUSY"),
        "{result:?}"
    );
}

#[test]
fn lock_order_busy_writer_does_not_create_staging_directories() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = fresh_root();
    let txn = Txn::begin(root.path()).unwrap();
    fs::remove_dir(root.path().join(".own/tmp")).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["lock_order_contender_child", "--exact", "--nocapture"])
        .env("OWN_LOCK_ORDER_ROOT", root.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        !root.path().join(".own/tmp").exists(),
        "LOCK_BUSY caller changed protected staging state"
    );
    fs::create_dir(root.path().join(".own/tmp")).unwrap();
    txn.commit().unwrap();
}

#[test]
fn lock_order_mutation_apis_cannot_replace_the_live_lock() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let mut accepted = Vec::new();
    for api in ["backup", "write_file", "note_created_dir"] {
        let root = fresh_root();
        let txn = Txn::begin(root.path()).unwrap();
        let result = match api {
            "backup" => txn.backup(".own/lock"),
            "write_file" => txn.write_file(".own/lock", b"replacement"),
            _ => txn.note_created_dir(".own/lock"),
        };
        if result.is_ok() {
            accepted.push(api);
        }
    }
    assert!(
        accepted.is_empty(),
        "lock-control mutation accepted: {accepted:?}"
    );
}

#[test]
fn lock_order_recovery_cannot_remove_the_held_lock_file() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = fresh_root();
    let stale = root.path().join(".own/txn/lock-poison");
    fs::create_dir_all(stale.join("backup")).unwrap();
    fs::write(root.path().join(".own/lock"), b"").unwrap();
    let journal = serde_json::to_vec(&serde_json::json!({
        "root": fs::canonicalize(root.path()).unwrap(), "state": "started",
        "backup_files": [], "created_dirs": [".own/lock"]
    }))
    .unwrap();
    fs::write(stale.join("journal.json"), &journal).unwrap();
    let result = Txn::begin(root.path());
    assert!(
        result.is_err(),
        "recovery accepted mutation of the lock control file"
    );
    assert_eq!(fs::read(stale.join("journal.json")).unwrap(), journal);
    assert_eq!(
        fs::read(root.path().join("file.txt")).unwrap(),
        b"original\n"
    );
}

#[test]
fn confinement_cwd_child() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(mode) = std::env::var("OWN_CONFINEMENT_CHILD") else {
        return;
    };
    if mode == "crash" {
        let txn = Txn::begin(Path::new(".")).unwrap();
        let rel = std::env::var("OWN_CRASH_REL").unwrap_or_else(|_| "file.txt".into());
        let content = std::env::var("OWN_CRASH_CONTENT").unwrap_or_else(|_| "crashed\n".into());
        txn.write_file(&rel, content.as_bytes()).unwrap();
        std::process::exit(0);
    }
    let root = std::env::var("OWN_CONFINEMENT_ROOT").unwrap();
    Txn::begin(Path::new(&root)).unwrap().commit().unwrap();
}

fn crashed_transaction(root: &Path, rel: &str, content: &str) -> std::path::PathBuf {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["confinement_cwd_child", "--exact", "--nocapture"])
        .env("OWN_CONFINEMENT_CHILD", "crash")
        .env("OWN_CRASH_REL", rel)
        .env("OWN_CRASH_CONTENT", content)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let journals: Vec<_> = fs::read_dir(root.join(".own/txn"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(journals.len(), 1);
    journals.into_iter().next().unwrap()
}

#[test]
fn confinement_relative_root_recovers_from_another_cwd() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = fresh_root();
    let unrelated = fresh_root();
    fs::write(unrelated.path().join("file.txt"), b"unrelated\n").unwrap();
    for (mode, cwd) in [("crash", root.path()), ("recover", unrelated.path())] {
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["confinement_cwd_child", "--exact", "--nocapture"])
            .env("OWN_CONFINEMENT_CHILD", mode)
            .env("OWN_CONFINEMENT_ROOT", root.path())
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }
    assert_eq!(
        fs::read(unrelated.path().join("file.txt")).unwrap(),
        b"unrelated\n"
    );
    assert_eq!(
        fs::read(root.path().join("file.txt")).unwrap(),
        b"original\n"
    );
}

#[test]
fn confinement_journal_root_is_canonical() {
    let root = fresh_root();
    let txn = Txn::begin(&root.path().join(".")).unwrap();
    let raw = fs::read(txn.txn_dir.join("journal.json")).unwrap();
    let j: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(txn.root, fs::canonicalize(root.path()).unwrap());
    assert_eq!(
        j["root"].as_str().unwrap(),
        fs::canonicalize(root.path()).unwrap().to_str().unwrap()
    );
    txn.commit().unwrap();
}

#[test]
fn confinement_recovery_rejects_foreign_root_before_any_mutation() {
    let root = fresh_root();
    let foreign = fresh_root();
    let stale = root.path().join(".own/txn/foreign");
    fs::create_dir_all(stale.join("backup")).unwrap();
    fs::write(stale.join("backup/file.txt"), b"poison\n").unwrap();
    let raw = serde_json::to_vec(&serde_json::json!({
        "state": "started", "root": foreign.path(),
        "backup_files": [{"rel":"file.txt", "flat":"file.txt", "existed":true}],
        "created_dirs": []
    }))
    .unwrap();
    fs::write(stale.join("journal.json"), &raw).unwrap();
    assert!(
        Txn::begin(root.path()).is_err(),
        "foreign journal root must fail closed"
    );
    assert_eq!(
        fs::read(foreign.path().join("file.txt")).unwrap(),
        b"original\n"
    );
    assert_eq!(fs::read(stale.join("journal.json")).unwrap(), raw);
}

#[test]
fn path_guard_all_apis_reject_traversal_and_absolute_destinations() {
    let sandbox = tempfile::tempdir().unwrap();
    let absolute = sandbox.path().join("outside").to_str().unwrap().to_string();
    let mut accepted = Vec::new();
    for (i, rel) in [
        "",
        ".",
        "./file.txt",
        "sub/../file.txt",
        "../outside",
        &absolute,
    ]
    .iter()
    .enumerate()
    {
        let root = sandbox.path().join(format!("project-{i}"));
        fs::create_dir_all(&root).unwrap();
        let txn = Txn::begin(&root).unwrap();
        let src = root.join(".own/tmp/prepared");
        fs::create_dir_all(&src).unwrap();
        for (api, result) in [
            ("backup", txn.backup(rel)),
            ("write_file", txn.write_file(rel, b"poison")),
            ("move_dir_into", txn.move_dir_into(&src, rel)),
            ("note_created_dir", txn.note_created_dir(rel)),
        ] {
            if result.is_ok() {
                accepted.push(format!("{api}({rel:?})"));
            }
        }
        drop(txn); // release the lock fd
    }
    assert!(accepted.is_empty(), "unsafe paths accepted: {accepted:?}");
}

#[cfg(unix)]
#[test]
fn path_guard_all_apis_reject_symlink_parents_and_leaf() {
    use std::os::unix::fs::symlink;
    let mut accepted = Vec::new();
    for api in ["backup", "write_file", "move_dir_into", "note_created_dir"] {
        for leaf in [false, true] {
            let root = fresh_root();
            let outside = fresh_root();
            if leaf {
                symlink(outside.path().join("file.txt"), root.path().join("link")).unwrap();
            } else {
                symlink(outside.path(), root.path().join("link")).unwrap();
            }
            let txn = Txn::begin(root.path()).unwrap();
            let src = root.path().join(".own/tmp/prepared");
            fs::create_dir_all(&src).unwrap();
            let rel = if leaf { "link" } else { "link/file.txt" };
            let result = match api {
                "backup" => txn.backup(rel),
                "write_file" => txn.write_file(rel, b"poison"),
                "move_dir_into" => txn.move_dir_into(&src, rel),
                _ => txn.note_created_dir(rel),
            };
            if result.is_ok() {
                accepted.push(format!("{api}({rel})"));
            }
            drop(txn); // release the lock fd
        }
    }
    assert!(accepted.is_empty(), "symlink paths accepted: {accepted:?}");
}

#[cfg(unix)]
#[test]
fn path_guard_begin_rejects_symlink_transaction_metadata() {
    use std::os::unix::fs::symlink;
    let mut accepted = Vec::new();
    for rel in [".own", ".own/tmp", ".own/txn", ".own/lock"] {
        let root = fresh_root();
        let outside = fresh_root();
        fs::create_dir_all(root.path().join(".own")).unwrap();
        let target = if rel.ends_with("lock") {
            outside.path().join("file.txt")
        } else {
            outside.path().to_path_buf()
        };
        if rel == ".own" {
            fs::remove_dir(root.path().join(".own")).unwrap();
        }
        symlink(target, root.path().join(rel)).unwrap();
        if let Ok(txn) = Txn::begin(root.path()) {
            accepted.push(rel);
            drop(txn); // release the lock fd
        }
        assert_eq!(
            fs::read(outside.path().join("file.txt")).unwrap(),
            b"original\n"
        );
    }
    assert!(
        accepted.is_empty(),
        "metadata symlinks accepted: {accepted:?}"
    );
}

#[cfg(unix)]
#[test]
fn path_guard_recovery_rejects_replaced_parent_before_mutation() {
    use std::os::unix::fs::symlink;
    let root = fresh_root();
    let outside = fresh_root();
    fs::create_dir(root.path().join("sub")).unwrap();
    fs::write(root.path().join("sub/file.txt"), b"saved\n").unwrap();
    let stale = crashed_transaction(root.path(), "sub/file.txt", "changed\n");
    let raw = fs::read(stale.join("journal.json")).unwrap();
    fs::remove_dir_all(root.path().join("sub")).unwrap();
    symlink(outside.path(), root.path().join("sub")).unwrap();
    assert!(
        Txn::begin(root.path()).is_err(),
        "recovery followed replaced parent"
    );
    assert_eq!(
        fs::read(outside.path().join("file.txt")).unwrap(),
        b"original\n"
    );
    assert_eq!(fs::read(stale.join("journal.json")).unwrap(), raw);
}

#[cfg(unix)]
#[test]
fn path_guard_recovery_rejects_symlink_journal_and_backup() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    use std::os::unix::fs::symlink;
    let mut accepted = Vec::new();
    for component in ["txn-dir", "journal.json", "backup", "backup/file.txt"] {
        let root = fresh_root();
        let outside = fresh_root();
        let stale = root.path().join(".own/txn/stale");
        fs::create_dir_all(stale.join("backup")).unwrap();
        fs::write(stale.join("backup/file.txt"), b"saved\n").unwrap();
        let raw = serde_json::to_vec(&serde_json::json!({
            "state":"started", "root":root.path(),
            "backup_files":[{"rel":"file.txt", "flat":"file.txt", "existed":true}], "created_dirs":[]
        })).unwrap();
        fs::write(stale.join("journal.json"), &raw).unwrap();
        let (path, target) = match component {
            "txn-dir" => {
                fs::rename(&stale, outside.path().join("stale")).unwrap();
                (stale.clone(), outside.path().join("stale"))
            }
            "journal.json" => {
                fs::write(outside.path().join("journal.json"), &raw).unwrap();
                fs::remove_file(stale.join(component)).unwrap();
                (stale.join(component), outside.path().join(component))
            }
            "backup" => {
                fs::rename(stale.join("backup"), outside.path().join("backup")).unwrap();
                (stale.join(component), outside.path().join(component))
            }
            _ => {
                fs::remove_file(stale.join(component)).unwrap();
                (stale.join(component), outside.path().join("file.txt"))
            }
        };
        symlink(target, path).unwrap();
        if let Ok(txn) = Txn::begin(root.path()) {
            accepted.push(component);
            drop(txn); // release the lock before the next iteration
        }
    }
    // `backup/file.txt` is the LEAF of the backup tree: our own copy_dir
    // preserves symlinks there, so recovery legitimately accepts a symlinked
    // leaf (it is restored as a symlink, never followed). Symlinked ancestors
    // (`backup`, `backup/dir/...`) and symlinked metadata (txn dir, journal)
    // must still be refused — see recovery_fails_closed_on_symlink_inside_backup_tree.
    assert_eq!(
        accepted,
        vec!["backup/file.txt".to_string()],
        "only a symlinked backup LEAF may be accepted: {accepted:?}"
    );
}

#[test]
fn path_guard_move_rejects_source_outside_project() {
    let root = fresh_root();
    let outside = fresh_root();
    let txn = Txn::begin(root.path()).unwrap();
    assert!(
        txn.move_dir_into(outside.path(), "vendor/own/pkg").is_err(),
        "external source accepted"
    );
    assert_eq!(
        fs::read(outside.path().join("file.txt")).unwrap(),
        b"original\n"
    );
    txn.rollback().unwrap();
}

#[test]
fn durable_journal_replacement_preserves_previous_inode() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    use std::io::Read;
    let root = fresh_root();
    let txn = Txn::begin(root.path()).unwrap();
    txn.write_file("file.txt", b"first\n").unwrap();
    let journal = txn.txn_dir.join("journal.json");
    let before = fs::read(&journal).unwrap();
    let mut prior_inode = fs::File::open(&journal).unwrap();
    txn.write_file("second.txt", b"second\n").unwrap();
    let mut observed = Vec::new();
    prior_inode.read_to_end(&mut observed).unwrap();
    assert_eq!(observed, before, "journal was rewritten in place");
    assert_ne!(fs::read(&journal).unwrap(), before);
    txn.rollback().unwrap();
}

#[cfg(unix)]
#[test]
fn durable_journal_failure_child() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(root) = std::env::var("OWN_JOURNAL_FAILURE_CHILD") else {
        return;
    };
    let txn = Txn::begin(Path::new(&root)).unwrap();
    txn.write_file("file.txt", b"first\n").unwrap();
    let len = fs::metadata(txn.txn_dir.join("journal.json"))
        .unwrap()
        .len();
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        let limit = libc::rlimit {
            rlim_cur: len - 1,
            rlim_max: len - 1,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
    }
    assert!(txn.write_file("second.txt", b"second\n").is_err());
    // Abrupt exit: do not let Drop hide the journal-publication failure.
    std::process::exit(0);
}

#[cfg(unix)]
#[test]
fn durable_journal_failed_publication_keeps_recovery_record() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = fresh_root();
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["durable_journal_failure_child", "--exact", "--nocapture"])
        .env("OWN_JOURNAL_FAILURE_CHILD", root.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(fs::read(root.path().join("file.txt")).unwrap(), b"first\n");
    let stale = fs::read_dir(root.path().join(".own/txn"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let raw = fs::read(stale.join("journal.json")).unwrap();
    let j: serde_json::Value = serde_json::from_slice(&raw)
        .expect("failed journal publication destroyed previous recovery record");
    assert_eq!(j["state"], "started");
    assert_eq!(j["backup_files"].as_array().unwrap().len(), 1);
    Txn::begin(root.path()).unwrap().commit().unwrap();
    assert_eq!(
        fs::read(root.path().join("file.txt")).unwrap(),
        b"original\n"
    );
    assert!(!root.path().join("second.txt").exists());
}

#[test]
fn commit_keeps_changes_and_cleans_journal() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
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
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
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
fn repeated_writes_restore_first_backup_of_existing_file() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    let txn = Txn::begin(t.path()).unwrap();
    txn.write_file("file.txt", b"intermediate\n").unwrap();
    txn.write_file("file.txt", b"final\n").unwrap();
    txn.rollback().unwrap();
    assert_eq!(fs::read(t.path().join("file.txt")).unwrap(), b"original\n");
}

#[test]
fn repeated_writes_remove_originally_absent_file() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    let txn = Txn::begin(t.path()).unwrap();
    txn.write_file("new.txt", b"intermediate\n").unwrap();
    txn.write_file("new.txt", b"final\n").unwrap();
    txn.rollback().unwrap();
    assert!(!t.path().join("new.txt").exists());
}

#[test]
fn directory_backup_restores_exact_tree_after_replacement() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    let rel = "vendor/own/pkg__literal";
    let original = t.path().join(rel);
    fs::create_dir_all(original.join("nested__dir/empty")).unwrap();
    let long_name = "x".repeat(220);
    fs::write(original.join(&long_name), b"long name\n").unwrap();
    fs::write(original.join("nested__dir/run"), b"original\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        fs::set_permissions(&original, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(
            original.join("nested__dir"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(
            original.join("nested__dir/run"),
            fs::Permissions::from_mode(0o751),
        )
        .unwrap();
        symlink("nested__dir/run", original.join("link")).unwrap();
    }
    let txn = Txn::begin(t.path()).unwrap();
    txn.backup(rel).unwrap();
    fs::remove_dir_all(&original).unwrap();
    let prep = t.path().join(".own/tmp/prep");
    fs::create_dir_all(prep.join("extra")).unwrap();
    fs::write(prep.join("extra/new.txt"), b"extra\n").unwrap();
    txn.move_dir_into(&prep, rel).unwrap();
    txn.backup(rel).unwrap();
    txn.rollback().unwrap();
    assert_eq!(
        fs::read(original.join("nested__dir/run")).unwrap(),
        b"original\n"
    );
    assert_eq!(fs::read(original.join(&long_name)).unwrap(), b"long name\n");
    assert!(original.join("nested__dir/empty").is_dir());
    assert!(!original.join("extra").exists());
    assert_eq!(
        fs::read_dir(&original).unwrap().count(),
        if cfg!(unix) { 3 } else { 2 }
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&original).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(
            fs::metadata(original.join("nested__dir"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(original.join("nested__dir/run"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o751
        );
        assert_eq!(
            fs::read_link(original.join("link")).unwrap(),
            Path::new("nested__dir/run")
        );
    }
}

#[test]
fn directory_backup_removes_new_tree_when_parents_are_already_removed() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    let txn = Txn::begin(t.path()).unwrap();
    let prep = t.path().join(".own/tmp/prep");
    fs::create_dir_all(&prep).unwrap();
    fs::write(prep.join("new.txt"), b"new\n").unwrap();
    txn.move_dir_into(&prep, "new/parent/pkg").unwrap();
    txn.backup("new/parent/pkg").unwrap();
    txn.note_created_dir("new").unwrap();
    txn.note_created_dir("new/parent").unwrap();
    txn.rollback().unwrap();
    assert!(!t.path().join("new").exists());
}

#[test]
fn drop_uncommitted_transaction_restores_original() {
    let t = fresh_root();
    let txn = Txn::begin(t.path()).unwrap();
    txn.write_file("file.txt", b"abandoned\n").unwrap();
    let journal_dir = txn.txn_dir.clone();
    drop(txn);
    assert_eq!(fs::read(t.path().join("file.txt")).unwrap(), b"original\n");
    assert!(!journal_dir.exists());
}

#[test]
fn drop_on_question_mark_restores_files_and_directories() {
    fn failed_command(root: &Path) -> Result<(), String> {
        let txn = Txn::begin(root)?;
        txn.write_file("file.txt", b"intermediate\n")?;
        txn.write_file("file.txt", b"final\n")?;
        let prep = root.join(".own/tmp/prep");
        fs::create_dir_all(&prep).map_err(|e| e.to_string())?;
        fs::write(prep.join("new.txt"), b"new\n").map_err(|e| e.to_string())?;
        txn.move_dir_into(&prep, "vendor/own/pkg__new")?;
        fs::read(root.join("missing-input")).map_err(|e| e.to_string())?;
        txn.commit()
    }
    let t = fresh_root();
    assert!(failed_command(t.path()).is_err());
    assert_eq!(fs::read(t.path().join("file.txt")).unwrap(), b"original\n");
    assert!(!t.path().join("vendor/own/pkg__new").exists());
    assert_eq!(fs::read_dir(t.path().join(".own/txn")).unwrap().count(), 0);
}

#[test]
fn drop_failed_rollback_preserves_journal_for_retry() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    fs::create_dir_all(t.path().join("blocked")).unwrap();
    fs::write(t.path().join("blocked/file.txt"), b"original\n").unwrap();
    let txn = Txn::begin(t.path()).unwrap();
    txn.write_file("blocked/file.txt", b"changed\n").unwrap();
    let stale = txn.txn_dir.clone();
    let raw = fs::read(stale.join("journal.json")).unwrap();
    fs::remove_dir_all(t.path().join("blocked")).unwrap();
    fs::write(t.path().join("blocked"), b"barrier\n").unwrap();
    drop(txn);
    assert_eq!(fs::read(stale.join("journal.json")).unwrap(), raw);
    assert_eq!(
        fs::read(stale.join("backup/blocked__file.txt")).unwrap(),
        b"original\n"
    );
    assert!(Txn::begin(t.path()).is_err());
    fs::remove_file(t.path().join("blocked")).unwrap();
    let recovered = Txn::begin(t.path()).unwrap();
    recovered.commit().unwrap();
    assert_eq!(
        fs::read(t.path().join("blocked/file.txt")).unwrap(),
        b"original\n"
    );
    assert!(!stale.exists());
}

#[test]
fn rollback_removes_created_dirs() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
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
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    // Test legacy POSIX-lock compatibility on Linux; other Unix uses flock.
    let t = fresh_root();
    fs::create_dir_all(t.path().join(".own")).unwrap();
    let lockp = t.path().join(".own/lock");
    fs::write(&lockp, b"").unwrap();
    // hold an exclusive fcntl lock from a python child
    let py = "import fcntl,time,sys; f=open(sys.argv[1],'w'); lock=fcntl.lockf if sys.platform.startswith('linux') else fcntl.flock; lock(f, fcntl.LOCK_EX); print('LOCKED',flush=True); time.sleep(10)";
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
fn lock_taken_before_recovery_so_second_writer_cannot_rollback_active_txn() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    // A real second process must also see LOCK_BUSY and leave the parent's
    // live journal intact. Same-process exclusion is covered separately.
    let t = fresh_root();
    // parent holds a live transaction
    let txn1 = Txn::begin(t.path()).unwrap();
    txn1.write_file("file.txt", b"in-progress\n").unwrap();
    let live_txn_dir = t
        .path()
        .join(".own/txn")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(live_txn_dir.join("journal.json").exists());

    // child tries to begin while the parent's lock is held
    let py = r#"import fcntl,subprocess,sys,os
lockp = sys.argv[1]
root = sys.argv[2]
# hold nothing; just try to take the lock the parent holds
f = open(lockp, 'r+')
lock = fcntl.lockf if sys.platform.startswith('linux') else fcntl.flock
try:
    lock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    print("ACQUIRED")   # should NOT happen: parent holds it
except BlockingIOError:
    print("LOCK_BUSY")
"#;
    let out = Command::new("python3")
        .arg("-c")
        .arg(py)
        .arg(t.path().join(".own/lock").to_str().unwrap())
        .arg(t.path().to_str().unwrap())
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("LOCK_BUSY"), "expected LOCK_BUSY, got: {s}");

    // the parent's live journal must be untouched
    assert!(
        live_txn_dir.join("journal.json").exists(),
        "second writer destroyed the active transaction's journal"
    );
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "in-progress\n"
    );
    txn1.rollback().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "original\n"
    );
}

#[test]
fn rollback_preserves_literal_double_underscore_in_names() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    // backup flat-names encode '/' as "__"; a real name containing "__" (e.g.
    // "@types+babel__core") must round-trip, not be split into a directory.
    let t = fresh_root();
    let weird = "vendor/own/@types+babel__core@1.0.0/index.js";
    fs::create_dir_all(t.path().join("vendor/own/@types+babel__core@1.0.0")).unwrap();
    fs::write(t.path().join(weird), b"original\n").unwrap();
    let txn = Txn::begin(t.path()).unwrap();
    txn.write_file(weird, b"changed\n").unwrap();
    txn.rollback().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join(weird)).unwrap(),
        "original\n",
        "rollback must restore the literal '__' path, not vendor/own/@types+babel/core@1.0.0/..."
    );
}

#[test]
fn recovery_refuses_corrupt_journal_and_preserves_evidence() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    let stale = t.path().join(".own/txn/corrupt");
    fs::create_dir_all(stale.join("backup")).unwrap();
    let raw = b"{\"state\":\"started\", truncated";
    fs::write(stale.join("journal.json"), raw).unwrap();
    assert!(
        Txn::begin(t.path()).is_err(),
        "corrupt recovery must fail closed"
    );
    assert_eq!(fs::read(stale.join("journal.json")).unwrap(), raw);
    assert_eq!(fs::read_dir(t.path().join(".own/txn")).unwrap().count(), 1);
}

#[test]
fn recovery_refuses_unrestorable_backup_and_preserves_evidence() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    let stale = t.path().join(".own/txn/unrestorable");
    fs::create_dir_all(stale.join("backup")).unwrap();
    fs::write(stale.join("backup/blocked__file.txt"), b"original\n").unwrap();
    fs::write(t.path().join("blocked"), b"not a directory\n").unwrap();
    let raw = serde_json::to_vec(&serde_json::json!({
        "state": "started", "root": t.path(),
        "backup_files": [{"rel": "blocked/file.txt", "flat": "blocked__file.txt"}],
        "created_dirs": []
    }))
    .unwrap();
    fs::write(stale.join("journal.json"), &raw).unwrap();
    assert!(
        Txn::begin(t.path()).is_err(),
        "failed restoration must fail closed"
    );
    assert_eq!(fs::read(stale.join("journal.json")).unwrap(), raw);
    assert_eq!(
        fs::read(stale.join("backup/blocked__file.txt")).unwrap(),
        b"original\n"
    );
    assert_eq!(
        fs::read(t.path().join("blocked")).unwrap(),
        b"not a directory\n"
    );
    assert_eq!(fs::read_dir(t.path().join(".own/txn")).unwrap().count(), 1);
}

#[test]
fn recovery_refuses_invalid_entries_before_removing_created_dirs() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    let stale = t.path().join(".own/txn/invalid-entry");
    fs::create_dir_all(stale.join("backup")).unwrap();
    fs::create_dir_all(t.path().join("created")).unwrap();
    fs::write(t.path().join("created/evidence"), b"keep\n").unwrap();
    let raw = serde_json::to_vec(&serde_json::json!({
        "state": "started", "root": t.path(),
        "backup_files": [{"rel": "file.txt"}], "created_dirs": ["created"]
    }))
    .unwrap();
    fs::write(stale.join("journal.json"), &raw).unwrap();
    assert!(
        Txn::begin(t.path()).is_err(),
        "invalid entries must not be skipped"
    );
    assert_eq!(fs::read(stale.join("journal.json")).unwrap(), raw);
    assert_eq!(
        fs::read(t.path().join("created/evidence")).unwrap(),
        b"keep\n"
    );
}

#[test]
fn recovery_refuses_missing_backup_of_existing_path() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    // A real exited child releases its descriptor lock without running Drop.
    let stale = crashed_transaction(t.path(), "file.txt", "intermediate\n");
    fs::remove_file(stale.join("backup/file.txt")).unwrap();
    let raw = fs::read(stale.join("journal.json")).unwrap();
    assert!(
        Txn::begin(t.path()).is_err(),
        "missing original must not mean absent path"
    );
    assert_eq!(fs::read(stale.join("journal.json")).unwrap(), raw);
    assert_eq!(
        fs::read(t.path().join("file.txt")).unwrap(),
        b"intermediate\n"
    );
}

#[test]
fn stale_started_journal_is_recovered_by_next_writer() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
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

/// Child-process helper for the signal tests below. It returns immediately
/// unless the parent set `OWN_TXN_SIGNAL_CHILD`, so the normal suite only sees
/// a no-op test. The parent re-executes this same test binary with `--exact`
/// and the env var, so the child opens a real transaction, modifies a file,
/// prints READY, then blocks until it is signalled.
#[test]
fn txn_signal_child_helper() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(root) = std::env::var("OWN_TXN_SIGNAL_CHILD") else {
        return;
    };
    let txn = Txn::begin(Path::new(&root)).unwrap();
    txn.write_file("file.txt", b"interrupted\n").unwrap();
    use std::io::Write as _;
    println!("READY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

struct SignalChild {
    child: std::process::Child,
    // kept open on purpose: closing the read end would SIGPIPE the child
    _out: std::process::ChildStdout,
    err: std::process::ChildStderr,
}

/// Spawn `txn_signal_child_helper` in a child process and wait until it prints
/// READY (so the transaction is live and the journal is on disk).
fn spawn_signal_child(root: &Path) -> SignalChild {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "txn_signal_child_helper",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("OWN_TXN_SIGNAL_CHILD", root.to_str().unwrap())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    use std::io::Read;
    let mut seen = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = out.read(&mut buf).expect("child stdout");
        assert!(n > 0, "child exited before READY");
        seen.extend_from_slice(&buf[..n]);
        if seen.windows(5).any(|w| w == b"READY") {
            break;
        }
    }
    SignalChild {
        child,
        _out: out,
        err,
    }
}

/// Signal the child and return (exit code, stderr). The exit code proves the
/// async-signal-safe handler ran: `_exit(128 + signal)` instead of the default
/// disposition (which would report no code at all).
fn signal_and_collect(mut c: SignalChild, sig: i32) -> (i32, String) {
    unsafe { libc::kill(c.child.id() as i32, sig) };
    let status = c.child.wait().unwrap();
    let code = status
        .code()
        .expect("signal handler must _exit(128+sig), not die by default disposition");
    use std::io::Read;
    let mut errs = String::new();
    let mut err = c.err;
    err.read_to_string(&mut errs).unwrap();
    (code, errs)
}

fn journal_state(root: &Path) -> String {
    let txn_root = root.join(".own/txn");
    let dir = fs::read_dir(&txn_root)
        .unwrap()
        .next()
        .expect("a journal directory")
        .unwrap()
        .path();
    let raw = fs::read_to_string(dir.join("journal.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    v["state"].as_str().unwrap().to_string()
}

#[test]
fn sigterm_leaves_started_journal_that_next_writer_restores() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    let c = spawn_signal_child(t.path());
    let (code, errs) = signal_and_collect(c, libc::SIGTERM);
    assert_eq!(code, 143, "SIGTERM must exit 128+15, stderr: {errs}");
    assert!(errs.contains("SIGTERM"), "handler message missing: {errs}");
    // the handler touches nothing: the modified file stays and the journal is
    // still `started`, which is what makes the next writer restore it
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "interrupted\n"
    );
    assert_eq!(journal_state(t.path()), "started");
    let txn = Txn::begin(t.path()).unwrap();
    txn.commit().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "original\n",
        "the next writing command must restore the backup"
    );
}

#[test]
fn sigint_leaves_started_journal_that_next_writer_restores() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let t = fresh_root();
    let c = spawn_signal_child(t.path());
    let (code, errs) = signal_and_collect(c, libc::SIGINT);
    assert_eq!(code, 130, "SIGINT must exit 128+2, stderr: {errs}");
    assert!(errs.contains("SIGINT"), "handler message missing: {errs}");
    assert_eq!(journal_state(t.path()), "started");
    let txn = Txn::begin(t.path()).unwrap();
    txn.commit().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "original\n"
    );
}

#[test]
fn write_file_publishes_only_synced_content() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    // INV-9 durability: `write_file` fsyncs the temporary before the rename and
    // the parent directory after it. We cannot drop the power on the test
    // machine, so this asserts the observable part: the published file is the
    // journal-backed content and the journal records the backup entry that a
    // recovery would need (i.e. the ordering backup -> journal -> rename held).
    let t = fresh_root();
    let txn = Txn::begin(t.path()).unwrap();
    txn.write_file("sub/dir/file.txt", b"new\n").unwrap();
    let raw = fs::read_to_string(txn.txn_dir.join("journal.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["state"], "started");
    assert_eq!(
        v["backup_files"].as_array().unwrap().len(),
        1,
        "every write must be preceded by a durable backup entry"
    );
    txn.commit().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join("sub/dir/file.txt")).unwrap(),
        "new\n"
    );
}

#[test]
fn kill9_recovery_in_child_process() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    // child starts a txn, writes, then gets SIGKILL; parent then begins a new txn
    let t = fresh_root();
    // Reuse the built test binary: no auxiliary Cargo project, network fetch
    // or assumption about the caller's CARGO_TARGET_DIR.
    let mut child = spawn_signal_child(t.path());
    assert_eq!(journal_state(t.path()), "started");
    child.child.kill().unwrap();
    let status = child.child.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "interrupted\n"
    );
    // parent (this process) recovers on next begin
    let txn = Txn::begin(t.path()).unwrap();
    txn.commit().unwrap();
    assert_eq!(
        fs::read_to_string(t.path().join("file.txt")).unwrap(),
        "original\n"
    );
}

#[cfg(unix)]
#[test]
fn recovery_restores_symlink_leaf_as_symlink_not_regular_file() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    use std::os::unix::fs::symlink;
    let t = fresh_root();
    fs::write(t.path().join("target.txt"), b"target\n").unwrap();
    symlink("target.txt", t.path().join("link.txt")).unwrap();
    // simulate a crashed transaction whose backup preserved the symlink
    let stale = t.path().join(".own/txn/symlink-txn");
    fs::create_dir_all(stale.join("backup")).unwrap();
    symlink("target.txt", stale.join("backup/link.txt")).unwrap();
    fs::write(stale.join("backup/target.txt"), b"target\n").unwrap();
    let raw = serde_json::to_vec(&serde_json::json!({
        "state": "started", "root": fs::canonicalize(t.path()).unwrap(),
        "backup_files": [
            {"rel": "link.txt", "flat": "link.txt", "existed": true},
            {"rel": "target.txt", "flat": "target.txt", "existed": true},
        ],
        "created_dirs": []
    }))
    .unwrap();
    fs::write(stale.join("journal.json"), &raw).unwrap();
    // the working tree lost the link and modified the target
    fs::remove_file(t.path().join("link.txt")).unwrap();
    fs::write(t.path().join("target.txt"), b"crashed\n").unwrap();
    // next writer recovers
    let txn = Txn::begin(t.path()).unwrap();
    txn.commit().unwrap();
    let restored = t.path().join("link.txt");
    assert!(
        fs::symlink_metadata(&restored)
            .unwrap()
            .file_type()
            .is_symlink(),
        "rollback must restore the symlink itself, not a regular file copy"
    );
    assert_eq!(fs::read_link(&restored).unwrap(), Path::new("target.txt"));
    assert_eq!(
        fs::read_to_string(t.path().join("target.txt")).unwrap(),
        "target\n"
    );
}

#[cfg(unix)]
#[test]
fn recovery_fails_closed_on_symlink_inside_backup_tree() {
    let _guard = LOCK_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    // A symlink as an ANCESTOR inside the backup tree must still be refused:
    // only the leaf may be a link.
    use std::os::unix::fs::symlink;
    let t = fresh_root();
    let stale = t.path().join(".own/txn/evil");
    fs::create_dir_all(stale.join("backup")).unwrap();
    // backup/dir is a symlink pointing outside the txn tree
    symlink(t.path(), stale.join("backup/dir")).unwrap();
    let raw = serde_json::to_vec(&serde_json::json!({
        "state": "started", "root": fs::canonicalize(t.path()).unwrap(),
        "backup_files": [{"rel": "file.txt", "flat": "dir/file.txt", "existed": true}],
        "created_dirs": []
    }))
    .unwrap();
    fs::write(stale.join("journal.json"), &raw).unwrap();
    assert!(
        Txn::begin(t.path()).is_err(),
        "a symlinked ancestor in the backup tree must fail closed"
    );
    assert!(stale.join("journal.json").exists(), "evidence retained");
}
