//! Recovery collection must be validated before any root mutation.
use own_core::txn::Txn;
use std::fs;
use std::path::Path;

#[test]
fn concurrent_calls_on_one_transaction_preserve_writes_and_journal() {
    for _ in 0..20 {
        let root = tempfile::tempdir().unwrap();
        let transaction = std::sync::Arc::new(Txn::begin(root.path()).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut workers = Vec::new();
        for index in 0..8 {
            let txn = transaction.clone();
            let start = barrier.clone();
            workers.push(std::thread::spawn(move || {
                let path = format!("file-{index}.txt");
                let content = format!("content-{index}");
                start.wait();
                txn.write_file(&path, content.as_bytes())
            }));
        }
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(
            results.iter().all(Result::is_ok),
            "same-transaction writes raced: {results:?}"
        );
        for index in 0..8 {
            assert_eq!(
                fs::read_to_string(root.path().join(format!("file-{index}.txt"))).unwrap(),
                format!("content-{index}")
            );
        }
        let journal: serde_json::Value =
            serde_json::from_slice(&fs::read(transaction.txn_dir.join("journal.json")).unwrap())
                .unwrap();
        assert_eq!(
            journal["backup_files"].as_array().unwrap().len(),
            8,
            "concurrent journal entries were lost"
        );
        transaction.rollback().unwrap();
        for index in 0..8 {
            assert!(!root.path().join(format!("file-{index}.txt")).exists());
        }
    }
}

fn journal(directory: &Path, root: &Path, state: &str, original: &[u8]) {
    fs::create_dir_all(directory.join("backup")).unwrap();
    fs::write(directory.join("backup/file.txt"), original).unwrap();
    fs::write(
        directory.join("journal.json"),
        serde_json::json!({
            "root": fs::canonicalize(root).unwrap(), "state": state,
            "backup_files": [{"rel":"file.txt","flat":"file.txt","existed":true}],
            "created_dirs": []
        })
        .to_string(),
    )
    .unwrap();
}

#[test]
fn recovery_order_validates_every_journal_before_restoring_any_file() {
    let root = tempfile::tempdir().unwrap();
    let txns = root.path().join(".own/txn");
    for name in ["first", "second"] {
        fs::create_dir_all(txns.join(name)).unwrap();
    }
    // Use the filesystem's actual traversal order, then make its first record
    // restorable and its second invalid. No timing or directory-order guess.
    let dirs: Vec<_> = fs::read_dir(&txns)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    journal(&dirs[0], root.path(), "started", b"original");
    fs::write(dirs[1].join("journal.json"), b"{broken").unwrap();
    fs::write(root.path().join("file.txt"), b"intermediate").unwrap();
    let before = fs::read(dirs[0].join("journal.json")).unwrap();
    assert!(Txn::begin(root.path()).is_err());
    assert_eq!(
        fs::read(root.path().join("file.txt")).unwrap(),
        b"intermediate",
        "a later invalid journal must not permit earlier restoration"
    );
    assert_eq!(fs::read(dirs[0].join("journal.json")).unwrap(), before);
}

#[test]
fn recovery_order_refuses_ambiguous_multiple_unfinished_transactions() {
    let root = tempfile::tempdir().unwrap();
    let txns = root.path().join(".own/txn");
    journal(&txns.join("old"), root.path(), "started", b"old-original");
    journal(
        &txns.join("new"),
        root.path(),
        "started",
        b"intermediate-original",
    );
    fs::write(root.path().join("file.txt"), b"current").unwrap();
    let result = Txn::begin(root.path());
    assert!(
        result.is_err(),
        "ambiguous recovery order must not be guessed"
    );
    assert_eq!(fs::read(root.path().join("file.txt")).unwrap(), b"current");
    assert!(txns.join("old/journal.json").is_file());
    assert!(txns.join("new/journal.json").is_file());
}

#[test]
fn recovery_order_committed_journal_is_cleaned_without_restoring_backups() {
    let root = tempfile::tempdir().unwrap();
    let old = root.path().join(".own/txn/committed");
    journal(&old, root.path(), "committed", b"must-not-restore");
    fs::write(root.path().join("file.txt"), b"committed-value").unwrap();
    Txn::begin(root.path()).unwrap().commit().unwrap();
    assert_eq!(
        fs::read(root.path().join("file.txt")).unwrap(),
        b"committed-value"
    );
    assert!(
        !old.exists(),
        "a completed recovery record should not accumulate"
    );
}
