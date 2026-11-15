#![cfg(unix)]
//! Fail closed when Git cannot establish the ejection preconditions.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn eject_git_status_failure_preserves_project_inv5_inv9() {
    let root = std::env::temp_dir().join(format!("own-eject-git-error-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("package.json"), b"{\"name\":\"fixture\"}\n").unwrap();
    let initialized = Command::new(env!("CARGO_BIN_EXE_own"))
        .arg("init")
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(initialized.status.success(), "{initialized:?}");
    let before_lock = fs::read(root.join("own.lock")).unwrap();
    let before_config = fs::read(root.join("own.toml")).unwrap();
    let shim = root.join("tools");
    fs::create_dir(&shim).unwrap();
    let git = shim.join("git");
    fs::write(
        &git,
        b"#!/bin/sh\necho 'fatal: unsafe repository' >&2\nexit 128\n",
    )
    .unwrap();
    fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_own"))
        .args(["eject", "--adopt", "--yes"])
        .env("PATH", &shim)
        .current_dir(&root)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("GIT_ERROR"),
        "{out:?}"
    );
    assert_eq!(fs::read(root.join("own.lock")).unwrap(), before_lock);
    assert_eq!(fs::read(root.join("own.toml")).unwrap(), before_config);
    fs::remove_dir_all(root).unwrap();
}
