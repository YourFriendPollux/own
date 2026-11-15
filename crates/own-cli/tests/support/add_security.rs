use super::*;
use sha2::{Digest, Sha512};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(std::path::PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "own-add-security-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&path)
            .status()
            .unwrap()
            .success());
        std::fs::write(path.join("package.json"), "{\"name\":\"fixture\"}").unwrap();
        std::fs::write(path.join("own.toml"), own_core::config::DEFAULT_OWN_TOML).unwrap();
        std::fs::write(
            path.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\nimporters: {}\npackages: {}\n",
        )
        .unwrap();
        let lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        std::fs::write(path.join("own.lock"), write_lock_canonical(&lock)).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn archive(package: serde_json::Value) -> Vec<u8> {
    let json = serde_json::to_vec(&package).unwrap();
    let mut raw = Vec::new();
    for (name, bytes) in [
        ("package/package.json", json.as_slice()),
        ("package/LICENSE", b"MIT License\n".as_slice()),
    ] {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|b| *b as u32).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        raw.extend_from_slice(&header);
        raw.extend_from_slice(bytes);
        raw.resize(raw.len().next_multiple_of(512), 0);
    }
    raw.extend_from_slice(&[0; 1024]);
    let mut child = Command::new("gzip")
        .args(["-n", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&raw).unwrap(); // small bounded fixture
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    out.stdout
}

#[test]
fn add_rejects_hidden_install_scripts_in_the_verified_archive_inv4() {
    let root = Root::new();
    let lock =
        own_core::lock::parse_lock(&std::fs::read_to_string(root.0.join("own.lock")).unwrap())
            .unwrap();
    let bytes = archive(
        serde_json::json!({"name":"a","version":"1.0.0","license":"MIT","scripts":{"postinstall":"exit 99"}}),
    );
    let sha512 = format!("{:x}", Sha512::digest(&bytes));
    let args = AddArgs {
        pkg: "a".into(),
        version: "1.0.0".into(),
        ecosystem: "npm".into(),
        allow_diamond: None,
        license_override: false,
        no_install: true,
        allow_untested_pnpm: false,
    };
    let txn = Txn::begin(&root.0).unwrap();
    let result = add_inner(
        &txn,
        &root.0,
        &lock,
        &args,
        &bytes,
        &sha512,
        &own_core::sha256_hex(&bytes),
        &own_core::sha256_hex(b"fixture"),
        "sha512-x",
        "allow",
        None,
        "MIT",
        &evaluate_provenance(&serde_json::json!({})),
        &own_extract::SecurityLimits::default(),
        "https://registry.npmjs.org",
    );
    assert!(
        matches!(result, Err(ref e) if e == "NOT_ELIGIBLE:install_scripts"),
        "{result:?}"
    );
    txn.rollback().unwrap();
    assert!(!root.0.join("vendor/own/a@1.0.0").exists());
}

#[test]
fn pnpm_failure_child() {
    let Some(root) = std::env::var_os("OWN_TEST_PNPM_FAILURE_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let txn = Txn::begin(&root).unwrap();
    let result = install_and_verify(&txn, &root, "a", false);
    assert!(
        matches!(result, Err(ref e) if e.starts_with("PNPM_FAILED")),
        "{result:?}"
    );
}

#[cfg(unix)]
#[test]
fn add_does_not_accept_a_failed_second_pnpm_install_inv5() {
    use std::os::unix::fs::PermissionsExt;
    let root = Root::new();
    let tools = root.0.join("tools");
    std::fs::create_dir(&tools).unwrap();
    let shim = tools.join("pnpm");
    std::fs::write(
        &shim,
        "#!/bin/sh\ncase \"$*\" in *--force*) printf 'corrupted\\n' > pnpm-lock.yaml; exit 42;; *) exit 0;; esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let before = std::fs::read(root.0.join("pnpm-lock.yaml")).unwrap();
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "add::security_tests::pnpm_failure_child",
            "--exact",
            "--nocapture",
        ])
        .env("OWN_TEST_PNPM_FAILURE_ROOT", &root.0)
        .env("PATH", &tools)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        std::fs::read(root.0.join("pnpm-lock.yaml")).unwrap(),
        before
    );
}
