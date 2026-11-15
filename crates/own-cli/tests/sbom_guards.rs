//! Offline regressions through the real SBOM/OpenVEX CLI.
use own_core::canonical::{empty_lock, write_lock_canonical};
use own_core::config::DEFAULT_OWN_TOML;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NONCE: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "own-sbom-guards-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join(".own")).unwrap();
        fs::write(root.join("own.toml"), DEFAULT_OWN_TOML).unwrap();
        let lock = empty_lock("0.1.0", "1", &serde_json::Map::new());
        let mut text = write_lock_canonical(&lock);
        for version in ["1.0.0", "2.0.0"] {
            text.push_str(&format!(
                r#"
[[package]]
name = "fakepkg"
ecosystem = "npm"
version = "{version}"
dir = "vendor/own/fakepkg@{version}"
registry = "https://registry.npmjs.org"
integrity = "sha512-AAAA"
tarball_sha256 = "sha256:0000"
version_manifest_sha256 = "sha256:0001"
provenance_level = "integrity-only"
mode = "verbatim"
roots = ["."]
dependents = ["importer:."]
license_expression = "MIT"
license_policy = "allow"
license_files = []
package_files_sha256 = "sha256:0002"
file_count = 0
total_size = 0
"#
            ));
        }
        fs::write(root.join("own.lock"), text).unwrap();
        fs::write(
            root.join(".own/osv.json"),
            json!({
                "schema_version": 1,
                "generated_at": "2025-01-02T03:04:05Z",
                "source": "https://example.invalid/npm/all.zip",
                "source_last_modified": null,
                "covered_packages": ["fakepkg"],
                "advisories": [{"id": "SYNTHETIC-version-2", "affected": [{
                    "package": "fakepkg", "versions": ["2.0.0"], "ranges": []
                }]}]
            })
            .to_string(),
        )
        .unwrap();
        Self(root)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_own"))
            .args(args)
            .current_dir(&self.0)
            .env("OWN_NOW", "2025-01-02T03:04:05Z")
            .env_remove("SOURCE_DATE_EPOCH")
            .env_remove("OWN_OSV_LOCAL_PATH")
            .env_remove("OWN_OSV_MAX_AGE_DAYS")
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn success(out: &Output) {
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn sbom_recovers_before_reading_the_lock_it_will_publish() {
    let fixture = Fixture::new();
    let original = fs::read(fixture.0.join("own.lock")).unwrap();
    let expected = fixture.run(&["sbom", "--format", "cyclonedx"]).stdout;
    let stale = fixture.0.join(".own/txn/stale");
    fs::create_dir_all(stale.join("backup")).unwrap();
    fs::write(stale.join("backup/own.lock"), &original).unwrap();
    fs::write(stale.join("journal.json"), json!({"state":"started", "root":fs::canonicalize(&fixture.0).unwrap(), "backup_files":[{"rel":"own.lock", "flat":"own.lock", "existed":true}], "created_dirs":[]}).to_string()).unwrap();
    let mut lock = own_core::lock::parse_lock(std::str::from_utf8(&original).unwrap()).unwrap();
    lock.metadata.lock_digest = own_core::sha256_hex(b"uncommitted");
    fs::write(fixture.0.join("own.lock"), write_lock_canonical(&lock)).unwrap();
    success(&fixture.run(&["sbom", "--format", "cyclonedx", "--output", "cdx.json"]));
    assert_eq!(fs::read(fixture.0.join("own.lock")).unwrap(), original);
    assert_eq!(fs::read(fixture.0.join("cdx.json")).unwrap(), expected);
}

#[test]
fn sbom_cannot_overwrite_own_state_or_vendored_files() {
    for output in [
        "own.lock",
        "own.toml",
        "package.json",
        "pnpm-lock.yaml",
        "vendor/own/fakepkg@1.0.0/index.js",
        ".git/config",
    ] {
        let fixture = Fixture::new();
        let target = fixture.0.join(output);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        if !target.exists() {
            fs::write(&target, b"original").unwrap();
        }
        let before = fs::read(&target).unwrap();
        let out = fixture.run(&["sbom", "--format", "cyclonedx", "--output", output]);
        assert_eq!(out.status.code(), Some(2), "{output}: {out:?}");
        assert_eq!(fs::read(&target).unwrap(), before);
    }
}

#[test]
fn openvex_product_matches_the_affected_name_and_version() {
    let fixture = Fixture::new();
    let out = fixture.run(&["sbom", "--format", "vex"]);
    success(&out);
    let vex: Value = serde_json::from_slice(&out.stdout).unwrap();
    let statements = vex["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 1);
    assert_eq!(statements[0]["status"], "under_investigation");
    assert_eq!(statements[0]["products"][0]["@id"], "pkg:npm/fakepkg@2.0.0");
    assert!(statements[0]["status_notes"]
        .as_str()
        .unwrap()
        .contains("fakepkg@2.0.0"));
}

#[test]
fn both_requires_all_outputs_before_overwriting_any_artifact() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("vex.json"), b"original VEX\n").unwrap();
    let out = fixture.run(&["sbom", "--format", "both", "--vex-output", "vex.json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("USAGE_ERROR"));
    assert_eq!(
        fs::read(fixture.0.join("vex.json")).unwrap(),
        b"original VEX\n"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("wrote"));
}

#[test]
fn both_invalid_second_path_preserves_the_existing_first_artifact() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("vex.json"), b"original VEX\n").unwrap();
    let out = fixture.run(&[
        "sbom",
        "--format",
        "both",
        "--vex-output",
        "vex.json",
        "--output",
        "missing/dir/cdx.json",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("IO_ERROR"));
    assert_eq!(
        fs::read(fixture.0.join("vex.json")).unwrap(),
        b"original VEX\n"
    );
    assert!(!fixture.0.join("missing").exists());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("wrote"));
}

#[test]
fn both_publishes_two_valid_documents_without_changing_the_inputs() {
    let fixture = Fixture::new();
    let lock_before = fs::read(fixture.0.join("own.lock")).unwrap();
    let osv_before = fs::read(fixture.0.join(".own/osv.json")).unwrap();
    fs::write(fixture.0.join("vex.json"), b"original VEX\n").unwrap();
    fs::write(fixture.0.join("cdx.json"), b"original CDX\n").unwrap();
    success(&fixture.run(&[
        "sbom",
        "--format",
        "both",
        "--vex-output",
        "vex.json",
        "--output",
        "cdx.json",
    ]));
    let vex = fs::read(fixture.0.join("vex.json")).unwrap();
    let cdx = fs::read(fixture.0.join("cdx.json")).unwrap();
    let vex_doc: Value = serde_json::from_slice(&vex).unwrap();
    let cdx_doc: Value = serde_json::from_slice(&cdx).unwrap();
    assert_eq!(
        vex_doc["statements"][0]["products"][0]["@id"],
        "pkg:npm/fakepkg@2.0.0"
    );
    assert_eq!(cdx_doc["components"].as_array().unwrap().len(), 2);
    assert_eq!(vex, fixture.run(&["sbom", "--format", "vex"]).stdout);
    assert_eq!(cdx, fixture.run(&["sbom", "--format", "cyclonedx"]).stdout);
    assert_eq!(fs::read(fixture.0.join("own.lock")).unwrap(), lock_before);
    assert_eq!(
        fs::read(fixture.0.join(".own/osv.json")).unwrap(),
        osv_before
    );
    assert_eq!(fs::read_dir(fixture.0.join(".own/txn")).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn file_outputs_obey_the_project_transaction_lock_but_stdout_is_read_only() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("vex.json"), b"original VEX\n").unwrap();
    fs::write(fixture.0.join("cdx.json"), b"original CDX\n").unwrap();
    let txn = own_core::txn::Txn::begin(&fixture.0).unwrap();
    for args in [
        vec!["sbom", "--format", "cyclonedx", "--output", "cdx.json"],
        vec!["sbom", "--format", "vex", "--output", "vex.json"],
        vec![
            "sbom",
            "--format",
            "both",
            "--vex-output",
            "vex.json",
            "--output",
            "cdx.json",
        ],
    ] {
        let out = fixture.run(&args);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("LOCK_BUSY"));
        assert_eq!(
            fs::read(fixture.0.join("vex.json")).unwrap(),
            b"original VEX\n"
        );
        assert_eq!(
            fs::read(fixture.0.join("cdx.json")).unwrap(),
            b"original CDX\n"
        );
    }
    success(&fixture.run(&["sbom", "--format", "vex"]));
    success(&fixture.run(&["sbom", "--format", "cyclonedx"]));
    txn.rollback().unwrap();
}

#[cfg(unix)]
#[test]
fn both_late_write_failure_rolls_back_the_already_published_first_artifact() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fs::write(fixture.0.join("vex.json"), b"original VEX\n").unwrap();
    let blocked = fixture.0.join("blocked");
    fs::create_dir(&blocked).unwrap();
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o555)).unwrap();
    // Ensure the local fixture really induces a late rename failure. This test
    // is deliberately not a fabricated failure hook in production code.
    let probe = fs::write(blocked.join("probe"), b"probe");
    if unsafe { libc::geteuid() } == 0 {
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).unwrap();
        return; // root bypasses this Unix permission fixture
    }
    assert_eq!(
        probe.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let out = fixture.run(&[
        "sbom",
        "--format",
        "both",
        "--vex-output",
        "vex.json",
        "--output",
        "blocked/cdx.json",
    ]);
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("IO_ERROR"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("rollback failed"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("wrote"));
    assert_eq!(
        fs::read(fixture.0.join("vex.json")).unwrap(),
        b"original VEX\n"
    );
    assert!(!blocked.join("cdx.json").exists());
    assert_eq!(fs::read_dir(fixture.0.join(".own/txn")).unwrap().count(), 0);
}

#[test]
fn both_rejects_overlapping_outputs_and_transaction_metadata() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("vex.json"), b"original VEX\n").unwrap();
    for output in [
        "vex.json",
        ".own/lock",
        ".own/tmp/cdx.json",
        ".own/txn/cdx.json",
    ] {
        let out = fixture.run(&[
            "sbom",
            "--format",
            "both",
            "--vex-output",
            "vex.json",
            "--output",
            output,
        ]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("USAGE_ERROR"));
        assert_eq!(
            fs::read(fixture.0.join("vex.json")).unwrap(),
            b"original VEX\n"
        );
    }
}

#[cfg(unix)]
#[test]
fn output_symlinks_and_parent_escapes_are_refused_before_publication() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let outside = Fixture::new();
    fs::write(fixture.0.join("vex.json"), b"original VEX\n").unwrap();
    fs::write(outside.0.join("cdx.json"), b"outside CDX\n").unwrap();
    symlink(&outside.0, fixture.0.join("escape")).unwrap();
    symlink(outside.0.join("cdx.json"), fixture.0.join("alias.json")).unwrap();
    let absolute = outside.0.join("cdx.json");
    for output in [
        "escape/cdx.json",
        "alias.json",
        "../cdx.json",
        absolute.to_str().unwrap(),
    ] {
        let out = fixture.run(&[
            "sbom",
            "--format",
            "both",
            "--vex-output",
            "vex.json",
            "--output",
            output,
        ]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("IO_ERROR"));
        assert_eq!(
            fs::read(fixture.0.join("vex.json")).unwrap(),
            b"original VEX\n"
        );
        assert_eq!(
            fs::read(outside.0.join("cdx.json")).unwrap(),
            b"outside CDX\n"
        );
    }
}
