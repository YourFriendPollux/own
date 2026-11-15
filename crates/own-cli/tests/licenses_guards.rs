//! License inventory display and drift regressions through the real CLI.
use own_core::canonical::{
    compute_lock_digest, compute_vendor_files_sha256, empty_lock, write_lock_canonical,
};
use own_core::config::DEFAULT_OWN_TOML;
use own_core::toml_write::TomlWriter;
use own_core::{package_files_sha256, sha256_hex};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new(with_package: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "own-licenses-guards-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("vendor/own/.manifests")).unwrap();
        fs::write(root.join("own.toml"), DEFAULT_OWN_TOML).unwrap();
        let mut overrides = serde_json::Map::new();
        if with_package {
            overrides.insert(
                "fixture".into(),
                serde_json::json!("file:vendor/own/fixture@1.0.0"),
            );
        }
        fs::write(
            root.join("package.json"),
            serde_json::json!({"pnpm":{"overrides":overrides}}).to_string(),
        )
        .unwrap();
        let mut lock = empty_lock("0.1.0", "1", &overrides);
        if with_package {
            let dir = "vendor/own/fixture@1.0.0";
            fs::create_dir(root.join(dir)).unwrap();
            let sources = [
                ("LICENSE", "MIT License\n"),
                (
                    "package.json",
                    "{\"name\":\"fixture\",\"version\":\"1.0.0\"}\n",
                ),
            ];
            let files: Vec<_> = sources
                .iter()
                .map(|(path, text)| {
                    fs::write(root.join(dir).join(path), text).unwrap();
                    (
                        path.to_string(),
                        sha256_hex(text.as_bytes())
                            .trim_start_matches("sha256:")
                            .to_string(),
                        text.len() as u64,
                        false,
                    )
                })
                .collect();
            let hash = package_files_sha256(&files);
            let size: u64 = files.iter().map(|f| f.2).sum();
            let count = files.len() as u64;
            let mut manifest = TomlWriter::new();
            manifest
                .section("[manifest]")
                .key_int("schema_version", 1)
                .key_string("package", "fixture@1.0.0")
                .key_string("package_files_sha256", &hash)
                .key_int("file_count", count)
                .key_int("total_size", size);
            for (path, hash, size, _) in &files {
                manifest
                    .section("[[file]]")
                    .key_string("path", path)
                    .key_string("sha256", &format!("sha256:{hash}"))
                    .key_int("size", *size)
                    .key_value("exec", "false");
            }
            fs::write(
                root.join("vendor/own/.manifests/fixture@1.0.0.toml"),
                manifest.finish(),
            )
            .unwrap();
            lock.packages.push(serde_json::from_value(serde_json::json!({
                "name":"fixture", "ecosystem":"npm", "version":"1.0.0", "dir":dir,
                "registry":"https://registry.npmjs.org", "integrity":format!("sha512-{}==", "A".repeat(86)),
                "tarball_sha256":sha256_hex(b"synthetic-tarball"), "version_manifest_sha256":sha256_hex(b"synthetic-manifest"),
                "provenance_level":"integrity-only", "mode":"verbatim", "roots":["."], "dependents":["importer:."],
                "license_expression":"MIT", "license_policy":"allow", "license_files":[{"path":"LICENSE","sha256":sha256_hex(b"MIT License\n")}],
                "package_files_sha256":hash, "file_count":count, "total_size":size,
            })).unwrap());
            lock.metadata.vendor_files_sha256 = compute_vendor_files_sha256(&lock.packages);
            lock.metadata.lock_digest = compute_lock_digest(&lock, &overrides);
        }
        fs::write(root.join("own.lock"), write_lock_canonical(&lock)).unwrap();
        Self(root)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_own"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn success(output: &Output) {
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn licenses_verified_nonempty_inventory_keeps_the_table_and_does_not_write() {
    let fixture = Fixture::new(true);
    success(&fixture.run(&["verify"]));
    let before = fixture.run(&["licenses"]);
    success(&before);
    let table = String::from_utf8_lossy(&before.stdout);
    for column in ["Package", "Version", "SPDX", "Policy", "Files", "Hash"] {
        assert!(table.contains(column), "{table}");
    }
    assert!(table.contains("fixture") && table.contains("1.0.0") && table.contains("MIT"));
    success(&fixture.run(&["licenses", "--write"]));
    success(&fixture.run(&["verify"]));
    let lock = fs::read(fixture.0.join("own.lock")).unwrap();
    let inventory = fs::read(fixture.0.join("vendor/own/LICENSES.md")).unwrap();
    let after = fixture.run(&["licenses"]);
    success(&after);
    assert_eq!(after.stdout, before.stdout);
    assert_eq!(fs::read(fixture.0.join("own.lock")).unwrap(), lock);
    assert_eq!(
        fs::read(fixture.0.join("vendor/own/LICENSES.md")).unwrap(),
        inventory
    );
}

#[test]
fn licenses_missing_or_changed_inventory_still_blocks_and_keeps_drift_findings() {
    for (missing, expected_code) in [(true, "DRIFT_MISSING"), (false, "DRIFT_MODIFIED")] {
        let fixture = Fixture::new(false);
        success(&fixture.run(&["licenses", "--write"]));
        let inventory = fixture.0.join("vendor/own/LICENSES.md");
        if missing {
            fs::remove_file(inventory).unwrap();
        } else {
            fs::write(inventory, "changed generated inventory\n").unwrap();
        }
        let licenses = fixture.run(&["licenses"]);
        assert!(!licenses.status.success(), "{licenses:?}");
        assert!(licenses.stdout.is_empty(), "{licenses:?}");
        assert!(String::from_utf8_lossy(&licenses.stderr).contains("LICENSES_MD_STALE"));
        let verify = fixture.run(&["verify", "--format=json"]);
        assert_eq!(verify.status.code(), Some(1), "{verify:?}");
        assert!(verify.stderr.is_empty(), "{verify:?}");
        let envelope: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
        let findings = envelope["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1, "{envelope}");
        assert_eq!(findings[0]["code"], expected_code);
        assert_eq!(findings[0]["path"], "vendor/own/LICENSES.md");
    }
}
