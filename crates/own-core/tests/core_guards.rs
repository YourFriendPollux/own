use own_core::config::license_policy_json;
use own_core::lock::parse_manifest;

#[test]
fn config_guard_rejects_malformed_license_sections_instead_of_defaults() {
    let mut accepted = Vec::new();
    for text in [
        "license = 42",
        "license = []",
        "license = 'deny'",
        "[license]\nallow = 'MIT'",
        "[license]\nallow = ['MIT', 42]",
        "[license]\nunknown = false",
        "[license]\nunknown = 'allow'",
        "[license]\ndenny = ['GPL-*']",
        "schema_version = 999",
    ] {
        if license_policy_json(text).is_ok() {
            accepted.push(text);
        }
    }
    assert!(
        accepted.is_empty(),
        "malformed configs accepted: {accepted:?}"
    );
}

fn empty_manifest(schema: u32) -> String {
    format!("[manifest]\nschema_version = {schema}\npackage = 'a@1.0.0'\npackage_files_sha256 = '{}'\nfile_count = 0\ntotal_size = 0\n", own_core::sha256_hex(b""))
}

#[test]
fn lock_reader_rejects_unsupported_schema_before_any_consumer_uses_it() {
    let lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
    let source = own_core::canonical::write_lock_canonical(&lock);
    for version in [0, 99] {
        let invalid = source.replace("schema_version = 1", &format!("schema_version = {version}"));
        assert!(own_core::lock::parse_lock(&invalid).is_err());
    }
}

#[test]
fn manifest_guard_rejects_unsupported_schema() {
    assert!(
        parse_manifest(&empty_manifest(999)).is_err(),
        "future manifest schema accepted"
    );
}

#[test]
fn manifest_guard_rejects_unknown_fields() {
    let text = empty_manifest(1) + "future_validation = true\n";
    assert!(
        parse_manifest(&text).is_err(),
        "unknown manifest field accepted"
    );
}

#[test]
fn manifest_guard_rejects_unsafe_paths_and_duplicates() {
    let file = |path: &str| {
        format!(
            "\n[[file]]\npath = '{path}'\nsha256 = '{}'\nsize = 0\nexec = false\n",
            own_core::sha256_hex(b"")
        )
    };
    let mut accepted = Vec::new();
    for path in [
        "../outside",
        "/outside",
        "./file",
        "sub/../file",
        "sub\\file",
        "",
    ] {
        if parse_manifest(&(empty_manifest(1) + &file(path))).is_ok() {
            accepted.push(path);
        }
    }
    assert!(
        accepted.is_empty(),
        "unsafe manifest paths accepted: {accepted:?}"
    );
    assert!(
        parse_manifest(&(empty_manifest(1) + &file("same") + &file("same"))).is_err(),
        "duplicate file accepted"
    );
}

use own_core::canonical::{
    compute_lock_digest, compute_vendor_files_sha256, default_license_policy, empty_lock,
    write_lock_canonical,
};
use own_core::lock::{Lock, Manifest, ManifestFile, ManifestHeader, Package};
use own_core::verify::verify;
use std::fs;

fn verified_tree() -> (
    tempfile::TempDir,
    Lock,
    serde_json::Map<String, serde_json::Value>,
) {
    let root = tempfile::tempdir().unwrap();
    let pkgdir = "vendor/own/a@1.0.0";
    fs::create_dir_all(root.path().join(format!("{pkgdir}/dist"))).unwrap();
    fs::create_dir_all(root.path().join("vendor/own/.manifests")).unwrap();
    fs::write(root.path().join(format!("{pkgdir}/dist/index.js")), b"ok\n").unwrap();
    let hash = own_core::sha256_hex(b"ok\n");
    let package_hash =
        own_core::package_files_sha256(&[("dist/index.js".into(), hash[7..].into(), 3, false)]);
    let manifest = Manifest {
        manifest: ManifestHeader {
            schema_version: 1,
            package: "a@1.0.0".into(),
            package_files_sha256: package_hash.clone(),
            file_count: 1,
            total_size: 3,
        },
        files: vec![ManifestFile {
            path: "dist/index.js".into(),
            sha256: hash,
            size: 3,
            exec: false,
        }],
    };
    fs::write(
        root.path().join("vendor/own/.manifests/a@1.0.0.toml"),
        toml::to_string(&manifest).unwrap(),
    )
    .unwrap();
    let mut overrides = serde_json::Map::new();
    overrides.insert("a".into(), serde_json::json!("file:vendor/own/a@1.0.0"));
    let mut lock = empty_lock("0.1.0", "1", &overrides);
    lock.packages.push(Package {
        name: "a".into(),
        ecosystem: "npm".into(),
        version: "1.0.0".into(),
        dir: pkgdir.into(),
        registry: "https://registry.npmjs.org".into(),
        integrity: "sha512-test".into(),
        tarball_sha256: own_core::sha256_hex(b""),
        version_manifest_sha256: own_core::sha256_hex(b""),
        provenance_level: "integrity-only".into(),
        provenance_source: None,
        mode: "verbatim".into(),
        roots: vec![".".into()],
        dependents: vec!["importer:.".into()],
        license_expression: "MIT".into(),
        license_selected: None,
        license_policy: "allow".into(),
        license_files: vec![],
        package_files_sha256: package_hash,
        file_count: 1,
        total_size: 3,
        diamond_resolution: None,
        unified_ranges: None,
    });
    lock.metadata.vendor_files_sha256 = compute_vendor_files_sha256(&lock.packages);
    lock.metadata.lock_digest = compute_lock_digest(&lock, &overrides);
    fs::write(root.path().join("own.lock"), write_lock_canonical(&lock)).unwrap();
    let out = verify(root.path(), &default_license_policy(), &overrides).unwrap();
    assert!(out.findings.is_empty(), "baseline: {:?}", out.findings);
    (root, lock, overrides)
}

fn assert_not_clean(
    root: &std::path::Path,
    overrides: &serde_json::Map<String, serde_json::Value>,
) {
    if let Ok(out) = verify(root, &default_license_policy(), overrides) {
        assert!(!out.findings.is_empty(), "hostile tree reported clean");
    }
}

#[cfg(unix)]
#[test]
fn verify_guard_reports_unlisted_fifo() {
    use std::os::unix::ffi::OsStrExt;
    let (root, _, overrides) = verified_tree();
    let path = std::ffi::CString::new(
        root.path()
            .join("vendor/own/a@1.0.0/.extra-fifo")
            .as_os_str()
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert_not_clean(root.path(), &overrides);
}

#[cfg(unix)]
#[test]
fn verify_guard_rejects_symlink_package_and_file_parents() {
    use std::os::unix::fs::symlink;
    let mut accepted = Vec::new();
    for rel in [
        "vendor/own/a@1.0.0",
        "vendor/own/a@1.0.0/dist",
        "vendor/own/.manifests",
    ] {
        let (root, _, overrides) = verified_tree();
        let outside = tempfile::tempdir().unwrap();
        fs::rename(root.path().join(rel), outside.path().join("original")).unwrap();
        symlink(outside.path().join("original"), root.path().join(rel)).unwrap();
        if let Ok(out) = verify(root.path(), &default_license_policy(), &overrides) {
            if out.findings.is_empty() {
                accepted.push(rel);
            }
        }
    }
    assert!(accepted.is_empty(), "symlink tree accepted: {accepted:?}");
}

#[test]
fn verify_guard_rejects_nonobject_policy() {
    let (root, mut lock, overrides) = verified_tree();
    let invalid = serde_json::json!(null);
    lock.metadata.license_policy_sha256 = own_core::canonical::license_policy_sha256(&invalid);
    lock.metadata.lock_digest = compute_lock_digest(&lock, &overrides);
    fs::write(root.path().join("own.lock"), write_lock_canonical(&lock)).unwrap();
    assert!(
        verify(root.path(), &invalid, &overrides).is_err(),
        "nonobject policy accepted"
    );
}

#[test]
fn verify_guard_reports_hidden_orphan() {
    let (root, _, overrides) = verified_tree();
    fs::create_dir(root.path().join("vendor/own/.untracked")).unwrap();
    assert_not_clean(root.path(), &overrides);
}

#[test]
fn verify_guard_reports_unlisted_empty_directory() {
    let (root, _, overrides) = verified_tree();
    fs::create_dir(root.path().join("vendor/own/a@1.0.0/.extra-empty")).unwrap();
    assert_not_clean(root.path(), &overrides);
}
