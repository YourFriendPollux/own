#![cfg(unix)]
//! Verified-archive UPDATE regressions and controlled PR plumbing.
//! Synthetic fixtures: no real commit, push, registry or GitHub contact.
use super::*;
use sha2::{Digest, Sha512};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};

// Synthetic unit fixtures only: no published-data or live-network claim.
static NEXT_UPDATE: AtomicU64 = AtomicU64::new(0);
struct UpdateRoot(std::path::PathBuf);
impl UpdateRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "own-update-security-{}-{}",
            std::process::id(),
            NEXT_UPDATE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("vendor/own/a@1.0.0")).unwrap();
        std::fs::write(root.join("own.toml"), own_core::config::DEFAULT_OWN_TOML).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"synthetic-update","pnpm":{"overrides":{"a":"file:vendor/own/a@1.0.0"}}}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\nimporters: {}\npackages: {}\n",
        )
        .unwrap();
        for (path, contents) in [
            (
                "package.json",
                r#"{"name":"a","version":"1.0.0","license":"MIT"}"#,
            ),
            ("LICENSE", "MIT License\n"),
            ("index.js", "module.exports = 1;\n"),
            ("removed.txt", "removed in the new version\n"),
        ] {
            std::fs::write(root.join("vendor/own/a@1.0.0").join(path), contents).unwrap();
        }
        Self(root)
    }

    fn lock(&self) -> Lock {
        let pol = license_policy_json(own_core::config::DEFAULT_OWN_TOML).unwrap();
        let mut lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        let mut package = super::override_tests::package("a", "1.0.0");
        let (hash, count, size) = own_core::verify::hash_dir(&self.0.join(&package.dir)).unwrap();
        package.package_files_sha256 = hash;
        package.file_count = count;
        package.total_size = size;
        package.license_files[0].sha256 = own_core::sha256_hex(b"MIT License\n");
        let manifest =
            build_manifest_pub(&package.name, &package.version, &self.0, &package.dir).unwrap();
        std::fs::create_dir_all(self.0.join("vendor/own/.manifests")).unwrap();
        std::fs::write(self.0.join("vendor/own/.manifests/a@1.0.0.toml"), manifest).unwrap();
        lock.packages.push(package);
        lock.metadata.license_policy_sha256 = license_policy_sha256(&pol);
        lock.metadata.vendor_files_sha256 = compute_vendor_files_sha256(&lock.packages);
        lock.metadata.lock_digest = compute_lock_digest(&lock, &read_overrides(&self.0).unwrap());
        std::fs::write(self.0.join("own.lock"), write_lock_canonical(&lock)).unwrap();
        let outcome =
            own_core::verify::verify(&self.0, &pol, &read_overrides(&self.0).unwrap()).unwrap();
        assert!(outcome.findings.is_empty(), "{:?}", outcome.findings);
        lock
    }
}
impl Drop for UpdateRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn update_args() -> UpdateArgs {
    UpdateArgs {
        pkg: "a".into(),
        new_version: "1.1.0".into(),
        no_pr: true,
        allow_diamond: None,
        no_install: true,
    }
}

fn update_archive(package: &serde_json::Value, js: &[u8]) -> (Vec<u8>, String, String) {
    let json = serde_json::to_vec(package).unwrap();
    let mut raw = Vec::new();
    for (name, bytes) in [
        ("package/package.json", json.as_slice()),
        ("package/LICENSE", b"MIT License\n".as_slice()),
        ("package/index.js", js),
        (
            "package/added.txt",
            b"added in the new version\n".as_slice(),
        ),
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
    let mut gzip = Command::new("gzip")
        .args(["-n", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // Less than 8 KiB: the bounded input cannot fill either pipe.
    gzip.stdin.take().unwrap().write_all(&raw).unwrap();
    let compressed = gzip.wait_with_output().unwrap();
    assert!(compressed.status.success());
    let bytes = compressed.stdout;
    let hash = Sha512::digest(&bytes);
    let mut base64 = Command::new("base64")
        .arg("-w0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    base64.stdin.take().unwrap().write_all(&hash).unwrap();
    let encoded = base64.wait_with_output().unwrap();
    assert!(encoded.status.success());
    let integrity = format!("sha512-{}", String::from_utf8(encoded.stdout).unwrap());
    let verified_hash = own_net::verify_sri_integrity(&integrity, &bytes).unwrap();
    (bytes, verified_hash, integrity)
}

fn apply_archive(
    txn: &Txn,
    root: &Path,
    lock: &mut Lock,
    package: &serde_json::Value,
    js: &[u8],
) -> Result<(Lock, crate::diff::DiffReport), String> {
    let (bytes, hash, integrity) = update_archive(package, js);
    let old = lock.packages[0].clone();
    update_inner(
        txn,
        root,
        lock,
        0,
        &old,
        &update_args(),
        &bytes,
        &hash,
        &own_core::sha256_hex(&bytes),
        &crate::add::version_manifest_hash_pub(package).unwrap(),
        &integrity,
        "allow",
        None,
        "MIT",
        &crate::add::evaluate_provenance(package),
        &crate::project_config::load(root).unwrap(),
    )
}

#[test]
fn update_verified_archive_diffs_the_new_temporary_tree_before_replacement() {
    let root = UpdateRoot::new();
    let mut lock = root.lock();
    let before = std::fs::read(root.0.join("vendor/own/a@1.0.0/index.js")).unwrap();
    let txn = Txn::begin(&root.0).unwrap();
    let package = serde_json::json!({"name":"a","version":"1.1.0","license":"MIT"});
    let result = apply_archive(&txn, &root.0, &mut lock, &package, b"eval('new risk');\n");
    assert!(
        result.is_ok(),
        "valid verified update archive refused: {result:?}"
    );
    let (new_lock, report) = result.unwrap();
    assert_eq!(report.added, ["added.txt"]);
    assert_eq!(report.removed, ["removed.txt"]);
    assert_eq!(report.modified, ["index.js", "package.json"]);
    assert!(report
        .signals
        .iter()
        .any(|s| s.name == "eval" && s.path == "index.js"));
    assert_eq!(new_lock.packages[0].version, "1.1.0");
    assert_eq!(
        std::fs::read(root.0.join("vendor/own/a@1.1.0/index.js")).unwrap(),
        b"eval('new risk');\n"
    );
    txn.rollback().unwrap();
    assert_eq!(
        std::fs::read(root.0.join("vendor/own/a@1.0.0/index.js")).unwrap(),
        before
    );
    assert!(!root.0.join("vendor/own/a@1.1.0").exists());
}

#[test]
fn update_archive_refusal_rolls_back_cache_and_removes_temporary_extraction() {
    let root = UpdateRoot::new();
    let mut lock = root.lock();
    let before = std::fs::read(root.0.join("own.lock")).unwrap();
    let txn = Txn::begin(&root.0).unwrap();
    let tmp = root.0.join(format!(".own/tmp/upd-{}", txn.id));
    let package = serde_json::json!({
        "name":"a", "version":"1.1.0", "license":"MIT",
        "scripts":{"postinstall":"exit 99"}
    });
    let result = apply_archive(&txn, &root.0, &mut lock, &package, b"module.exports = 2;\n");
    assert!(
        matches!(result, Err(ref e) if e == "NOT_ELIGIBLE:install_scripts"),
        "{result:?}"
    );
    assert!(
        tmp.is_dir(),
        "fixture must reach extraction before the refusal"
    );
    txn.rollback().unwrap();
    assert!(
        !tmp.exists(),
        "failed update left the extracted archive at {}",
        tmp.display()
    );
    assert_eq!(std::fs::read(root.0.join("own.lock")).unwrap(), before);
    assert!(root.0.join("vendor/own/a@1.0.0").is_dir());
    assert!(!root.0.join("vendor/own/a@1.1.0").exists());
    assert_eq!(
        std::fs::read_dir(root.0.join(".own/cache"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        std::fs::read_dir(root.0.join(".own/txn")).unwrap().count(),
        0
    );
}

fn update_state(root: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(path: &Path, root: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return;
        };
        let rel = path.strip_prefix(root).unwrap().to_str().unwrap();
        let mut value = (metadata.permissions().mode() & 0o777)
            .to_le_bytes()
            .to_vec();
        if metadata.file_type().is_symlink() {
            value.extend_from_slice(
                std::fs::read_link(path)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .as_bytes(),
            );
            out.insert(format!("symlink:{rel}"), value);
        } else if metadata.is_dir() {
            if rel != ".own/cache" {
                out.insert(format!("dir:{rel}"), value);
            }
            for entry in std::fs::read_dir(path).unwrap() {
                walk(&entry.unwrap().path(), root, out);
            }
        } else {
            value.extend_from_slice(&std::fs::read(path).unwrap());
            out.insert(format!("file:{rel}"), value);
        }
    }
    let mut state = std::collections::BTreeMap::new();
    for rel in [
        "own.lock",
        "package.json",
        "pnpm-lock.yaml",
        "vendor/own",
        "node_modules",
        ".own/cache",
    ] {
        walk(&root.join(rel), root, &mut state);
    }
    state
}

#[test]
fn update_pipeline_child() {
    let Some(root) = std::env::var_os("OWN_UPDATE_TEST_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let mut args = update_args();
    args.no_install = std::env::var_os("OWN_UPDATE_NO_INSTALL").is_some();
    let package: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("input.json")).unwrap()).unwrap();
    let bytes = std::fs::read(root.join("input.tgz")).unwrap();
    let download = own_net::TarballDownload {
        sha512_hex: format!("{:x}", Sha512::digest(&bytes)),
        sha256: own_core::sha256_hex(&bytes),
        bytes,
    };
    let result = update_with_fetch(&root, &args, |_| {
        std::fs::write(root.join("fetch-observed"), b"acquisition seam reached\n").unwrap();
        Ok((package, download))
    });
    println!("UPDATE_PIPELINE_RESULT={result:?}");
    let record = match result {
        Ok(code) => serde_json::json!({"code":code,"error":null}),
        Err(error) => serde_json::json!({"code":null,"error":error}),
    };
    std::fs::write(
        root.join("pipeline-result.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
}

fn run_update_pipeline(
    no_install: bool,
    pnpm_body: Option<&str>,
) -> (
    UpdateRoot,
    std::collections::BTreeMap<String, Vec<u8>>,
    serde_json::Value,
) {
    let root = UpdateRoot::new();
    root.lock();
    let mut package = serde_json::json!({"name":"a","version":"1.1.0","license":"MIT"});
    let (bytes, _, integrity) = update_archive(&package, b"eval('new risk');\n");
    package["dist"] = serde_json::json!({"integrity":integrity});
    std::fs::write(
        root.0.join("input.json"),
        serde_json::to_vec(&package).unwrap(),
    )
    .unwrap();
    std::fs::write(root.0.join("input.tgz"), bytes).unwrap();
    let old_copy = root
        .0
        .join("node_modules/.pnpm/a@file+vendor+own+a@1.0.0/node_modules/a");
    std::fs::create_dir_all(&old_copy).unwrap();
    for entry in std::fs::read_dir(root.0.join("vendor/own/a@1.0.0")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), old_copy.join(entry.file_name())).unwrap();
    }
    std::os::unix::fs::symlink(
        ".pnpm/a@file+vendor+own+a@1.0.0/node_modules/a",
        root.0.join("node_modules/a"),
    )
    .unwrap();
    assert!(own_core::verify::verify_installed(&root.0)
        .unwrap()
        .is_empty());
    let real_git = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|path| path.join("git"))
        .find(|path| path.is_file())
        .unwrap()
        .canonicalize()
        .unwrap();
    let initialized = Command::new(&real_git)
        .args(["init", "-q"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(&root.0)
        .output()
        .unwrap();
    assert!(initialized.status.success(), "{initialized:?}");
    // Keep the real worktree clean without creating any commit.
    std::fs::write(root.0.join(".git/info/exclude"), "*\n").unwrap();
    let tools = root.0.join("tools");
    std::fs::create_dir(&tools).unwrap();
    let git_body = format!("printf '%s\\n' \"$*\" >> git-calls\nif [ \"$1\" != status ]; then exit 98; fi\nexec '{}' \"$@\"", real_git.display());
    let mut scripts = vec![
        ("git", git_body),
        (
            "gh",
            "printf 'unexpected gh invocation\\n' >> gh-calls\nexit 98".into(),
        ),
    ];
    if let Some(body) = pnpm_body {
        scripts.push((
            "pnpm",
            format!("printf '%s\\n' \"$*\" >> pnpm-calls\n{body}"),
        ));
    }
    for (name, body) in scripts {
        let tool = tools.join(name);
        std::fs::write(&tool, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let before = update_state(&root.0);
    let refs_before = std::fs::read(root.0.join(".git/HEAD")).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "update::security_tests::update_pipeline_child",
            "--exact",
            "--nocapture",
        ])
        .env("OWN_UPDATE_TEST_ROOT", &root.0)
        .env("PATH", &tools)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    if no_install {
        command.env("OWN_UPDATE_NO_INSTALL", "1");
    } else {
        command.env_remove("OWN_UPDATE_NO_INSTALL");
    }
    let out = command.output().unwrap();
    println!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{out:?}");
    let calls = std::fs::read_to_string(root.0.join("git-calls")).unwrap();
    assert!(
        calls.lines().all(|call| call == "status --porcelain"),
        "--no-pr mutated Git: {calls}"
    );
    assert_eq!(
        std::fs::read(root.0.join(".git/HEAD")).unwrap(),
        refs_before
    );
    assert!(
        !root.0.join("gh-calls").exists(),
        "--no-pr called GitHub plumbing"
    );
    let mut result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.0.join("pipeline-result.json")).unwrap())
            .unwrap();
    result["observed_stdout"] = serde_json::json!(String::from_utf8_lossy(&out.stdout));
    result["observed_stderr"] = serde_json::json!(String::from_utf8_lossy(&out.stderr));
    (root, before, result)
}

#[test]
fn update_diff_parse_failure_removes_the_verified_prepared_archive() {
    let root = UpdateRoot::new();
    std::fs::write(
        root.0.join("vendor/own/a@1.0.0/package.json"),
        b"{invalid JSON\n",
    )
    .unwrap();
    // Synthetic old bytes are hash-anchored, so the error must come from diff.
    let mut lock = root.lock();
    let before = update_state(&root.0);
    let txn = Txn::begin(&root.0).unwrap();
    let package = serde_json::json!({"name":"a","version":"1.1.0","license":"MIT"});
    let result = apply_archive(&txn, &root.0, &mut lock, &package, b"module.exports = 2;\n");
    assert!(
        matches!(result, Err(ref e) if e.starts_with("PARSE_ERROR: old package.json:")),
        "diff error was masked: {result:?}"
    );
    txn.rollback().unwrap();
    assert_eq!(update_state(&root.0), before);
    assert_eq!(
        std::fs::read_dir(root.0.join(".own/tmp")).unwrap().count(),
        0
    );
    assert_eq!(
        std::fs::read_dir(root.0.join(".own/txn")).unwrap().count(),
        0
    );
}

#[test]
fn update_install_and_post_verify_errors_restore_every_owned_write() {
    for (case, body, expected) in [
        ("spawn", None, "PNPM_FAILED:"),
        ("exit", Some("printf 'changed lock\\n' > pnpm-lock.yaml\nprintf 'changed installed file\\n' > node_modules/.pnpm/a@file+vendor+own+a@1.0.0/node_modules/a/index.js\nexit 42"), "PNPM_FAILED"),
        ("config-read", Some("/bin/rm own.toml\nprintf 'changed lock\\n' > pnpm-lock.yaml\nexit 0"), "IO_ERROR:"),
        ("policy-parse", Some("printf '[' > own.toml\nprintf 'changed lock\\n' > pnpm-lock.yaml\nexit 0"), "PARSE_ERROR:"),
        ("override-parse", Some("printf '{' > package.json\nprintf 'changed lock\\n' > pnpm-lock.yaml\nexit 0"), "PARSE_ERROR:"),
        ("verify-error", Some("printf '[' > own.lock\nprintf 'changed lock\\n' > pnpm-lock.yaml\nexit 0"), "PARSE_ERROR:"),
        ("vendor-drift", Some("printf 'tampered vendor bytes\\n' > vendor/own/a@1.1.0/index.js\nprintf 'changed lock\\n' > pnpm-lock.yaml\nexit 0"), "DRIFT_MODIFIED:"),
        ("installed-io", Some("/bin/rm -rf node_modules/.pnpm\nprintf 'not a directory\\n' > node_modules/.pnpm\nexit 0"), "IO_ERROR:"),
    ] {
        let (root, before, result) = run_update_pipeline(false, body);
        assert!(result["error"].as_str().is_some_and(|e| e.starts_with(expected)), "{case}: wrong error path: {result}");
        assert_eq!(update_state(&root.0), before, "{case}: owned writes were not rolled back");
        assert_eq!(std::fs::read_dir(root.0.join(".own/tmp")).unwrap().count(), 0, "{case}: temporary residue");
        assert_eq!(std::fs::read_dir(root.0.join(".own/txn")).unwrap().count(), 0, "{case}: journal residue");
        println!("ROLLBACK_CASE_PASSED={case}");
    }
}

#[test]
fn update_failed_manifest_publication_cleans_the_transaction_temporary_file() {
    let root = UpdateRoot::new();
    let mut lock = root.lock();
    // Synthetic late filesystem fault: a directory occupies the manifest target.
    let target = root.0.join("vendor/own/.manifests/a@1.1.0.toml");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(
        target.join("keep"),
        b"preserve the original conflicting target\n",
    )
    .unwrap();
    let before = update_state(&root.0);
    let txn = Txn::begin(&root.0).unwrap();
    let package = serde_json::json!({"name":"a","version":"1.1.0","license":"MIT"});
    let result = apply_archive(&txn, &root.0, &mut lock, &package, b"module.exports = 2;\n");
    assert!(
        matches!(result, Err(ref e) if e.starts_with("IO_ERROR:")),
        "fixture did not fail manifest publication: {result:?}"
    );
    txn.rollback().unwrap();
    assert_eq!(update_state(&root.0), before);
    let remaining: Vec<_> = std::fs::read_dir(root.0.join(".own/tmp"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(
        remaining.is_empty(),
        "failed manifest write leaked temporary files: {remaining:?}"
    );
}

#[test]
fn update_no_install_verifies_vendor_state_but_reports_install_as_unchecked() {
    let (root, before, result) = run_update_pipeline(true, Some("exit 98"));
    assert_eq!(result["code"], 0, "{result}");
    assert!(result["error"].is_null(), "{result}");
    assert!(
        result["observed_stderr"]
            .as_str()
            .unwrap()
            .contains("--no-install: post-install verification not performed"),
        "skipped verification was not disclosed: {result}"
    );
    assert!(
        result["observed_stdout"]
            .as_str()
            .unwrap()
            .contains("4 files changed, 1 signals"),
        "real archive diff was lost: {result}"
    );
    assert!(!root.0.join("pnpm-calls").exists());
    let policy = license_policy_json(own_core::config::DEFAULT_OWN_TOML).unwrap();
    assert!(
        own_core::verify::verify(&root.0, &policy, &read_overrides(&root.0).unwrap())
            .unwrap()
            .findings
            .is_empty()
    );
    let installed_before: std::collections::BTreeMap<_, _> = before
        .into_iter()
        .filter(|(path, _)| path.contains("node_modules"))
        .collect();
    let installed_after: std::collections::BTreeMap<_, _> = update_state(&root.0)
        .into_iter()
        .filter(|(path, _)| path.contains("node_modules"))
        .collect();
    assert_eq!(
        installed_before, installed_after,
        "--no-install mutated installed copies"
    );
    assert_eq!(
        std::fs::read_dir(root.0.join(".own/tmp")).unwrap().count(),
        0
    );
    assert_eq!(
        std::fs::read_dir(root.0.join(".own/txn")).unwrap().count(),
        0
    );
}

#[test]
fn update_records_the_validated_current_registry_in_the_new_lock_entry() {
    let root = UpdateRoot::new();
    let mut lock = root.lock();
    let mut config: toml::Value = toml::from_str(own_core::config::DEFAULT_OWN_TOML).unwrap();
    config["registry"]["url"] = toml::Value::String("https://registry.example/npm".into());
    std::fs::write(root.0.join("own.toml"), toml::to_string(&config).unwrap()).unwrap();
    let txn = Txn::begin(&root.0).unwrap();
    let package = serde_json::json!({"name":"a","version":"1.1.0","license":"MIT"});
    let (new_lock, _) =
        apply_archive(&txn, &root.0, &mut lock, &package, b"module.exports = 2;\n").unwrap();
    txn.rollback().unwrap();
    assert_eq!(
        new_lock.packages[0].registry, "https://registry.example/npm",
        "stale registry was copied from the old version"
    );
}

#[test]
fn update_rejects_oversized_metadata_before_publishing_the_archive_cache() {
    let root = UpdateRoot::new();
    root.lock();
    let mut config: toml::Value = toml::from_str(own_core::config::DEFAULT_OWN_TOML).unwrap();
    config["security"]["max_unpacked_size_mb"] = toml::Value::Integer(1);
    std::fs::write(root.0.join("own.toml"), toml::to_string(&config).unwrap()).unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(&root.0)
        .status()
        .unwrap()
        .success());
    std::fs::write(root.0.join(".git/info/exclude"), "*\n").unwrap();
    let mut package = serde_json::json!({"name":"a","version":"1.1.0","license":"MIT"});
    let (bytes, hash, integrity) = update_archive(&package, b"module.exports = 2;\n");
    package["dist"] = serde_json::json!({"integrity":integrity,"unpackedSize":2 * 1_048_576});
    let download = own_net::TarballDownload {
        sha512_hex: hash,
        sha256: own_core::sha256_hex(&bytes),
        bytes,
    };
    let before = update_state(&root.0);
    let result = update_with_fetch(&root.0, &update_args(), |_| Ok((package, download)));
    assert!(
        matches!(result, Err(ref e) if e == "NOT_ELIGIBLE:size"),
        "configured metadata cap ignored: {result:?}"
    );
    assert_eq!(update_state(&root.0), before);
    assert!(!root.0.join(".own/cache").exists());
}

#[test]
fn update_uses_configured_extraction_limits_and_rolls_back_partial_archives() {
    let root = UpdateRoot::new();
    let mut lock = root.lock();
    let mut config: toml::Value = toml::from_str(own_core::config::DEFAULT_OWN_TOML).unwrap();
    config["security"]["max_entries"] = toml::Value::Integer(2);
    std::fs::write(root.0.join("own.toml"), toml::to_string(&config).unwrap()).unwrap();
    let before = update_state(&root.0);
    let txn = Txn::begin(&root.0).unwrap();
    let package = serde_json::json!({"name":"a","version":"1.1.0","license":"MIT"});
    let result = apply_archive(&txn, &root.0, &mut lock, &package, b"module.exports = 2;\n");
    txn.rollback().unwrap();
    assert!(
        matches!(result, Err(ref e) if e == "EXTRACT_REFUSED:max_entries"),
        "configured extraction cap ignored: {result:?}"
    );
    assert_eq!(update_state(&root.0), before);
    assert_eq!(
        std::fs::read_dir(root.0.join(".own/tmp")).unwrap().count(),
        0
    );
}

#[test]
fn update_reports_rollback_failure_on_both_install_and_post_read_errors() {
    let mut hidden = Vec::new();
    for (case, body, expected) in [
        ("install", "/bin/rm -rf .own/txn/*/backup/node_modules\nprintf 'changed lock\\n' > pnpm-lock.yaml\nexit 42", "PNPM_FAILED"),
        ("post-read", "/bin/rm -rf .own/txn/*/backup/node_modules\n/bin/rm own.toml\nexit 0", "IO_ERROR"),
    ] {
        let (root, _, result) = run_update_pipeline(false, Some(body));
        let error = result["error"].as_str().unwrap();
        if !error.contains(expected) || !error.contains("ROLLBACK_FAILED:") || !error.contains("journal retained") {
            hidden.push(format!("{case}: rollback failure hidden by {error}"));
        }
        let journals: Vec<_> = std::fs::read_dir(root.0.join(".own/txn")).unwrap().map(|entry| entry.unwrap().path().join("journal.json")).collect();
        assert_eq!(journals.len(), 1, "failed rollback lost the recovery journal");
        let journal: serde_json::Value = serde_json::from_slice(&std::fs::read(&journals[0]).unwrap()).unwrap();
        assert_eq!(journal["state"], "started");
        assert!(journals[0].parent().unwrap().join("backup/own.lock").is_file());
    }
    assert!(hidden.is_empty(), "{}", hidden.join("\n"));
}

#[test]
fn update_rejects_installed_drift_and_rolls_back_the_entire_application() {
    let (root, before, result) = run_update_pipeline(false, Some(
        "dest='node_modules/.pnpm/a@file+vendor+own+a@1.1.0/node_modules/a'\n/bin/mkdir -p \"$dest\"\n/bin/cp vendor/own/a@1.1.0/* \"$dest/\"\nprintf 'tampered installed bytes\\n' > \"$dest/index.js\"\nprintf 'changed lock\\n' > pnpm-lock.yaml\nprintf 'changed existing installed bytes\\n' > node_modules/.pnpm/a@file+vendor+own+a@1.0.0/node_modules/a/index.js\nexit 0"
    ));
    assert!(
        result["error"]
            .as_str()
            .is_some_and(|e| e.contains("DRIFT_INSTALLED")),
        "successful pnpm status hid installed drift: {result}"
    );
    assert_eq!(
        update_state(&root.0),
        before,
        "rollback did not restore project and installed bytes"
    );
    assert_eq!(
        std::fs::read_dir(root.0.join(".own/tmp")).unwrap().count(),
        0
    );
    assert_eq!(
        std::fs::read_dir(root.0.join(".own/txn")).unwrap().count(),
        0
    );
    assert_eq!(
        std::fs::read_to_string(root.0.join("pnpm-calls")).unwrap(),
        "install --ignore-scripts\n"
    );
}

#[test]
fn pr_child() {
    let Some(root) = std::env::var_os("OWN_PR_TEST_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let args = UpdateArgs {
        pkg: "a".into(),
        new_version: "1.1.0".into(),
        no_pr: false,
        allow_diamond: None,
        no_install: true,
    };
    let result = create_pr(&root, &args, &crate::diff::DiffReport::default());
    let expected = if std::env::var_os("OWN_PR_FOREIGN").is_some() {
        "GIT_ERROR"
    } else {
        "GH_FAILED"
    };
    assert!(
        matches!(result, Err(ref e) if e.starts_with(expected)),
        "{result:?}"
    );
}

fn run_fixture(foreign: bool) {
    let root =
        std::env::temp_dir().join(format!("own-pr-plumbing-{}-{foreign}", std::process::id()));
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    std::fs::create_dir_all(root.join(".own/tmp")).unwrap();
    let tools = root.join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    for (name, body) in [
        ("git", "printf '%s\\n' \"$*\" >> \"$OWN_PR_TEST_ROOT/calls\"\nif [ \"$1\" = status ]; then printf ' M own.lock\\000'; if [ -n \"${OWN_PR_FOREIGN:-}\" ]; then printf '?? private.txt\\000'; fi; fi\nexit 0"),
        ("gh", "printf 'fixture: GitHub is not contacted\\n' >&2\nexit 1"),
    ] {
        let path = tools.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["update::security_tests::pr_child", "--exact", "--nocapture"])
        .env("PATH", &tools)
        .env("OWN_PR_TEST_ROOT", &root);
    if foreign {
        command.env("OWN_PR_FOREIGN", "1");
    } else {
        command.env_remove("OWN_PR_FOREIGN");
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let calls = std::fs::read_to_string(root.join("calls")).unwrap();
    if foreign {
        assert!(!calls.contains("checkout"));
        assert!(!calls.contains("push"));
    } else {
        assert!(calls.contains("checkout -b own/update-a@1.1.0"));
        assert!(calls.contains("add -- own.lock package.json pnpm-lock.yaml vendor/own"));
    }
}

#[test]
fn pr_accepts_update_changes_and_stages_only_owned_paths_inv11() {
    run_fixture(false);
}

#[test]
fn pr_refuses_foreign_changes_without_staging_or_pushing_inv11() {
    run_fixture(true);
}
