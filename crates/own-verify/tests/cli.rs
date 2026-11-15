use own_core::canonical::{empty_lock, write_lock_canonical};
use own_core::config::DEFAULT_OWN_TOML;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

struct Project(PathBuf);

impl Project {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "own-verify-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let project = Self(root);
        project.write("own.toml", DEFAULT_OWN_TOML);
        project.write("package.json", "{}\n");
        project.write(
            "own.lock",
            &write_lock_canonical(&empty_lock("0.1.0", "1", &serde_json::Map::new())),
        );
        fs::create_dir_all(project.0.join("vendor/own/.manifests")).unwrap();
        project
    }

    fn write(&self, path: &str, contents: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn with_package() -> Self {
        use own_core::canonical::{compute_lock_digest, compute_vendor_files_sha256};
        use own_core::lock::{LicenseFile, Package};
        use own_core::toml_write::TomlWriter;
        use own_core::{package_files_sha256, sha256_hex};

        let project = Self::new();
        let files = [
            ("LICENSE", "MIT License\n"),
            ("dist/index.js", "module.exports=1\n"),
            (
                "package.json",
                "{\"name\":\"fakepkg\",\"version\":\"1.0.0\"}\n",
            ),
        ];
        let hashes: Vec<_> = files
            .iter()
            .map(|(path, text)| {
                project.write(&format!("vendor/own/fakepkg@1.0.0/{path}"), text);
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
        let package_hash = package_files_sha256(&hashes);
        let size = hashes.iter().map(|file| file.2).sum();
        let count = hashes.len() as u64;
        let mut manifest = TomlWriter::new();
        manifest
            .section("[manifest]")
            .key_int("schema_version", 1)
            .key_string("package", "fakepkg@1.0.0")
            .key_string("package_files_sha256", &package_hash)
            .key_int("file_count", count)
            .key_int("total_size", size);
        for (path, hash, size, _) in &hashes {
            manifest
                .section("[[file]]")
                .key_string("path", path)
                .key_string("sha256", &format!("sha256:{hash}"))
                .key_int("size", *size)
                .key_value("exec", "false");
        }
        project.write(
            "vendor/own/.manifests/fakepkg@1.0.0.toml",
            &manifest.finish(),
        );
        let overrides = serde_json::json!({"fakepkg": "file:vendor/own/fakepkg@1.0.0"});
        let overrides = overrides.as_object().unwrap();
        project.write(
            "package.json",
            &serde_json::json!({"pnpm": {"overrides": overrides}}).to_string(),
        );
        let mut lock = empty_lock("0.1.0", "1", overrides);
        lock.packages.push(Package {
            name: "fakepkg".into(),
            ecosystem: "npm".into(),
            version: "1.0.0".into(),
            dir: "vendor/own/fakepkg@1.0.0".into(),
            registry: "https://registry.npmjs.org".into(),
            integrity: format!("sha512-{}==", "A".repeat(86)),
            tarball_sha256: sha256_hex(b"synthetic tarball identity"),
            version_manifest_sha256: sha256_hex(b"synthetic version manifest identity"),
            provenance_level: "integrity-only".into(),
            provenance_source: None,
            mode: "verbatim".into(),
            roots: vec![".".into()],
            dependents: vec!["importer:.".into()],
            license_expression: "MIT".into(),
            license_selected: None,
            license_policy: "allow".into(),
            license_files: vec![LicenseFile {
                path: "LICENSE".into(),
                sha256: sha256_hex(b"MIT License\n"),
            }],
            package_files_sha256: package_hash,
            file_count: count,
            total_size: size,
            diamond_resolution: None,
            unified_ranges: None,
        });
        lock.metadata.vendor_files_sha256 = compute_vendor_files_sha256(&lock.packages);
        lock.metadata.lock_digest = compute_lock_digest(&lock, overrides);
        project.write("own.lock", &write_lock_canonical(&lock));
        project
    }

    fn run(&self, args: &[&str]) -> Output {
        run(&self.0, args)
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_own-verify"))
        .arg("--root")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
}

fn assert_sorted_keys(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            let keys: Vec<_> = object.keys().collect();
            let mut sorted = keys.clone();
            sorted.sort();
            assert_eq!(keys, sorted, "{value}");
            for value in object.values() {
                assert_sorted_keys(value);
            }
        }
        serde_json::Value::Array(array) => {
            for value in array {
                assert_sorted_keys(value);
            }
        }
        _ => {}
    }
}

fn assert_json_error(output: &Output, code: &str) {
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        !output.stdout.is_empty(),
        "missing JSON error envelope: {output:?}"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema_version"], 1);
    assert_eq!(envelope["command"], "verify");
    assert_eq!(envelope["status"], "error");
    assert_eq!(envelope["exit_code"], 2);
    assert!(envelope["data"].is_object());
    let findings = envelope["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["code"], code);
    assert_eq!(findings[0]["severity"], "error");
    assert!(findings[0]["package"].is_string());
    assert!(findings[0]["path"].is_string());
    assert!(!findings[0]["message"].as_str().unwrap().is_empty());
    assert_sorted_keys(&envelope);
}

fn assert_error(output: &Output, code: &str, path: &str) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(code), "stderr={stderr}");
    assert!(stderr.contains(path), "stderr={stderr}");
}

#[test]
fn inv5_io_error_when_package_json_is_missing() {
    let project = Project::new();
    fs::remove_file(project.0.join("package.json")).unwrap();
    assert_error(&project.run(&[]), "IO_ERROR", "package.json");
}

#[test]
fn inv5_parse_error_when_own_toml_is_malformed() {
    let project = Project::new();
    project.write("own.toml", "[license\n");
    assert_error(&project.run(&[]), "PARSE_ERROR", "own.toml");
}

#[test]
fn not_initialized_when_lock_or_config_is_missing() {
    for path in ["own.lock", "own.toml"] {
        let project = Project::new();
        fs::remove_file(project.0.join(path)).unwrap();
        assert_error(&project.run(&[]), "NOT_INITIALIZED", path);
    }
}

#[test]
fn inv5_parse_error_when_package_json_has_invalid_shape() {
    for text in [
        "[]",
        "null",
        r#"{"pnpm":null}"#,
        r#"{"pnpm":{"overrides":[]}}"#,
        r#"{"pnpm":{"overrides":{"fakepkg":42}}}"#,
    ] {
        let project = Project::new();
        project.write("package.json", text);
        assert_error(&project.run(&[]), "PARSE_ERROR", "package.json");
    }
}

#[test]
fn inv8_installed_reports_altered_fakepkg() {
    let project = Project::with_package();
    let baseline = project.run(&[]);
    assert!(baseline.status.success(), "{baseline:?}");
    project.write(
        "node_modules/.pnpm/fakepkg@1.0.0/node_modules/fakepkg/dist/index.js",
        "module.exports=2\n",
    );
    let output = project.run(&["--installed", "--format", "json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = envelope["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["code"], "DRIFT_INSTALLED");
    assert_eq!(findings[0]["package"], "fakepkg@1.0.0");
    assert_eq!(findings[0]["path"], "dist/index.js");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn human_findings_are_results_on_stdout() {
    let project = Project::new();
    project.write("vendor/own/orphan.txt", "orphan\n");
    let output = project.run(&[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    // The human line carries the finding message: the code alone cannot tell
    // "file not in manifest" from "symlink present".
    assert!(
        stdout.starts_with("ERROR: [DRIFT_ORPHAN]  vendor/own/orphan.txt — "),
        "{stdout:?}"
    );
    assert!(stdout.ends_with('\n'), "{stdout:?}");
}

#[test]
fn inv10_json_keys_are_sorted_recursively() {
    let project = Project::with_package();
    project.write("vendor/own/fakepkg@1.0.0/dist/index.js", "tampered\n");
    let output = project.run(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let envelope = serde_json::from_slice(&output.stdout).unwrap();
    assert_sorted_keys(&envelope);
    assert_eq!(output.stdout, project.run(&["--format", "json"]).stdout);
}

#[test]
fn inv10_installed_findings_are_merged_in_sorted_order() {
    let project = Project::with_package();
    project.write("vendor/own/orphan.txt", "orphan\n");
    project.write(
        "vendor/own/fakepkg@1.0.0/dist/index.js",
        "vendor tampered\n",
    );
    project.write(
        "node_modules/.pnpm/fakepkg@1.0.0/node_modules/fakepkg/dist/index.js",
        "installed tampered\n",
    );
    let output = project.run(&["--installed", "--format", "json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = envelope["findings"].as_array().unwrap();
    let keys: Vec<_> = findings
        .iter()
        .map(|f| {
            (
                f["code"].as_str().unwrap(),
                f["package"].as_str().unwrap(),
                f["path"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(keys.len(), 3, "{keys:?}");
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

#[test]
fn usage_error_when_output_format_is_invalid() {
    let project = Project::new();
    assert_error(&project.run(&["--format", "bogus"]), "USAGE_ERROR", "bogus");
}

#[test]
fn inv5_json_envelope_is_emitted_for_state_errors() {
    let project = Project::new();
    fs::remove_file(project.0.join("package.json")).unwrap();
    assert_json_error(&project.run(&["--format", "json"]), "IO_ERROR");
    project.write("package.json", "{ malformed");
    assert_json_error(&project.run(&["--format=json"]), "PARSE_ERROR");
    project.write("package.json", "{}");
    project.write("own.toml", "[license\n");
    assert_json_error(&project.run(&["--format", "json"]), "PARSE_ERROR");
    project.write("own.toml", DEFAULT_OWN_TOML);
    project.write("own.lock", "[metadata\n");
    assert_json_error(&project.run(&["--format", "json"]), "PARSE_ERROR");
    fs::remove_file(project.0.join("own.lock")).unwrap();
    assert_json_error(&project.run(&["--format", "json"]), "NOT_INITIALIZED");
}

#[test]
fn json_usage_errors_reject_remote_or_unknown_options() {
    let project = Project::new();
    for args in [
        &["--remote", "--format", "json"][..],
        &["--format=json", "--unknown"][..],
    ] {
        assert_json_error(&project.run(args), "USAGE_ERROR");
    }
}

#[test]
fn format_findings_from_core_exit_2() {
    let project = Project::with_package();
    project.write("vendor/own/.manifests/fakepkg@1.0.0.toml", "[manifest\n");
    assert_json_error(&project.run(&["--format", "json"]), "PARSE_ERROR");

    let project = Project::new();
    let lock = fs::read_to_string(project.0.join("own.lock")).unwrap();
    project.write("own.lock", &format!("# noncanonical\n{lock}"));
    assert_json_error(&project.run(&["--format", "json"]), "LOCK_NOT_CANONICAL");
}

#[test]
fn inv5_io_error_when_state_files_are_unreadable() {
    for path in ["package.json", "own.toml", "own.lock"] {
        let project = Project::new();
        fs::remove_file(project.0.join(path)).unwrap();
        fs::create_dir(project.0.join(path)).unwrap();
        assert_error(&project.run(&[]), "IO_ERROR", path);
        assert_json_error(&project.run(&["--format", "json"]), "IO_ERROR");
        fs::remove_dir(project.0.join(path)).unwrap();
        fs::write(project.0.join(path), [0xff]).unwrap();
        assert_error(&project.run(&[]), "IO_ERROR", path);
    }
}

#[test]
fn inv8_installed_accepts_a_clean_publication_subset() {
    let project = Project::with_package();
    let no_install = project.run(&["--installed"]);
    assert!(no_install.status.success(), "{no_install:?}");
    assert!(no_install.stderr.is_empty());
    assert_eq!(no_install.stdout, b"ok: no findings\n");
    project.write(
        "node_modules/.pnpm/fakepkg@1.0.0/node_modules/fakepkg/dist/index.js",
        "module.exports=1\n",
    );
    let subset = project.run(&["--installed"]);
    assert_eq!(subset.stdout, no_install.stdout);
    assert!(subset.status.success(), "{subset:?}");
    assert!(subset.stderr.is_empty());
}

#[test]
fn installed_checks_file_alias_and_peer_layouts_via_shared_core() {
    for store in [
        "fakepkg@file+vendor+own+fakepkg@1.0.0",
        "fakepkg@file+vendor+own+fakepkg@1.0.0_peer@2.0.0",
    ] {
        let project = Project::with_package();
        let path = format!("node_modules/.pnpm/{store}/node_modules/fakepkg/dist/index.js");
        project.write(&path, "module.exports=1\n");
        assert!(project.run(&["--installed"]).status.success());
        project.write(&path, "tampered installed bytes\n");
        assert!(
            project.run(&[]).status.success(),
            "vendor bytes must stay unchanged"
        );
        let output = project.run(&["--installed", "--format", "json"]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(envelope["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == "DRIFT_INSTALLED" && f["path"] == "dist/index.js"));
    }
}

#[test]
fn inv10_clean_json_matches_the_sorted_envelope_snapshot() {
    let project = Project::new();
    let output = Command::new(env!("CARGO_BIN_EXE_own-verify"))
        .current_dir(&project.0)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "{\"command\":\"verify\",\"data\":{},\"exit_code\":0,\"findings\":[],\"schema_version\":1,\"status\":\"ok\"}\n"
    );
}

#[test]
fn malformed_override_maps_never_become_a_clean_empty_map() {
    let wrong_maps = [
        serde_json::json!(null),
        serde_json::json!([]),
        serde_json::json!(42),
        serde_json::json!(false),
        serde_json::json!("not a map"),
    ];
    let mut malformed = Vec::new();
    for wrong in wrong_maps {
        malformed.push(wrong.clone());
        malformed.push(serde_json::json!({"pnpm":wrong}));
        malformed.push(serde_json::json!({"pnpm":{"overrides":wrong}}));
    }
    for value in [
        serde_json::json!(null),
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!(42),
        serde_json::json!(false),
        serde_json::json!(""),
        serde_json::json!(" \t"),
    ] {
        malformed.push(serde_json::json!({"pnpm":{"overrides":{"unused":value}}}));
    }
    for key in ["", " \t"] {
        malformed.push(serde_json::json!({"pnpm":{"overrides":{key:"^1.0.0"}}}));
    }
    for text in malformed {
        let project = Project::new();
        project.write("package.json", &text.to_string());
        assert_error(&project.run(&[]), "PARSE_ERROR", "package.json");
        assert_json_error(&project.run(&["--format=json"]), "PARSE_ERROR");
    }
}

#[test]
fn absent_or_valid_nonvendor_override_maps_still_verify_cleanly() {
    for text in [
        "{}",
        r#"{"pnpm":{}}"#,
        r#"{"pnpm":{"overrides":{}}}"#,
        r#"{"pnpm":{"overrides":{"other":"^1.0.0"}}}"#,
    ] {
        let project = Project::new();
        project.write("package.json", text);
        let output = project.run(&["--format=json"]);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["status"], "ok");
        assert_eq!(envelope["exit_code"], 0);
        assert_eq!(envelope["findings"], serde_json::json!([]));
        assert_sorted_keys(&envelope);
    }
}

#[test]
fn policy_parse_errors_name_own_toml_in_both_formats() {
    for text in [
        "license = false\n",
        "license = []\n",
        "[license]\nallow = false\n",
        "[license]\nallow = [42]\n",
        "[license]\nallow = [\"\"]\n",
        "[license]\nunknown = \"allow\"\n",
        "[license]\nunknown_field = true\n",
    ] {
        let project = Project::new();
        project.write("own.toml", text);
        assert_error(&project.run(&[]), "PARSE_ERROR", "own.toml");
        let output = project.run(&["--format=json"]);
        assert_json_error(&output, "PARSE_ERROR");
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(envelope["findings"][0]["message"]
            .as_str()
            .unwrap()
            .contains("own.toml"));
    }
}

#[cfg(unix)]
#[test]
fn deleted_current_directory_is_an_io_error_not_a_panic() {
    for format in ["json", "human"] {
        let project = Project::new();
        let cwd = project.0.join("deleted-current-directory");
        fs::create_dir(&cwd).unwrap();
        let output = Command::new("/bin/sh")
            .args([
                "-c",
                "cd \"$1\" && rmdir \"$1\" && exec \"$2\" --format=\"$3\"",
                "own-verify-deleted-cwd",
            ])
            .arg(&cwd)
            .arg(env!("CARGO_BIN_EXE_own-verify"))
            .arg(format)
            .output()
            .unwrap();
        if format == "json" {
            assert_json_error(&output, "IO_ERROR");
        } else {
            assert_error(&output, "IO_ERROR", "current directory");
        }
    }
}

#[test]
fn schema_errors_keep_their_categories_and_json_exit_two() {
    for text in [
        "schema_version = 0\n",
        "schema_version = 2\n",
        "schema_version = \"1\"\n",
    ] {
        let project = Project::new();
        project.write("own.toml", text);
        assert_error(&project.run(&[]), "CONFIG_SCHEMA_UNSUPPORTED", "own.toml");
        assert_json_error(
            &project.run(&["--format=json"]),
            "CONFIG_SCHEMA_UNSUPPORTED",
        );
    }
    for version in [0, 2] {
        let project = Project::new();
        let lock = fs::read_to_string(project.0.join("own.lock")).unwrap();
        project.write(
            "own.lock",
            &lock.replacen(
                "schema_version = 1",
                &format!("schema_version = {version}"),
                1,
            ),
        );
        assert_error(&project.run(&[]), "PARSE_ERROR", "own.lock");
        assert_json_error(&project.run(&["--format=json"]), "PARSE_ERROR");
    }
}

#[test]
fn absent_and_explicit_empty_license_policies_remain_valid_defaults() {
    for text in [
        "",
        "schema_version = 1\n",
        "schema_version = 1\n[license]\n",
    ] {
        let project = Project::new();
        project.write("own.toml", text);
        let output = project.run(&["--format=json"]);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["findings"], serde_json::json!([]));
        assert_eq!(envelope["status"], "ok");
    }
}

#[test]
fn strict_override_map_preserves_valid_npm_alias_selectors() {
    let project = Project::with_package();
    let overrides = serde_json::json!({
        "fakepkg":"file:vendor/own/fakepkg@1.0.0",
        "alias@npm:fakepkg@1.0.0":"file:vendor/own/fakepkg@1.0.0"
    });
    project.write(
        "package.json",
        &serde_json::json!({"pnpm":{"overrides":overrides}}).to_string(),
    );
    let text = fs::read_to_string(project.0.join("own.lock")).unwrap();
    let mut lock = own_core::lock::parse_lock(&text).unwrap();
    lock.metadata.lock_digest =
        own_core::canonical::compute_lock_digest(&lock, overrides.as_object().unwrap());
    project.write("own.lock", &write_lock_canonical(&lock));
    let output = project.run(&["--format=json"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["findings"], serde_json::json!([]));
}
