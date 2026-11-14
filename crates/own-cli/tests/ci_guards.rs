//! Non-empty offline fixture: CI must exercise actual vendored bytes.
use own_core::canonical::{
    compute_lock_digest, compute_vendor_files_sha256, empty_lock, write_lock_canonical,
};
use own_core::config::DEFAULT_OWN_TOML;
use own_core::lock::{LicenseFile, Package};
use own_core::toml_write::TomlWriter;
use own_core::{package_files_sha256, sha256_hex};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NONCE: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "own-ci-guards-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("vendor/own/.manifests")).unwrap();
        let out = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(out.status.success());
        fs::write(root.join("own.toml"), DEFAULT_OWN_TOML).unwrap();
        fs::write(root.join("package.json"), r#"{"name":"fixture","pnpm":{"overrides":{"a":"file:vendor/own/a@1.0.0"}},"dependencies":{"a":"file:vendor/own/a@1.0.0"}}"#).unwrap();
        fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: file:vendor/own/a@1.0.0\n        version: file:vendor/own/a@1.0.0\npackages: {}\n").unwrap();
        let dir = "vendor/own/a@1.0.0";
        fs::create_dir_all(root.join(dir)).unwrap();
        let source: [(&str, &[u8]); 3] = [
            ("LICENSE", b"MIT License\n"),
            ("index.js", b"module.exports=1\n"),
            ("package.json", b"{\"name\":\"a\",\"version\":\"1.0.0\"}\n"),
        ];
        let files: Vec<_> = source
            .iter()
            .map(|(path, bytes)| {
                fs::write(root.join(dir).join(path), bytes).unwrap();
                (
                    (*path).to_string(),
                    sha256_hex(bytes).trim_start_matches("sha256:").to_string(),
                    bytes.len() as u64,
                    false,
                )
            })
            .collect();
        let digest = package_files_sha256(&files);
        let size = files.iter().map(|f| f.2).sum();
        let mut manifest = TomlWriter::new();
        manifest
            .section("[manifest]")
            .key_int("schema_version", 1)
            .key_string("package", "a@1.0.0")
            .key_string("package_files_sha256", &digest)
            .key_int("file_count", 3)
            .key_int("total_size", size);
        for (path, hash, len, _) in &files {
            manifest
                .section("[[file]]")
                .key_string("path", path)
                .key_string("sha256", &format!("sha256:{hash}"))
                .key_int("size", *len)
                .key_value("exec", "false");
        }
        fs::write(
            root.join("vendor/own/.manifests/a@1.0.0.toml"),
            manifest.finish(),
        )
        .unwrap();
        let mut overrides = serde_json::Map::new();
        overrides.insert("a".into(), serde_json::json!(format!("file:{dir}")));
        let mut lock = empty_lock("0.1.0", "1", &overrides);
        lock.packages.push(Package {
            name: "a".into(), ecosystem: "npm".into(), version: "1.0.0".into(), dir: dir.into(), registry: "https://registry.npmjs.org".into(), integrity: "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".into(), tarball_sha256: sha256_hex(b"synthetic-tarball"), version_manifest_sha256: sha256_hex(b"synthetic-manifest"), provenance_level: "integrity-only".into(), provenance_source: None, mode: "verbatim".into(), roots: vec![".".into()], dependents: vec!["importer:.".into()], license_expression: "MIT".into(), license_selected: None, license_policy: "allow".into(), license_files: vec![LicenseFile { path: "LICENSE".into(), sha256: sha256_hex(b"MIT License\n") }], package_files_sha256: digest, file_count: 3, total_size: size, diamond_resolution: None, unified_ranges: None,
        });
        lock.metadata.vendor_files_sha256 = compute_vendor_files_sha256(&lock.packages);
        lock.metadata.lock_digest = compute_lock_digest(&lock, &overrides);
        fs::write(root.join("own.lock"), write_lock_canonical(&lock)).unwrap();
        Fixture(root)
    }
    fn osv(&self, generated_at: &str, advisories: serde_json::Value) {
        self.osv_with_source_date(generated_at, serde_json::Value::Null, advisories)
    }

    fn osv_with_source_date(
        &self,
        generated_at: &str,
        source_last_modified: serde_json::Value,
        advisories: serde_json::Value,
    ) {
        fs::create_dir_all(self.0.join(".own")).unwrap();
        fs::write(
            self.0.join(".own/osv.json"),
            serde_json::json!({
                "schema_version": 1, "generated_at": generated_at,
                "source": "https://example.invalid/npm/all.zip",
                "source_last_modified": source_last_modified,
                "covered_packages": ["a"], "advisories": advisories,
            })
            .to_string(),
        )
        .unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_env(args, &[])
    }
    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_own"))
            .args(args)
            .current_dir(&self.0)
            .env("OWN_NOW", "2025-01-02T03:04:05Z")
            .env_remove("SOURCE_DATE_EPOCH")
            .env_remove("OWN_OSV_LOCAL_PATH")
            .env_remove("OWN_OSV_MAX_AGE_DAYS")
            .envs(env.iter().copied())
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .env("GIT_CONFIG_NOSYSTEM", "1")
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
fn read(root: &Path, rel: &str) -> Vec<u8> {
    fs::read(root.join(rel)).unwrap()
}

#[test]
fn check_missing_override_does_not_mask_unreadable_snapshot_inv5() {
    for invalid_utf8 in [false, true] {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.0.join(".own")).unwrap();
        let snapshot = fixture.0.join(".own/osv.json");
        if invalid_utf8 {
            fs::write(&snapshot, [0xff, 0xfe]).unwrap();
        } else {
            fs::create_dir(&snapshot).unwrap();
        }
        let out = fixture.run(&["check", "--allow-missing-osv"]);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(
            error.contains("IO_ERROR") || error.contains("PARSE_ERROR"),
            "{out:?}"
        );
        assert!(!error.contains("W_OSV_MISSING"), "{out:?}");
    }
}

#[test]
fn check_osv_fractional_utc_age_preserves_exact_deadline_inv5() {
    let fixture = Fixture::new();
    for (snapshot, now, expected) in [
        ("2024-12-26T03:04:05.125Z", "2025-01-02T03:04:05.125Z", 0),
        ("2024-12-26T03:04:05.125Z", "2025-01-02T03:04:05.1250Z", 0),
        (
            "2024-12-26T03:04:05.125Z",
            "2025-01-02T03:04:05.124999999Z",
            0,
        ),
        (
            "2024-12-26T03:04:05.125Z",
            "2025-01-02T03:04:05.1250000000000000000000001Z",
            2,
        ),
        (
            "2024-12-26T03:04:05.1250000000000000000000001Z",
            "2025-01-02T03:04:05.125Z",
            0,
        ),
        (
            "2024-12-26T03:04:05.125+00:00",
            "2025-01-02T03:04:05.125Z",
            0,
        ),
    ] {
        fixture.osv(snapshot, serde_json::json!([]));
        let out = fixture.run_env(&["check"], &[("OWN_NOW", now)]);
        assert_eq!(
            out.status.code(),
            Some(expected),
            "snapshot={snapshot}, now={now}, {out:?}"
        );
        if expected == 2 {
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("OSV_STALE"),
                "{out:?}"
            );
        }
    }
}

#[test]
fn future_source_date_is_refused_even_with_stale_optout_inv5() {
    // §8.2 risk table: a mirror that lies about its dates must not pass silently.
    // The rule reads the system clock (a mirror cannot know OWN_NOW), so the
    // fixture uses a date no real clock can reach.
    let fixture = Fixture::new();
    fixture.osv_with_source_date(
        "2025-01-02T03:04:05Z",
        serde_json::json!("2099-01-01T00:00:00Z"),
        serde_json::json!([]),
    );
    for args in [
        vec!["check"],
        vec!["check", "--allow-stale-osv"],
        vec!["sbom", "--format", "vex"],
    ] {
        let out = fixture.run_env(&args, &[("OWN_NOW", "2025-01-02T03:04:05Z")]);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(
            error.contains("PARSE_ERROR") && error.contains("future"),
            "{out:?}"
        );
    }
}

#[test]
fn future_dated_osv_snapshot_is_refused_inv5() {
    let fixture = Fixture::new();
    fixture.osv(
        "2025-01-02T03:04:05.0000000000000000000000001Z",
        serde_json::json!([]),
    );
    for args in [
        vec!["check"],
        vec!["check", "--allow-stale-osv"],
        vec!["sbom", "--format", "vex"],
    ] {
        let out = fixture.run(&args);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(
            error.contains("PARSE_ERROR") && error.contains("future"),
            "{out:?}"
        );
    }
}

#[test]
#[ignore = "requires the full public HTTPS OSV npm dump within the configured download cap"]
fn real_osv_fetch_keeps_source_date_at_configured_path_inv10() {
    let fixture = Fixture::new();
    let config = DEFAULT_OWN_TOML.replace(
        "local_path = \".own/osv.json\"",
        "local_path = \".own/cache/real-osv.json\"",
    );
    assert!(config.contains(".own/cache/real-osv.json"));
    fs::write(fixture.0.join("own.toml"), config).unwrap();
    success(&fixture.run(&["osv-fetch"]));
    let snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.0.join(".own/cache/real-osv.json")).unwrap())
            .unwrap();
    let modified = snapshot["source_last_modified"].as_str();
    assert!(
        modified.is_some(),
        "snapshot lost the real HTTP Last-Modified header: {snapshot}"
    );
    assert!(modified.unwrap().ends_with('Z'));
    assert_eq!(snapshot["generated_at"], "2025-01-02T03:04:05Z");
    assert_eq!(snapshot["covered_packages"], serde_json::json!(["a"]));
    assert!(!fixture.0.join(".own/osv.json").exists());
    // The mirror's own date is compared against the system clock, not the
    // injected OWN_NOW, so a live fetch under a pinned CI clock stays usable.
    let check = fixture.run(&["check"]);
    assert!(matches!(check.status.code(), Some(0 | 1)), "{check:?}");
}

#[test]
fn inv10_e1_vex_id_is_byte_stable_across_runs() {
    // Counter-review claim: VEX @id would drift because the reachable set comes
    // from a HashSet. The alert hash sorts before hashing; this observes it
    // end to end through the real binary instead of trusting the reading.
    let fixture = Fixture::new();
    let pkg = fixture.0.join("vendor/own/a@1.0.0");
    fs::write(
        pkg.join("package.json"),
        r#"{"name":"a","version":"1.0.0","main":"index.js"}"#,
    )
    .unwrap();
    fs::write(pkg.join("index.js"), "require('./a.js');\n").unwrap();
    fs::write(pkg.join("a.js"), "module.exports = 1;\n").unwrap();
    fs::write(pkg.join("vuln.js"), "module.exports = 'vulnerable';\n").unwrap();
    fixture.osv(
        "2025-01-02T03:04:05Z",
        serde_json::json!([{
            "id": "GHSA-e1-fixture",
            "aliases": [],
            "affected": [{
                "package": "a",
                "versions": ["1.0.0"],
                "ranges": [],
                "database_specific": {"vulnerable_files": ["vuln.js"]},
            }],
            "severity": null,
        }]),
    );
    let first = fixture.run(&["sbom", "--format", "vex", "--e1"]);
    success(&first);
    let second = fixture.run(&["sbom", "--format", "vex", "--e1"]);
    success(&second);
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&second.stdout),
        "INV-10: two VEX runs under the same OWN_NOW must be byte-identical"
    );
    let vex = String::from_utf8_lossy(&first.stdout);
    assert!(vex.contains("evidence_level=E1"), "{vex}");
    assert!(vex.contains("reachable_set_sha256="), "{vex}");
}

#[test]
fn inv10_nonempty_vendor_verify_and_sbom_are_byte_reproducible() {
    let fixture = Fixture::new();
    let lock = read(&fixture.0, "own.lock");
    let first = fixture.run(&["verify", "--format", "json"]);
    success(&first);
    let second = fixture.run(&["verify", "--format", "json"]);
    success(&second);
    assert_eq!(first.stdout, second.stdout);
    success(&fixture.run(&["sbom", "--output", "one.json"]));
    success(&fixture.run(&["sbom", "--output", "two.json"]));
    let one = read(&fixture.0, "one.json");
    assert_eq!(one, read(&fixture.0, "two.json"));
    let sbom: serde_json::Value = serde_json::from_slice(&one).unwrap();
    assert_eq!(sbom["components"].as_array().unwrap().len(), 1);
    assert_eq!(sbom["components"][0]["purl"], "pkg:npm/a@1.0.0");
    assert_eq!(lock, read(&fixture.0, "own.lock"));
}

#[test]
fn ci_vendor_path_ignored_uses_project_relative_paths_inv1() {
    let fixture = Fixture::new();
    success(&fixture.run(&["ci"]));
    fs::write(fixture.0.join(".gitignore"), "vendor/own/a@1.0.0/LICENSE\n").unwrap();
    let out = fixture.run(&["ci", "--format", "json"]);
    assert_eq!(out.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        doc["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == "VENDOR_PATH_IGNORED"),
        "{doc}"
    );
}

#[test]
fn ci_ignored_paths_are_individual_exact_and_sorted_inv10() {
    let fixture = Fixture::new();
    let vendor = "vendor/own/a@1.0.0";
    for name in ["z.js", "café.js", "a file.js"] {
        fs::write(fixture.0.join(vendor).join(name), b"module.exports=0\n").unwrap();
    }
    fs::write(fixture.0.join(".gitignore"), "vendor/\n").unwrap();
    let first = fixture.run(&["ci", "--format", "json"]);
    assert_eq!(first.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let paths: Vec<_> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "VENDOR_PATH_IGNORED")
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "LICENSE",
            "a file.js",
            "café.js",
            "index.js",
            "package.json",
            "z.js"
        ]
        .map(|name| format!("{vendor}/{name}"))
    );
    let findings = doc["findings"].as_array().unwrap();
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
    assert!(keys.windows(2).all(|pair| pair[0] <= pair[1]));
    let second = fixture.run(&["ci", "--format", "json"]);
    assert_eq!(second.status.code(), Some(1));
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn ci_large_ignored_vendor_does_not_deadlock_inv5() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let fixture = Fixture::new();
    for i in 0..3000 {
        let name = format!("{i:04}-{}.js", "x".repeat(180));
        fs::write(fixture.0.join("vendor/own/a@1.0.0").join(name), b"x").unwrap();
    }
    fs::write(fixture.0.join(".gitignore"), "vendor/\n").unwrap();
    // A file drains own's final output without introducing a second pipe
    // deadlock in the test harness itself.
    let output_path = fixture.0.join("result.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_own"))
        .args(["ci", "--format", "json"])
        .current_dir(&fixture.0)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .stdout(Stdio::from(fs::File::create(&output_path).unwrap()))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("ci git-ignore probe deadlocked on a large ignored vendor");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_slice(&fs::read(output_path).unwrap()).unwrap();
    assert!(doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["code"] == "VENDOR_PATH_IGNORED"));
}

#[test]
fn ci_git_error_is_not_a_clean_ignore_check_inv5() {
    let fixture = Fixture::new();
    fs::remove_dir_all(fixture.0.join(".git")).unwrap();
    let out = fixture.run(&["ci"]);
    // SPEC §5: git is a prerequisite of ci and a failing git command is a
    // GIT_ERROR — never a clean "nothing ignored" result (INV-4/INV-5).
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("GIT_ERROR"), "stderr: {stderr}");
    assert!(
        stderr.contains("git init"),
        "the error must say what to do: {stderr}"
    );
}

#[test]
fn ci_git_unavailable_is_not_a_clean_ignore_check_inv5() {
    let fixture = Fixture::new();
    // A git that cannot run at all is unknown, never "nothing ignored" (INV-4).
    let out = fixture.run_env(&["ci"], &[("PATH", "/nonexistent")]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("GIT_ERROR"));
}

#[test]
fn check_json_lists_every_alert_as_a_finding() {
    let fixture = Fixture::new();
    fixture.osv(
        "2025-01-02T03:04:05Z",
        serde_json::json!([{
            "id": "GHSA-fixture-check",
            "aliases": ["CVE-2025-0001"],
            "affected": [{
                "package": "a",
                "versions": ["1.0.0"],
                "ranges": [],
                "database_specific": serde_json::Value::Null,
            }],
            "severity": null,
        }]),
    );
    let out = fixture.run(&["check", "--format", "json"]);
    assert_eq!(out.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["status"].as_str(), Some("findings"));
    let findings = doc["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("no findings array: {doc}"));
    // §8.0: the public list must carry what decides the exit code; an alert that
    // only lives in data.alerts leaves `findings` empty on a failing run.
    assert_eq!(findings.len(), 1, "expected one finding, got {doc}");
    assert_eq!(findings[0]["code"].as_str(), Some("CVE_ALERT"));
    assert_eq!(findings[0]["severity"].as_str(), Some("error"));
    assert_eq!(findings[0]["package"].as_str(), Some("a@1.0.0"));
    assert!(findings[0]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("GHSA-fixture-check"));
    assert_eq!(
        doc["data"]["alerts"].as_array().map(Vec::len),
        Some(1),
        "the detailed payload stays available"
    );
}

#[test]
fn verify_rejects_file_and_manifest_rewrite_without_lock_change_inv8() {
    let fixture = Fixture::new();
    let lock_before = read(&fixture.0, "own.lock");
    let changed = b"module.exports=2\n";
    fs::write(fixture.0.join("vendor/own/a@1.0.0/index.js"), changed).unwrap();
    let manifest_path = fixture.0.join("vendor/own/.manifests/a@1.0.0.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap()
        .replace(&sha256_hex(b"module.exports=1\n"), &sha256_hex(changed));
    fs::write(manifest_path, manifest).unwrap();
    let out = fixture.run(&["verify", "--format", "json"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a modified manifest must not bypass the lock anchor"
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["code"] == "DRIFT_MODIFIED"));
    assert_eq!(lock_before, read(&fixture.0, "own.lock"));
}

#[test]
fn ci_base_ref_json_keeps_change_notes_inside_envelope_inv10() {
    let fixture = Fixture::new();
    for args in [
        vec!["add", "own.lock", "own.toml"],
        vec![
            "-c",
            "user.name=own-test",
            "-c",
            "user.email=own-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ],
    ] {
        let out = Command::new("git")
            .args(args)
            .current_dir(&fixture.0)
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        success(&out);
    }
    let mut config = fs::read_to_string(fixture.0.join("own.toml")).unwrap();
    config.push_str("\n# reviewed change\n");
    fs::write(fixture.0.join("own.toml"), config).unwrap();
    let out = fixture.run(&["ci", "--base-ref", "HEAD", "--format", "json"]);
    success(&out);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("stdout must be one JSON document, not notes followed by JSON");
    let notes = doc["data"]["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 1);
    assert!(notes[0].as_str().unwrap().contains("own.toml"));
}

#[test]
fn check_rejects_osv_local_paths_outside_project_inv5() {
    let fixture = Fixture::new();
    fixture.osv("2025-01-02T03:04:05Z", serde_json::json!([]));
    let absolute = fixture
        .0
        .join(".own/osv.json")
        .to_string_lossy()
        .into_owned();
    for path in ["", "..", "../snapshot.json", absolute.as_str()] {
        let mut config: toml::Value = toml::from_str(DEFAULT_OWN_TOML).unwrap();
        config["osv"]["local_path"] = toml::Value::String(path.into());
        fs::write(
            fixture.0.join("own.toml"),
            toml::to_string(&config).unwrap(),
        )
        .unwrap();
        let out = fixture.run(&["check"]);
        assert_eq!(out.status.code(), Some(2), "{path}: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("PARSE_ERROR"),
            "{out:?}"
        );
    }
}

#[test]
fn check_rejects_malformed_advisories_in_osv_snapshot_inv5() {
    let fixture = Fixture::new();
    for advisory in [
        serde_json::json!(null),
        serde_json::json!({"id": "fixture", "affected": null}),
        serde_json::json!({"id": "fixture", "aliases": [3], "affected": []}),
        serde_json::json!({"id": "fixture", "affected": [{"package": {"name": "a"}}]}),
        serde_json::json!({"id": "fixture", "affected": [{"package": "a", "versions": [3]}]}),
        serde_json::json!({"id": "fixture", "affected": [{"package": "a", "ranges": [{"type": "SEMVER", "events": [{"introduced": false}]}]}]}),
    ] {
        fixture.osv("2025-01-02T03:04:05Z", serde_json::json!([advisory]));
        let out = fixture.run(&["check"]);
        assert_eq!(out.status.code(), Some(2), "{advisory}: {out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("PARSE_ERROR"));
    }
}

#[test]
fn check_and_vex_osv_environment_overrides_config_inv5() {
    let fixture = Fixture::new();
    fixture.osv("2024-12-28T03:04:05Z", serde_json::json!([]));
    let config = DEFAULT_OWN_TOML
        .replace("max_age_days = 7", "max_age_days = 1")
        .replace(
            "local_path = \".own/osv.json\"",
            "local_path = \"cache/missing.json\"",
        );
    fs::write(fixture.0.join("own.toml"), config).unwrap();
    let env = [
        ("OWN_OSV_LOCAL_PATH", ".own/osv.json"),
        ("OWN_OSV_MAX_AGE_DAYS", "10"),
    ];
    for args in [vec!["check"], vec!["sbom", "--format", "vex"]] {
        success(&fixture.run_env(&args, &env));
    }
    let invalid = [
        ("OWN_OSV_LOCAL_PATH", ".own/osv.json"),
        ("OWN_OSV_MAX_AGE_DAYS", "invalid"),
    ];
    let out = fixture.run_env(&["check"], &invalid);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("PARSE_ERROR"));
}

#[test]
fn check_expired_osv_ignore_warns_without_suppressing_alert_inv5() {
    let fixture = Fixture::new();
    fixture.osv(
        "2025-01-02T03:04:05Z",
        serde_json::json!([{
            "id": "GHSA-fixture-a", "aliases": [],
            "affected": [{"package": "a", "ranges": [], "versions": ["1.0.0"]}],
            "severity": null,
        }]),
    );
    let config = DEFAULT_OWN_TOML.replace(
        "ignore = []",
        r#"ignore = [{ id = "GHSA-fixture-a", reason = "fixture", expires = "2025-01-01" }]"#,
    );
    fs::write(fixture.0.join("own.toml"), config).unwrap();
    let out = fixture.run(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("CVE_ALERT"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("W_IGNORE_EXPIRED"),
        "{out:?}"
    );
    let vex = fixture.run(&["sbom", "--format", "vex"]);
    success(&vex);
    assert!(String::from_utf8_lossy(&vex.stderr).contains("W_IGNORE_EXPIRED"));
    let doc: serde_json::Value = serde_json::from_slice(&vex.stdout).unwrap();
    assert_eq!(doc["statements"][0]["status"], "under_investigation");
}

#[test]
fn check_rejects_invalid_osv_ignore_policy_inv5() {
    let fixture = Fixture::new();
    fixture.osv("2025-01-02T03:04:05Z", serde_json::json!([]));
    for entry in [
        r#"{ id = "GHSA-fixture-a", expires = "2025-01-02" }"#,
        r#"{ id = "GHSA-fixture-a", reason = "", expires = "2025-01-02" }"#,
        r#"{ id = "", reason = "fixture", expires = "2025-01-02" }"#,
        r#"{ id = "GHSA-fixture-a", reason = "fixture", expires = "2025-02-30" }"#,
        r#"{ id = "GHSA-fixture-a", reason = 1, expires = "2025-01-02" }"#,
    ] {
        let config = DEFAULT_OWN_TOML.replace("ignore = []", &format!("ignore = [{entry}]"));
        fs::write(fixture.0.join("own.toml"), config).unwrap();
        let out = fixture.run(&["check"]);
        assert_eq!(out.status.code(), Some(2), "{entry}: {out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("PARSE_ERROR"));
    }
}

#[test]
fn check_honors_osv_ignore_by_id_or_alias_inv5() {
    let fixture = Fixture::new();
    fixture.osv(
        "2025-01-02T03:04:05Z",
        serde_json::json!([{
            "id": "GHSA-fixture-a", "aliases": ["CVE-2000-0001"],
            "affected": [{"package": "a", "ranges": [], "versions": ["1.0.0"]}],
            "severity": null,
        }]),
    );
    for id in ["GHSA-fixture-a", "CVE-2000-0001"] {
        let config = DEFAULT_OWN_TOML.replace("ignore = []", &format!(
            "ignore = [{{ id = \"{id}\", reason = \"fixture exception\", expires = \"2025-01-02\" }}]"
        ));
        fs::write(fixture.0.join("own.toml"), config).unwrap();
        success(&fixture.run(&["check"]));
        let vex = fixture.run(&["sbom", "--format", "vex"]);
        success(&vex);
        let doc: serde_json::Value = serde_json::from_slice(&vex.stdout).unwrap();
        assert_eq!(doc["statements"], serde_json::json!([]));
    }
}

#[test]
fn check_stale_override_keeps_explicit_warning_inv5() {
    let fixture = Fixture::new();
    fixture.osv("2024-01-01T00:00:00Z", serde_json::json!([]));
    let out = fixture.run(&["check", "--allow-stale-osv"]);
    success(&out);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("W_OSV_STALE"),
        "{out:?}"
    );
}

#[test]
fn check_and_vex_use_configured_osv_max_age_days_inv5() {
    let fixture = Fixture::new();
    fixture.osv("2024-12-28T03:04:05Z", serde_json::json!([]));
    for (max_age_days, expected) in [(1, 2), (10, 0)] {
        let config = DEFAULT_OWN_TOML.replace(
            "max_age_days = 7",
            &format!("max_age_days = {max_age_days}"),
        );
        fs::write(fixture.0.join("own.toml"), config).unwrap();
        for args in [vec!["check"], vec!["sbom", "--format", "vex"]] {
            let out = fixture.run(&args);
            assert_eq!(out.status.code(), Some(expected), "{args:?}: {out:?}");
            if expected == 2 {
                assert!(String::from_utf8_lossy(&out.stderr).contains("OSV_STALE"));
            }
        }
    }
}

#[test]
fn check_and_vex_use_configured_osv_local_path_inv5() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.0.join("cache")).unwrap();
    fs::write(
        fixture.0.join("cache/osv.json"),
        serde_json::json!({
            "schema_version": 1, "generated_at": "2025-01-02T03:04:05Z",
            "source": "https://example.invalid/npm/all.zip", "source_last_modified": null,
            "covered_packages": ["a"], "advisories": [],
        })
        .to_string(),
    )
    .unwrap();
    let config = DEFAULT_OWN_TOML.replace(
        "local_path = \".own/osv.json\"",
        "local_path = \"cache/osv.json\"",
    );
    fs::write(fixture.0.join("own.toml"), config).unwrap();
    success(&fixture.run(&["check"]));
    let vex = fixture.run(&["sbom", "--format", "vex"]);
    success(&vex);
    let doc: serde_json::Value = serde_json::from_slice(&vex.stdout).unwrap();
    assert_eq!(doc["statements"], serde_json::json!([]));
    assert!(!fixture.0.join(".own/osv.json").exists());
}

#[test]
fn check_rejects_malformed_osv_snapshot_inv5() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.0.join(".own")).unwrap();
    let valid = serde_json::json!({
        "schema_version": 1,
        "generated_at": "2025-01-02T03:04:05Z",
        "source": "https://example.invalid/npm/all.zip",
        "source_last_modified": null,
        "covered_packages": ["a"],
        "advisories": [],
    });
    for (key, value) in [
        ("schema_version", serde_json::json!(2)),
        ("advisories", serde_json::json!({})),
        ("generated_at", serde_json::json!("")),
        ("generated_at", serde_json::json!("x")),
        ("covered_packages", serde_json::json!(["a", 3])),
    ] {
        let mut snapshot = valid.clone();
        snapshot[key] = value;
        fs::write(fixture.0.join(".own/osv.json"), snapshot.to_string()).unwrap();
        let out = fixture.run(&["check"]);
        assert_eq!(out.status.code(), Some(2), "{key}: {snapshot}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("PARSE_ERROR"),
            "{key}: {:?}",
            out
        );
    }
}

#[test]
fn vex_missing_snapshot_cannot_publish_an_empty_report_inv5() {
    let fixture = Fixture::new();
    let out = fixture.run(&["sbom", "--format", "vex", "--output", "vex.json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("OSV_MISSING"));
    assert!(!fixture.0.join("vex.json").exists());
    assert!(out.stdout.is_empty());
}

#[test]
fn check_osv_age_uses_system_clock_without_own_now_inv5() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.0.join(".own")).unwrap();
    fs::write(
        fixture.0.join(".own/osv.json"),
        serde_json::json!({
            "schema_version": 1, "generated_at": "1970-01-01T00:00:00Z",
            "source": "https://example.invalid/npm/all.zip", "source_last_modified": null,
            "covered_packages": ["a"], "advisories": [],
        })
        .to_string(),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_own"))
        .arg("check")
        .current_dir(&fixture.0)
        .env_remove("OWN_NOW")
        .env_remove("SOURCE_DATE_EPOCH")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("OSV_STALE"));
}

#[test]
fn check_osv_age_uses_elapsed_seconds_across_years_inv5() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.0.join(".own")).unwrap();
    for (generated_at, expected) in [
        ("2024-12-28T03:04:05Z", 0),
        ("2024-12-26T03:04:05Z", 0),
        ("2024-12-26T03:04:04Z", 2),
    ] {
        let doc = serde_json::json!({
            "schema_version": 1, "generated_at": generated_at,
            "source": "https://example.invalid/npm/all.zip", "source_last_modified": null,
            "covered_packages": ["a"], "advisories": [],
        });
        fs::write(fixture.0.join(".own/osv.json"), doc.to_string()).unwrap();
        let out = fixture.run(&["check"]);
        assert_eq!(
            out.status.code(),
            Some(expected),
            "{generated_at}: {:?}",
            out
        );
        if expected == 2 {
            assert!(String::from_utf8_lossy(&out.stderr).contains("OSV_STALE"));
        }
    }
}
