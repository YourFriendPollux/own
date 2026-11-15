//! Malformed snapshots must fail closed, never yield a clean check.
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
            "own-osv-guards-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join(".own")).unwrap();
        fs::write(root.join("own.toml"), DEFAULT_OWN_TOML).unwrap();
        fs::write(
            root.join("own.lock"),
            write_lock_canonical(&empty_lock("0.1.0", "1", &serde_json::Map::new())),
        )
        .unwrap();
        Self(root)
    }
    fn set_version(&self, version: &str) {
        let mut lock = empty_lock("0.1.0", "1", &serde_json::Map::new());
        // Synthetic package: check only consumes name/version, no vendor IO.
        lock.packages.push(
            serde_json::from_value(json!({
                "name": "fakepkg", "ecosystem": "npm", "version": version,
                "dir": "vendor/own/fakepkg", "registry": "https://registry.npmjs.org",
                "integrity": "sha512-AAAA", "tarball_sha256": "sha256:0000",
                "version_manifest_sha256": "sha256:0001", "provenance_level": "integrity-only",
                "mode": "verbatim", "roots": ["."], "dependents": ["importer:."],
                "license_expression": "MIT", "license_policy": "allow", "license_files": [],
                "package_files_sha256": "sha256:0002", "file_count": 0, "total_size": 0
            }))
            .unwrap(),
        );
        fs::write(self.0.join("own.lock"), write_lock_canonical(&lock)).unwrap();
    }
    fn assert_events(&self, events: Value, cases: &[(&str, bool)]) {
        for (version, expected) in cases {
            self.set_version(version);
            let out = self.check(
                json!({"package": "fakepkg", "ranges": [{"type": "SEMVER", "events": events}]}),
            );
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(
                out.status.code(),
                Some(i32::from(*expected)),
                "synthetic {version} {events}: {stdout} {stderr}"
            );
            let envelope: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(
                envelope["data"]["alerts"].as_array().unwrap().len(),
                usize::from(*expected),
                "synthetic {version}: {stdout}"
            );
        }
    }
    fn check(&self, affected: Value) -> Output {
        self.check_records(vec![affected], &[])
    }
    fn check_records(&self, affected: Vec<Value>, flags: &[&str]) -> Output {
        fs::write(
            self.0.join(".own/osv.json"),
            json!({
                "schema_version": 1,
                "generated_at": "2025-01-02T03:04:05Z",
                "source": "https://example.invalid/npm/all.zip",
                "source_last_modified": null,
                "covered_packages": ["fakepkg"],
                "advisories": [{"id": "SYNTHETIC-malformed", "affected": affected}]
            })
            .to_string(),
        )
        .unwrap();
        Command::new(env!("CARGO_BIN_EXE_own"))
            .args(["check", "--format", "json"])
            .args(flags)
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
fn refused(out: Output, context: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{context}: {stdout} {stderr}");
    assert!(
        stdout.contains("PARSE_ERROR") || stderr.contains("PARSE_ERROR"),
        "{context}: {stdout} {stderr}"
    );
}

#[test]
fn synthetic_binding_e1_uses_only_the_affected_record_that_hit() {
    assert_record_binding("--e1", "E1");
}

#[test]
fn synthetic_binding_e2_uses_only_the_affected_record_that_hit() {
    assert_record_binding("--e2", "E2");
}

fn assert_record_binding(flag: &str, proof: &str) {
    // Synthetic packages and hints; E2 executes only this harmless local JS.
    let fixture = Fixture::new();
    fixture.set_version("1.0.0");
    let dir = fixture.0.join("vendor/own/fakepkg");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{"name":"fakepkg","main":"index.js"}"#,
    )
    .unwrap();
    fs::write(dir.join("index.js"), "module.exports = 1;\n").unwrap();
    fs::write(dir.join("unused.js"), "module.exports = 2;\n").unwrap();
    for (records, expected) in [
        (
            vec![
                json!({"package":"fakepkg", "versions":["1.0.0"]}),
                json!({"package":"neighbor", "versions":["1.0.0"], "database_specific":{"vulnerable_files":["unused.js"]}}),
            ],
            "E0",
        ),
        (
            vec![
                json!({"package":"fakepkg", "versions":["1.0.0"]}),
                json!({"package":"fakepkg", "versions":["2.0.0"], "database_specific":{"vulnerable_files":["unused.js"]}}),
            ],
            "E0",
        ),
        (
            vec![
                json!({"package":"fakepkg", "versions":["1.0.0"], "database_specific":{"vulnerable_files":["unused.js"]}}),
                json!({"package":"neighbor", "versions":["1.0.0"], "database_specific":{"vulnerable_files":["index.js"]}}),
            ],
            proof,
        ),
    ] {
        let out = fixture.check_records(records, &[flag]);
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{flag}: {e}: {} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        let alerts = doc["data"]["alerts"].as_array().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(
            alerts[0]["evidence_level"], expected,
            "synthetic {flag}: {doc}"
        );
    }
}

#[test]
fn invalid_osv_boundaries_are_refused_before_evaluation() {
    let fixture = Fixture::new();
    fixture.set_version("1.0.0");
    for kind in ["SEMVER", "ECOSYSTEM"] {
        for key in ["introduced", "fixed", "last_affected", "limit"] {
            let events = if key == "introduced" {
                json!([{key: "not-a-version"}])
            } else {
                json!([{"introduced": "0"}, {key: "not-a-version"}])
            };
            let out = fixture.check(json!({
                "package": "fakepkg", "versions": [],
                "ranges": [{"type": kind, "events": events}]
            }));
            if kind == "SEMVER" {
                refused(out, &format!("{kind} {key}"));
            } else {
                // An opaque ECOSYSTEM string is schema-valid, not SEMVER.
                assert!(!out.status.success());
                assert!(String::from_utf8_lossy(&out.stderr).contains("OSV_UNEVALUABLE"));
            }
        }
    }
}

#[test]
fn synthetic_calendar_bounds_are_evaluated_without_relaxing_semver() {
    let fixture = Fixture::new();
    let events = json!([{"introduced": "2026.03.1"}, {"fixed": "2026.04.1"}]);
    for (version, expected) in [("2026.4.0", 1), ("2026.4.1", 0)] {
        fixture.set_version(version);
        let out = fixture.check(json!({"package": "fakepkg", "ranges": [
            {"type": "ECOSYSTEM", "events": events}
        ]}));
        assert_eq!(
            out.status.code(),
            Some(expected),
            "{} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if expected == 1 {
            let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(
                doc["data"]["alerts"][0]["fixed_versions"],
                json!(["2026.04.1"])
            );
        }
    }
    refused(
        fixture.check(json!({"package": "fakepkg", "ranges": [
            {"type": "SEMVER", "events": events}
        ]})),
        "synthetic non-SEMVER calendar bound in a SEMVER range",
    );
}

#[test]
fn synthetic_numeric_version_lists_match_points_not_wildcards() {
    let fixture = Fixture::new();
    for (version, expected) in [
        ("12.0.0", 1),
        ("12.0.1", 0),
        ("12.1.0", 0),
        ("2026.4.1", 1),
        ("2026.4.0", 0),
        ("2026.4.2", 0),
    ] {
        fixture.set_version(version);
        let out = fixture.check(json!({"package": "fakepkg", "versions": ["12.0", "2026.04.1"]}));
        assert_eq!(
            out.status.code(),
            Some(expected),
            "{version}: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn synthetic_unevaluable_records_never_produce_a_clean_check() {
    let fixture = Fixture::new();
    fixture.set_version("1.0.0");
    for range in [
        json!({"type": "GIT", "repo": "https://example.invalid/repo", "events": [
            {"introduced": "0"}, {"fixed": "a".repeat(40)}
        ]}),
        json!({"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "release-two"}]}),
    ] {
        let out =
            fixture.check(json!({"package": "fakepkg", "ranges": [range], "versions": ["0.9.0"]}));
        assert!(
            !out.status.success(),
            "{} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("OSV_UNEVALUABLE"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // A positive explicit version remains a sufficient OR witness even
        // when the companion range cannot be evaluated without its repository.
        let out =
            fixture.check(json!({"package": "fakepkg", "ranges": [range], "versions": ["1.0.0"]}));
        assert_eq!(
            out.status.code(),
            Some(1),
            "{} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(doc["data"]["alerts"][0]["evidence_level"], "E0");
        assert!(doc["data"]["alerts"][0]["fixed_versions"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}

#[test]
fn late_osv_ranges_require_an_introduced_event() {
    // Synthetic snapshots, not claims about a public advisory.
    let fixture = Fixture::new();
    for kind in ["SEMVER", "ECOSYSTEM"] {
        for events in [
            json!([{ "fixed": "2.0.0" }]),
            json!([{ "last_affected": "2.0.0" }]),
            json!([{ "limit": "2.0.0" }]),
            json!([]),
        ] {
            refused(
                fixture.check(
                    json!({"package": "fakepkg", "ranges": [{"type": kind, "events": events}]}),
                ),
                &format!("synthetic {kind}: {events}"),
            );
        }
    }
}

#[test]
fn late_osv_fixed_and_last_affected_cannot_share_a_range() {
    let fixture = Fixture::new();
    refused(
        fixture.check(
            json!({"package": "fakepkg", "ranges": [{"type": "SEMVER", "events": [
                {"introduced": "0"}, {"fixed": "2.0.0"}, {"last_affected": "3.0.0"}
            ]}]}),
        ),
        "synthetic mixed closing types",
    );
}

#[test]
fn late_osv_unsorted_events_are_evaluated_by_version() {
    Fixture::new().assert_events(
        json!([{"fixed": "2.0.0"}, {"introduced": "1.0.0"}]),
        &[
            ("2.0.0", false),
            ("0.9.9", false),
            ("1.0.0", true),
            ("1.9.9", true),
        ],
    );
}

#[test]
fn late_osv_repeated_introductions_do_not_erase_an_active_status() {
    Fixture::new().assert_events(
        json!([{"introduced": "1.0.0"}, {"introduced": "3.0.0"}]),
        &[("1.5.0", true), ("0.9.9", false), ("3.0.0", true)],
    );
}

#[test]
fn late_osv_limits_are_or_constraints_independent_of_status_events() {
    let fixture = Fixture::new();
    fixture.assert_events(
        json!([{"introduced": "0"}, {"fixed": "1.0.0"}, {"limit": "2.0.0"}, {"introduced": "3.0.0"}]),
        &[("3.5.0", false), ("0.9.9", true), ("1.0.0", false), ("2.0.0", false)],
    );
    fixture.assert_events(
        json!([{"introduced": "0"}, {"limit": "2.0.0"}, {"limit": "4.0.0"}]),
        &[("3.0.0", true), ("2.0.0", true), ("4.0.0", false)],
    );
}

#[test]
fn late_osv_infinite_limits_are_valid_and_do_not_close_status() {
    let fixture = Fixture::new();
    for limit in ["*", "1.*"] {
        fixture.assert_events(
            json!([{"introduced": "0"}, {"limit": "1.0.0"}, {"limit": limit}]),
            &[("0.0.0-alpha", true), ("9.0.0", true)],
        );
        fixture.assert_events(
            json!([{"limit": limit}, {"fixed": "2.0.0"}, {"introduced": "0"}]),
            &[("2.0.0", false), ("1.9.9", true)],
        );
    }
}

#[test]
fn late_osv_valid_neighboring_timelines_and_constraints() {
    let fixture = Fixture::new();
    fixture.assert_events(
        json!([{"last_affected": "2.0.0"}, {"introduced": "1.0.0"}]),
        &[
            ("0.9.9", false),
            ("1.0.0", true),
            ("2.0.0", true),
            ("2.0.1", false),
        ],
    );
    fixture.assert_events(
        json!([{"fixed": "4.0.0"}, {"introduced": "3.0.0"}, {"fixed": "2.0.0"}, {"introduced": "1.0.0"}]),
        &[("1.0.0", true), ("2.0.0", false), ("2.5.0", false), ("3.0.0", true), ("4.0.0", false)],
    );
    fixture.assert_events(
        json!([{"introduced": "0"}, {"fixed": "0.0.0"}]),
        &[("0.0.0-alpha", true), ("0.0.0", false)],
    );
    fixture.set_version("13.5.0");
    let out = fixture.check(json!({"package": "fakepkg", "ranges": [
        {"type": "ECOSYSTEM", "events": [{"fixed": "14.2.30"}, {"introduced": "13.0"}]}
    ]}));
    assert_eq!(
        out.status.code(),
        Some(1),
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // fixed and last_affected may coexist in separate ranges. Explicit versions
    // also match independently from a range's finite limit.
    fixture.set_version("1.0.0");
    let out = fixture.check(json!({"package": "fakepkg", "versions": ["1.0.0"], "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.5.0"}, {"limit": "0.9.0"}]},
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "0.5.0"}]}
    ]}));
    assert_eq!(
        out.status.code(),
        Some(1),
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for affected in [
        json!({"package": "fakepkg", "versions": ["1.0.0"]}),
        json!({"package": "fakepkg", "ranges": [], "versions": []}),
    ] {
        let out = fixture.check(affected.clone());
        assert_eq!(
            out.status.code(),
            Some(if affected["versions"].as_array().unwrap().is_empty() {
                0
            } else {
                1
            }),
            "{} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for key in ["introduced", "fixed", "last_affected"] {
        refused(fixture.check(json!({"package": "fakepkg", "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {key: "*"}]}]})), "synthetic star is only a limit");
    }
    refused(fixture.check(json!({"package": "fakepkg", "ranges": [{"type": "SEMVER", "events": [{"introduced": "0", "fixed": "2.0.0"}]}]})), "synthetic event has multiple keys");
}

#[test]
fn git_ranges_are_refused_instead_of_evaluated_as_semver() {
    let fixture = Fixture::new();
    refused(
        fixture.check(json!({
            "package": "fakepkg", "versions": [],
            "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]
        })),
        "unsupported GIT range",
    );
}

#[test]
fn malformed_range_and_version_types_are_refused() {
    let fixture = Fixture::new();
    for affected in [
        json!({"package": "fakepkg", "versions": [123]}),
        json!({"package": "fakepkg", "ranges": {}}),
        json!({"package": "fakepkg", "ranges": [{"type": 123, "events": [{"introduced": "0"}]}]}),
        json!({"package": "fakepkg", "ranges": [{"type": "SEMVER", "events": [{"introduced": 123}]}]}),
        json!({"package": "fakepkg", "ranges": [{"type": "UNKNOWN", "events": [{"introduced": "0"}]}]}),
    ] {
        refused(fixture.check(affected.clone()), &affected.to_string());
    }
}

#[test]
fn malformed_semver_tokens_are_refused_in_boundaries_and_version_lists() {
    let fixture = Fixture::new();
    for version in [
        "not-a-version",
        "1.0.0-!",
        "1.0.0-beta..1",
        "1.0.0+",
        "1.0.0.0",
    ] {
        for affected in [
            json!({"package": "fakepkg", "versions": [version]}),
            json!({"package": "fakepkg", "ranges": [{"type": "SEMVER", "events": [{"introduced": version}]}]}),
        ] {
            refused(fixture.check(affected.clone()), &affected.to_string());
        }
    }
    // Legacy numeric tokens are allowed only as ecosystem versions/bounds;
    // their presence does not widen the strict SEMVER range grammar.
    for version in ["01.0.0", "2026.04.1", "12.0"] {
        refused(
            fixture.check(json!({"package": "fakepkg", "ranges": [
                {"type": "SEMVER", "events": [{"introduced": version}]}
            ]})),
            "synthetic noncanonical SEMVER event",
        );
    }
}

#[test]
fn valid_semver_sentinel_prerelease_and_build_metadata_are_preserved() {
    let fixture = Fixture::new();
    let out = fixture.check(json!({
        "package": "fakepkg", "versions": ["1.0.0", "2.0.0-beta.1+build.23"],
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0-beta.1+build.23"}]}]
    }));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
