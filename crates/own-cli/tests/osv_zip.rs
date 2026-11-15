//! Exercise the ZIP reader used by OSV after dependency upgrades, offline.
use std::io::{Cursor, Read, Write};

const DEFAULT_OSV_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

// Compile the actual collector, not a second implementation of its guards.
#[allow(dead_code)]
#[path = "../src/osv.rs"]
mod osv;
#[allow(dead_code)]
#[path = "../src/sbom.rs"]
mod sbom;

#[allow(dead_code)]
#[path = "../src/project_config.rs"]
mod project_config;

// Synthetic filesystem/lock fixtures. Only explicitly ignored live tests below
// use a genuine upstream archive; no test substitutes an HTTP response.
struct FetchFixture(std::path::PathBuf);
impl FetchFixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "own-osv-fetch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join(".own")).unwrap();
        std::fs::write(root.join("own.toml"), own_core::config::DEFAULT_OWN_TOML).unwrap();
        let lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        std::fs::write(
            root.join("own.lock"),
            own_core::canonical::write_lock_canonical(&lock),
        )
        .unwrap();
        Self(root)
    }
    fn path(&self, rel: &str) {
        std::fs::write(
            self.0.join("own.toml"),
            own_core::config::DEFAULT_OWN_TOML.replace(
                "local_path = \".own/osv.json\"",
                &format!("local_path = {rel:?}"),
            ),
        )
        .unwrap();
    }
    fn offline_refusal(&self) -> Result<u8, String> {
        osv::osv_fetch(
            &self.0,
            "http://example.invalid/npm.zip",
            1,
            Some("2025-01-02T03:04:05Z"),
        )
    }
}
impl Drop for FetchFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn synthetic_fetch_sensitive_outputs_are_refused_before_network() {
    let fixture = FetchFixture::new();
    for rel in [
        "own.lock",
        "own.toml",
        "package.json",
        "pnpm-lock.yaml",
        ".own/lock",
        ".own/tmp/osv.json",
        ".own/txn/journal.json",
        ".git/config",
        "vendor/own/a/package.json",
        ".own/cache/abc.tgz",
    ] {
        fixture.path(rel);
        let error = fixture.offline_refusal().unwrap_err();
        assert!(
            error.contains("OSV_OUTPUT_REFUSED:sensitive"),
            "synthetic {rel}: {error}"
        );
    }
}

#[test]
fn synthetic_fetch_non_regular_output_is_refused_before_network() {
    let fixture = FetchFixture::new();
    std::fs::create_dir(fixture.0.join("cache-dir")).unwrap();
    fixture.path("cache-dir");
    let error = fixture.offline_refusal().unwrap_err();
    assert!(error.contains("OSV_OUTPUT_REFUSED:not_file"), "{error}");
}

#[cfg(unix)]
#[test]
fn synthetic_fetch_symlink_output_is_refused_before_network() {
    let fixture = FetchFixture::new();
    std::fs::write(fixture.0.join("sentinel"), "synthetic-original").unwrap();
    std::os::unix::fs::symlink(fixture.0.join("sentinel"), fixture.0.join(".own/osv.json"))
        .unwrap();
    let error = fixture.offline_refusal().unwrap_err();
    assert!(error.contains("OSV_OUTPUT_REFUSED:path"), "{error}");
    assert_eq!(
        std::fs::read(fixture.0.join("sentinel")).unwrap(),
        b"synthetic-original"
    );
}

#[cfg(unix)]
#[test]
fn synthetic_fetch_symlink_parent_is_refused_before_network() {
    let fixture = FetchFixture::new();
    std::fs::create_dir(fixture.0.join("outside")).unwrap();
    std::os::unix::fs::symlink(fixture.0.join("outside"), fixture.0.join("cache-link")).unwrap();
    fixture.path("cache-link/osv.json");
    let error = fixture.offline_refusal().unwrap_err();
    assert!(error.contains("OSV_OUTPUT_REFUSED:path"), "{error}");
    assert!(!fixture.0.join("outside/osv.json").exists());
}

#[cfg(unix)]
#[test]
fn synthetic_fetch_symlink_input_is_refused_before_network() {
    let fixture = FetchFixture::new();
    std::fs::rename(fixture.0.join("own.lock"), fixture.0.join("saved-lock")).unwrap();
    std::os::unix::fs::symlink(fixture.0.join("saved-lock"), fixture.0.join("own.lock")).unwrap();
    let error = fixture.offline_refusal().unwrap_err();
    assert!(error.contains("OSV_INPUT_REFUSED:own.lock"), "{error}");
}

#[cfg(unix)]
#[test]
fn synthetic_fetch_takes_the_exclusive_lock_before_network() {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    let fixture = FetchFixture::new();
    // A separate process is essential: POSIX record locks are process-owned.
    let mut holder = Command::new("python3").args(["-c", "import fcntl,sys; f=open(sys.argv[1],'w'); fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('LOCKED',flush=True); sys.stdin.read()"])
        .arg(fixture.0.join(".own/lock")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut ready = String::new();
    std::io::BufReader::new(holder.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "LOCKED");
    let result = fixture.offline_refusal();
    // The project entry must take the lock before even a malformed config can
    // be read. This shares the previously witnessed lock-order regression.
    std::fs::write(fixture.0.join("own.toml"), "[net]\nconnect_timeout_s = 0\n").unwrap();
    let project_result = osv::osv_fetch_project(&fixture.0, Some("2025-01-02T03:04:05Z"));
    drop(holder.stdin.take());
    assert!(holder.wait().unwrap().success());
    assert_eq!(result.unwrap_err(), "LOCK_BUSY");
    assert_eq!(project_result.unwrap_err(), "LOCK_BUSY");
    assert!(!fixture.0.join(".own/osv.json").exists());
}

#[test]
fn synthetic_fetch_recovers_an_interrupted_snapshot_before_failed_network() {
    let fixture = FetchFixture::new();
    let root = std::fs::canonicalize(&fixture.0).unwrap();
    let journal_dir = root.join(".own/txn/synthetic-interruption");
    std::fs::create_dir_all(journal_dir.join("backup")).unwrap();
    std::fs::write(
        journal_dir.join("backup/snapshot-original"),
        "synthetic-original",
    )
    .unwrap();
    std::fs::write(root.join(".own/osv.json"), "synthetic-interrupted").unwrap();
    std::fs::write(journal_dir.join("journal.json"), serde_json::json!({
        "root":root, "id":"synthetic-interruption", "state":"started",
        "backup_files":[{"rel":".own/osv.json", "flat":"snapshot-original", "existed":true}], "created_dirs":[]
    }).to_string()).unwrap();
    assert!(fixture.offline_refusal().is_err());
    assert_eq!(
        std::fs::read(root.join(".own/osv.json")).unwrap(),
        b"synthetic-original"
    );
    assert_eq!(std::fs::read_dir(root.join(".own/txn")).unwrap().count(), 0);
}

#[test]
fn synthetic_fetch_uses_validated_project_network_settings() {
    let fixture = FetchFixture::new();
    std::fs::write(
        fixture.0.join("own.toml"),
        own_core::config::DEFAULT_OWN_TOML
            .replace("connect_timeout_s = 10", "connect_timeout_s = 0"),
    )
    .unwrap();
    let error = fixture.offline_refusal().unwrap_err();
    assert!(
        error.starts_with("PARSE_ERROR") && error.contains("connect_timeout_s"),
        "{error}"
    );
}

fn collect(
    raw: serde_json::Value,
    method: zip::CompressionMethod,
) -> Result<Vec<serde_json::Value>, String> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "SYNTHETIC-1.json",
            zip::write::SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
    writer.write_all(raw.to_string().as_bytes()).unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    let package = "a".to_string();
    osv::collect_advisories(&bytes, &[&package].into_iter().collect())
}

#[test]
fn oversized_osv_advisories_are_refused_not_silently_skipped() {
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let error = collect(
            serde_json::json!({
                "id": "SYNTHETIC-large",
                "details": "x".repeat(5 * 1_048_576),
                "affected": [{"package": {"ecosystem": "npm", "name": "a"}, "versions": ["1.0.0"]}]
            }),
            method,
        )
        .expect_err("a capped record must not disappear from a complete snapshot");
        assert!(error.contains("cap"), "{error}");
    }
}

#[test]
fn synthetic_osv_calendar_bounds_are_retained_without_rewriting() {
    let events = serde_json::json!([
        {"introduced": "2026.03.1"}, {"fixed": "2026.04.1"}
    ]);
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let kept = collect(
            serde_json::json!({"id": "SYNTHETIC-calendar", "affected": [{
                "package": {"ecosystem": "npm", "name": "a"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}]
            }]}),
            method,
        )
        .expect("numeric ECOSYSTEM bounds must survive the actual collector");
        assert_eq!(kept[0]["affected"][0]["ranges"][0]["events"], events);
    }
}

#[test]
fn synthetic_numeric_version_lists_keep_partial_and_calendar_tokens() {
    let versions = serde_json::json!(["12.0", "2026.04.1"]);
    let kept = collect(
        serde_json::json!({"id": "SYNTHETIC-legacy-versions", "affected": [{
            "package": {"ecosystem": "npm", "name": "a"}, "versions": versions
        }]}),
        zip::CompressionMethod::Deflated,
    )
    .expect("ecosystem versions need not be strict SEMVER tokens");
    assert_eq!(kept[0]["affected"][0]["versions"], versions);
}

#[test]
fn synthetic_valid_git_npm_ranges_and_tags_are_retained() {
    let range = serde_json::json!({"type": "GIT", "repo": "https://example.invalid/repo",
        "events": [{"introduced": "0"}, {"fixed": "a".repeat(40)}]});
    let kept = collect(
        serde_json::json!({"id": "SYNTHETIC-npm-git", "affected": [{
            "package": {"ecosystem": "npm", "name": "a"},
            "ranges": [range], "versions": ["release-one", "1.0.0"]
        }]}),
        zip::CompressionMethod::Deflated,
    )
    .expect("valid GIT ranges must not invalidate the complete npm dump");
    assert_eq!(kept[0]["affected"][0]["ranges"][0], range);
    assert_eq!(
        kept[0]["affected"][0]["versions"],
        serde_json::json!(["release-one", "1.0.0"])
    );
}

#[test]
fn synthetic_non_numeric_ecosystem_bounds_are_preserved_as_unevaluable() {
    let range = serde_json::json!({"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "release-two"}
    ]});
    let kept = collect(
        serde_json::json!({"id": "SYNTHETIC-opaque-bound", "affected": [{
            "package": {"ecosystem": "npm", "name": "a"}, "ranges": [range]
        }]}),
        zip::CompressionMethod::Deflated,
    )
    .expect("ECOSYSTEM bounds are strings, not necessarily SEMVER");
    assert_eq!(kept[0]["affected"][0]["ranges"][0], range);
}

#[test]
fn synthetic_raw_non_object_affected_is_refused() {
    let error = collect(
        serde_json::json!({"id":"SYNTHETIC-record-type", "affected":[null]}),
        zip::CompressionMethod::Deflated,
    )
    .unwrap_err();
    assert!(error.starts_with("PARSE_ERROR"), "{error}");
}

#[test]
fn synthetic_nullable_and_legacy_alias_strings_are_preserved() {
    // Synthetic advisory. OSV aliases permit nullable arrays and legacy strings.
    for (aliases, expected) in [
        (
            serde_json::json!(["SYNTHETIC-legacy,"]),
            serde_json::json!(["SYNTHETIC-legacy,"]),
        ),
        (serde_json::json!(null), serde_json::json!([])),
    ] {
        let kept = collect(serde_json::json!({"id":"SYNTHETIC-alias-neighbor", "aliases":aliases, "affected":[{"package":{"ecosystem":"npm", "name":"a"},"versions":["1.0.0"]}]}), zip::CompressionMethod::Deflated).unwrap();
        assert_eq!(kept[0]["aliases"], expected);
    }
}

#[test]
fn synthetic_raw_alias_corruption_is_not_erased() {
    let error = collect(serde_json::json!({"id":"SYNTHETIC-alias-type", "aliases":[123], "affected":[{"package":{"ecosystem":"npm", "name":"not-covered"},"versions":["1.0.0"]}]}), zip::CompressionMethod::Deflated).unwrap_err();
    assert!(error.starts_with("PARSE_ERROR"), "{error}");
}

#[test]
fn synthetic_raw_unattributable_non_git_record_is_refused() {
    let error = collect(
        serde_json::json!({"id":"SYNTHETIC-unattributable", "affected":[{"versions":["1.0.0"]}]}),
        zip::CompressionMethod::Deflated,
    )
    .unwrap_err();
    assert!(error.starts_with("PARSE_ERROR"), "{error}");
}

#[test]
fn synthetic_raw_package_absent_git_requires_repo_and_full_commits() {
    for range in [
        serde_json::json!({"type":"GIT", "events":[{"introduced":"0"}]}),
        serde_json::json!({"type":"GIT", "repo":"https://example.invalid/repo", "events":[{"introduced":"0"},{"fixed":"short-hash"}]}),
    ] {
        let error = collect(
            serde_json::json!({"id":"SYNTHETIC-git-schema", "affected":[{"ranges":[range]}]}),
            zip::CompressionMethod::Deflated,
        )
        .unwrap_err();
        assert!(error.starts_with("PARSE_ERROR"), "{error}");
    }
}

#[test]
fn synthetic_raw_withdrawal_is_validated_before_ignoring() {
    for withdrawn in [
        serde_json::json!(42),
        serde_json::json!("not-a-date"),
        serde_json::json!(null),
    ] {
        let error = collect(serde_json::json!({"id":"SYNTHETIC-withdrawal", "withdrawn":withdrawn, "affected":[{"package":{"ecosystem":"npm", "name":"a"},"versions":["1.0.0"]}]}), zip::CompressionMethod::Deflated).unwrap_err();
        assert!(error.starts_with("PARSE_ERROR"), "{error}");
    }
}

#[test]
fn synthetic_raw_id_is_validated_not_repaired() {
    let error = collect(serde_json::json!({"id":"SYNTHETIC-bad / id", "affected":[{"package":{"ecosystem":"npm", "name":"a"},"versions":["1.0.0"]}]}), zip::CompressionMethod::Deflated).unwrap_err();
    assert!(error.starts_with("PARSE_ERROR"), "{error}");
}

#[test]
fn malformed_dump_fields_cannot_be_reduced_to_empty_constraints() {
    for fields in [
        serde_json::json!({"ranges": {}}),
        serde_json::json!({"ranges": "invalid"}),
        serde_json::json!({"versions": [123]}),
        serde_json::json!({"versions": "invalid"}),
        serde_json::json!({"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}),
        serde_json::json!({"ranges": [{"type": "SEMVER", "events": [{"introduced": "not-a-version"}]}]}),
    ] {
        let mut affected = fields.clone();
        affected["package"] = serde_json::json!({"ecosystem": "npm", "name": "a"});
        let error = collect(
            serde_json::json!({"id": "SYNTHETIC-invalid", "affected": [affected]}),
            zip::CompressionMethod::Deflated,
        )
        .expect_err(&format!(
            "malformed npm fields must survive validation: {fields}"
        ));
        assert!(error.starts_with("PARSE_ERROR"), "{error}");
    }
}

#[test]
fn late_osv_collector_requires_introduced_before_package_filtering() {
    for events in [
        serde_json::json!([{"fixed": "2.0.0"}]),
        serde_json::json!([{"introduced": "0"}, {"fixed": "2.0.0"}, {"last_affected": "3.0.0"}]),
    ] {
        let raw = serde_json::json!({"id": "SYNTHETIC-range-schema", "affected": [{
            "package": {"ecosystem": "npm", "name": "not-covered"},
            "ranges": [{"type": "SEMVER", "events": events}]
        }]});
        let error = collect(raw, zip::CompressionMethod::Deflated)
            .expect_err("invalid synthetic events must be refused before covered filtering");
        assert!(error.starts_with("PARSE_ERROR"), "{error}");
    }
}

#[test]
fn late_osv_collector_preserves_infinite_limits_and_unsorted_repeated_introductions() {
    let events = serde_json::json!([
        {"limit": "*"}, {"fixed": "2.0.0"}, {"introduced": "1.5.0"}, {"introduced": "0"}
    ]);
    let raw = serde_json::json!({"id": "SYNTHETIC-valid-timeline", "affected": [{
        "package": {"ecosystem": "npm", "name": "a"},
        "ranges": [{"type": "SEMVER", "events": events}]
    }]});
    let kept = collect(raw, zip::CompressionMethod::Deflated).unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0]["affected"][0]["ranges"][0]["events"], events);
}

#[test]
fn late_osv_collector_refuses_missing_or_non_string_ecosystems() {
    // Synthetic corrupt package identities must not silently look non-npm.
    for package in [
        serde_json::json!({"name": "a"}),
        serde_json::json!({"name": "not-covered", "ecosystem": null}),
        serde_json::json!({"name": "a", "ecosystem": 42}),
        serde_json::json!({"name": "a", "ecosystem": []}),
        serde_json::json!(null),
    ] {
        let error = collect(
            serde_json::json!({"id": "SYNTHETIC-ecosystem", "affected": [
                {"package": package, "versions": ["1.0.0"]},
                {"package": {"ecosystem": "npm", "name": "a"}, "versions": ["1.0.0"]}
            ]}),
            zip::CompressionMethod::Deflated,
        )
        .expect_err(&format!("synthetic invalid ecosystem: {package}"));
        assert!(error.starts_with("PARSE_ERROR"), "{error}");
    }
}

#[test]
fn late_osv_optional_package_git_record_does_not_discard_npm_record() {
    // Synthetic shape found in official EEF-CVE-2026-56812: the package field
    // itself is optional; when present, its ecosystem remains required.
    let kept = collect(
        serde_json::json!({"id": "SYNTHETIC-optional-package", "affected": [
            {"ranges": [{"type": "GIT", "repo": "https://example.invalid/repo", "events": [{"introduced": "0"}, {"fixed": "a".repeat(40)}]}]},
            {"package": {"ecosystem": "npm", "name": "a"}, "versions": ["1.0.0"]}
        ]}),
        zip::CompressionMethod::Deflated,
    ).unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0]["affected"].as_array().unwrap().len(), 1);
    assert_eq!(kept[0]["affected"][0]["package"], "a");
}

#[test]
fn late_osv_valid_known_non_npm_and_versions_only_records_are_preserved() {
    for ecosystem in ["PyPI", "Hex", "GIT"] {
        let kept = collect(
            serde_json::json!({"id": "SYNTHETIC-other-ecosystem", "affected": [
                {"package": {"ecosystem": ecosystem}, "ranges": "not-npm-data"},
                {"package": {"ecosystem": "npm", "name": "a"}, "versions": ["1.0.0"]}
            ]}),
            zip::CompressionMethod::Deflated,
        )
        .unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["affected"].as_array().unwrap().len(), 1);
        assert_eq!(
            kept[0]["affected"][0]["versions"],
            serde_json::json!(["1.0.0"])
        );
    }
    assert!(collect(
        serde_json::json!({"id": "SYNTHETIC-withdrawn", "withdrawn": "2025-01-01T00:00:00Z"}),
        zip::CompressionMethod::Deflated
    )
    .unwrap()
    .is_empty());
}

#[test]
#[ignore = "requires authorized real HTTPS npm/all.zip fetch and an external evidence path"]
fn real_osv_fetch_uses_transactional_publication_without_clobbering_neighbor() {
    let fixture = FetchFixture::new();
    fixture.path(".own/cache/real-osv.json");
    let mut lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
    // Synthetic lock entries; every advisory below is fetched from real HTTPS.
    for (name, version) in [("nocodb", "2026.4.0"), ("total4", "12.0.0")] {
        lock.packages.push(
            serde_json::from_value(serde_json::json!({
                "name":name, "ecosystem":"npm", "version":version,
                "dir":format!("vendor/own/{name}"), "registry":"https://registry.npmjs.org",
                "integrity":"sha512-AAAA", "tarball_sha256":"sha256:0000",
                "version_manifest_sha256":"sha256:0001", "provenance_level":"integrity-only",
                "mode":"verbatim", "roots":["."], "dependents":["importer:."],
                "license_expression":"MIT", "license_policy":"allow", "license_files":[],
                "package_files_sha256":"sha256:0002", "file_count":0, "total_size":0
            }))
            .unwrap(),
        );
    }
    std::fs::write(
        fixture.0.join("own.lock"),
        own_core::canonical::write_lock_canonical(&lock),
    )
    .unwrap();
    std::fs::create_dir_all(fixture.0.join(".own/cache")).unwrap();
    let target = fixture.0.join(".own/cache/real-osv.json");
    let neighbor = fixture.0.join(".own/cache/real-osv.json.tmp");
    std::fs::write(&target, "synthetic-previous-snapshot").unwrap();
    std::fs::write(&neighbor, "synthetic-neighbor").unwrap();
    assert_eq!(
        osv::osv_fetch_project(&fixture.0, Some("2025-01-02T03:04:05Z")).unwrap(),
        0
    );
    let bytes = std::fs::read(&target).unwrap();
    let snapshot: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        snapshot["covered_packages"],
        serde_json::json!(["nocodb", "total4"])
    );
    assert!(snapshot["source_last_modified"]
        .as_str()
        .unwrap()
        .ends_with('Z'));
    let advisories = snapshot["advisories"].as_array().unwrap();
    assert!(advisories
        .iter()
        .any(
            |a| a["affected"].as_array().unwrap().iter().any(|a| a["ranges"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["fixed"] == "2026.04.1")))
        ));
    assert!(advisories
        .iter()
        .any(|a| a["affected"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["versions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "12.0"))));
    let output = std::env::var("OWN_TEST_OSV_FETCH_SNAPSHOT")
        .expect("set an external snapshot evidence path");
    std::fs::write(&output, &bytes).unwrap();
    println!("LIVE_FETCH: source={}; snapshot={output}; sha256={}; advisories={}; source_last_modified={}", DEFAULT_OSV_URL, own_core::sha256_hex(&bytes), advisories.len(), snapshot["source_last_modified"]);
    assert_eq!(
        std::fs::read(&neighbor).expect("neighbor must remain untouched"),
        b"synthetic-neighbor"
    );
    assert_eq!(
        std::fs::read_dir(fixture.0.join(".own/txn"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        std::fs::read_dir(fixture.0.join(".own/tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
#[ignore = "requires explicitly downloaded upstream npm/all.zip and an output path"]
fn late_osv_public_npm_dump_collects_every_live_npm_advisory() {
    let path =
        std::env::var("OWN_TEST_OSV_DUMP").expect("set OWN_TEST_OSV_DUMP to the real upstream zip");
    let output =
        std::env::var("OWN_TEST_OSV_REDUCED").expect("set OWN_TEST_OSV_REDUCED output path");
    let bytes = std::fs::read(&path).unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
    let mut packages = std::collections::HashSet::new();
    let mut expected_ids = std::collections::HashSet::new();
    for index in 0..archive.len() {
        let mut body = Vec::new();
        archive
            .by_index(index)
            .unwrap()
            .read_to_end(&mut body)
            .unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if raw["withdrawn"].as_str().is_some() {
            continue;
        }
        for affected in raw["affected"].as_array().unwrap() {
            if affected["package"]["ecosystem"] == "npm" {
                packages.insert(affected["package"]["name"].as_str().unwrap().to_string());
                expected_ids.insert(raw["id"].as_str().unwrap().to_string());
            }
        }
    }
    let covered = packages.iter().collect();
    let mut kept = osv::collect_advisories(&bytes, &covered)
        .expect("actual upstream must pass the actual collector");
    let actual_ids: std::collections::HashSet<_> = kept
        .iter()
        .map(|raw| raw["id"].as_str().unwrap().to_string())
        .collect();
    assert!(!expected_ids.is_empty());
    assert_eq!(
        actual_ids, expected_ids,
        "every live upstream npm advisory must be retained"
    );
    assert_eq!(kept.len(), actual_ids.len(), "no duplicate advisories");
    kept.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let reduced = own_core::jcs::canonicalize(&serde_json::json!(kept)).unwrap();
    std::fs::write(&output, reduced).unwrap();
    println!("PUBLIC_UPSTREAM: source={path}; zip_entries={}; live_npm_advisories={}; covered_packages={}; reduced={output}", archive.len(), actual_ids.len(), packages.len());
}

#[test]
fn inv11_osv_zip_entries_are_read_in_memory_for_stored_and_deflate() {
    let advisory = br#"{"id":"SYNTHETIC-1","affected":[{"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]}]}"#;
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "SYNTHETIC-1.json",
                zip::write::SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
        writer.write_all(advisory).unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
        assert_eq!(archive.len(), 1);
        let mut entry = archive.by_index(0).unwrap();
        assert!(entry.size() < 5 * 1_048_576);
        let mut text = String::new();
        entry.read_to_string(&mut text).unwrap();
        assert_eq!(text.as_bytes(), advisory);
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["id"], "SYNTHETIC-1");
        assert_eq!(doc["affected"][0]["package"]["ecosystem"], "npm");
    }
}
