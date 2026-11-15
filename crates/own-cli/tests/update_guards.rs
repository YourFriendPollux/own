#![cfg(unix)]
//! Synthetic, offline CLI regressions. No fixture commit, push or registry access.
use own_core::canonical::{
    compute_lock_digest, compute_vendor_files_sha256, license_policy_sha256, write_lock_canonical,
};
use own_core::lock::{LicenseFile, Lock, Manifest, ManifestFile, ManifestHeader, Package};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new(packages: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "own-update-guards-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let git = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|path| path.join("git"))
            .find(|path| path.is_file())
            .unwrap()
            .canonicalize()
            .unwrap();
        let init = Command::new(&git)
            .args(["init", "-q"])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(init.status.success(), "{init:?}");
        // A real clean unborn worktree, without making a fixture commit.
        fs::write(root.join(".git/info/exclude"), "*\n").unwrap();
        fs::write(root.join("own.toml"), own_core::config::DEFAULT_OWN_TOML).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\nimporters: {}\npackages: {}\n",
        )
        .unwrap();
        let policy =
            own_core::config::license_policy_json(own_core::config::DEFAULT_OWN_TOML).unwrap();
        let mut lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        let mut overrides = serde_json::Map::new();
        for &(name, version) in packages {
            let dir = format!("vendor/own/{}", own_core::lock::dir_name(name, version));
            fs::create_dir_all(root.join(&dir)).unwrap();
            for (path, bytes) in [
                (
                    "package.json",
                    serde_json::json!({"name":name,"version":version,"license":"MIT"}).to_string(),
                ),
                ("LICENSE", "MIT License\n".into()),
                ("index.js", "module.exports = 1;\n".into()),
            ] {
                fs::write(root.join(&dir).join(path), bytes).unwrap();
            }
            let (hash, count, size) = own_core::verify::hash_dir(&root.join(&dir)).unwrap();
            let files = ["LICENSE", "index.js", "package.json"]
                .into_iter()
                .map(|path| {
                    let bytes = fs::read(root.join(&dir).join(path)).unwrap();
                    ManifestFile {
                        path: path.into(),
                        sha256: own_core::sha256_hex(&bytes),
                        size: bytes.len() as u64,
                        exec: false,
                    }
                })
                .collect();
            let manifest = Manifest {
                manifest: ManifestHeader {
                    schema_version: 1,
                    package: format!("{name}@{version}"),
                    package_files_sha256: hash.clone(),
                    file_count: count,
                    total_size: size,
                },
                files,
            };
            fs::create_dir_all(root.join("vendor/own/.manifests")).unwrap();
            fs::write(
                root.join("vendor/own/.manifests")
                    .join(format!("{}.toml", own_core::lock::dir_name(name, version))),
                toml::to_string(&manifest).unwrap(),
            )
            .unwrap();
            lock.packages.push(Package {
                name: name.into(),
                ecosystem: "npm".into(),
                version: version.into(),
                dir: dir.clone(),
                registry: "https://registry.npmjs.org".into(),
                integrity: "sha512-synthetic-unit-fixture".into(),
                tarball_sha256: own_core::sha256_hex(b"synthetic archive metadata"),
                version_manifest_sha256: own_core::sha256_hex(b"synthetic registry metadata"),
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
                    sha256: own_core::sha256_hex(b"MIT License\n"),
                }],
                package_files_sha256: hash,
                file_count: count,
                total_size: size,
                diamond_resolution: None,
                unified_ranges: None,
            });
            let key = if packages.iter().filter(|(n, _)| *n == name).count() > 1 {
                own_core::lock::versioned_override_key(name, version)
            } else {
                name.into()
            };
            overrides.insert(key, serde_json::json!(format!("file:{dir}")));
        }
        lock.packages
            .sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        lock.metadata.license_policy_sha256 = license_policy_sha256(&policy);
        lock.metadata.vendor_files_sha256 = compute_vendor_files_sha256(&lock.packages);
        lock.metadata.lock_digest = compute_lock_digest(&lock, &overrides);
        fs::write(root.join("own.lock"), write_lock_canonical(&lock)).unwrap();
        fs::write(
            root.join("package.json"),
            serde_json::json!({"name":"synthetic-update-guards","pnpm":{"overrides":overrides}})
                .to_string(),
        )
        .unwrap();
        let checked = own_core::verify::verify(&root, &policy, &overrides).unwrap();
        assert!(
            checked.findings.is_empty(),
            "synthetic fixture not clean: {:?}",
            checked.findings
        );
        fs::create_dir(root.join("tools")).unwrap();
        let shim = root.join("tools/git");
        fs::write(&shim, format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}/git-calls\"\nif [ \"$1\" != status ]; then exit 98; fi\nexec '{}' \"$@\"\n", root.display(), git.display()
        )).unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        Self(root)
    }

    fn lock(&self) -> Lock {
        own_core::lock::parse_lock(&fs::read_to_string(self.0.join("own.lock")).unwrap()).unwrap()
    }

    fn update(&self, extra: &[&str]) -> Output {
        let result = Command::new(env!("CARGO_BIN_EXE_own"))
            .args(["update", "a@1.1.0", "--no-pr", "--no-install"])
            .args(extra)
            .current_dir(&self.0)
            .env("PATH", self.0.join("tools"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("https_proxy")
            .env_remove("OWN_NOW")
            .output()
            .unwrap();
        println!(
            "own update {:?}: exit={:?} stdout={} stderr={}",
            extra,
            result.status.code(),
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        result
    }

    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                if matches!(rel.as_str(), ".git" | ".own" | "tools" | "git-calls") {
                    continue;
                }
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    out.insert(rel, fs::read(path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.0, &self.0, &mut out);
        out
    }

    fn assert_unchanged(&self, before: &BTreeMap<String, Vec<u8>>) {
        assert_eq!(
            &self.snapshot(),
            before,
            "precondition refusal modified project bytes"
        );
        for dir in [".own/tmp", ".own/txn"] {
            if self.0.join(dir).exists() {
                assert_eq!(
                    fs::read_dir(self.0.join(dir)).unwrap().count(),
                    0,
                    "{dir} not cleaned"
                );
            }
        }
        let calls = fs::read_to_string(self.0.join("git-calls")).unwrap_or_default();
        assert!(
            calls.lines().all(|line| line.starts_with("status ")),
            "--no-pr invoked mutating Git commands: {calls}"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn update_validates_project_network_and_security_settings_before_fetching() {
    for field in ["registry", "security"] {
        let fixture = Fixture::new(&[("a", "1.0.0")]);
        let mut config: toml::Value = toml::from_str(own_core::config::DEFAULT_OWN_TOML).unwrap();
        let expected = if field == "registry" {
            config["registry"]["url"] = toml::Value::String("http://registry.example".into());
            "PARSE_ERROR: own.toml network"
        } else {
            config["security"]["max_entries"] = toml::Value::String("not-an-integer".into());
            "PARSE_ERROR: own.toml max_entries"
        };
        fs::write(
            fixture.0.join("own.toml"),
            toml::to_string(&config).unwrap(),
        )
        .unwrap();
        let before = fixture.snapshot();
        let result = fixture.update(&[]);
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(expected),
            "project settings ignored: {result:?}"
        );
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        fixture.assert_unchanged(&before);
    }
}

#[test]
fn update_refuses_a_real_dirty_worktree_without_writing_project_files() {
    let fixture = Fixture::new(&[("a", "1.0.0")]);
    fs::write(fixture.0.join(".git/info/exclude"), "*\n!unrelated.txt\n").unwrap();
    fs::write(fixture.0.join("unrelated.txt"), "uncommitted user change\n").unwrap();
    let before = fixture.snapshot();
    let result = fixture.update(&[]);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("WORKTREE_DIRTY"),
        "{result:?}"
    );
    fixture.assert_unchanged(&before);
}

#[test]
fn update_refuses_all_current_project_errors_before_fetching() {
    let mut ignored = Vec::new();
    for case in [
        "digest",
        "canonical",
        "override",
        "orphan",
        "licenses",
        "other-package",
    ] {
        let packages: &[(&str, &str)] = if case == "other-package" {
            &[("a", "1.0.0"), ("b", "1.0.0")]
        } else {
            &[("a", "1.0.0")]
        };
        let fixture = Fixture::new(packages);
        let mut lock = fixture.lock();
        match case {
            "digest" => {
                lock.metadata.lock_digest = own_core::sha256_hex(b"wrong digest");
                fs::write(fixture.0.join("own.lock"), write_lock_canonical(&lock)).unwrap();
            }
            "canonical" => {
                let text = fs::read_to_string(fixture.0.join("own.lock")).unwrap();
                fs::write(fixture.0.join("own.lock"), format!("{text}\n")).unwrap();
            }
            "override" => {
                fs::write(
                    fixture.0.join("package.json"),
                    r#"{"name":"synthetic-update-guards","pnpm":{"overrides":{}}}"#,
                )
                .unwrap();
                lock.metadata.lock_digest = compute_lock_digest(&lock, &serde_json::Map::new());
                fs::write(fixture.0.join("own.lock"), write_lock_canonical(&lock)).unwrap();
            }
            "orphan" => fs::create_dir(fixture.0.join("vendor/own/unowned@1.0.0")).unwrap(),
            "licenses" => {
                lock.metadata.licenses_md_sha256 = Some(own_core::sha256_hex(b"missing notice"));
                let package: serde_json::Value =
                    serde_json::from_slice(&fs::read(fixture.0.join("package.json")).unwrap())
                        .unwrap();
                lock.metadata.lock_digest =
                    compute_lock_digest(&lock, package["pnpm"]["overrides"].as_object().unwrap());
                fs::write(fixture.0.join("own.lock"), write_lock_canonical(&lock)).unwrap();
            }
            "other-package" => fs::write(
                fixture.0.join("vendor/own/b@1.0.0/index.js"),
                "tampered unrelated package\n",
            )
            .unwrap(),
            _ => unreachable!(),
        }
        let expected = match case {
            "digest" => "LOCK_DIGEST_MISMATCH",
            "canonical" => "LOCK_NOT_CANONICAL",
            "override" => "OVERRIDE_MISMATCH",
            "orphan" => "DRIFT_ORPHAN",
            "licenses" => "DRIFT_MISSING",
            "other-package" => "DRIFT_MODIFIED",
            _ => unreachable!(),
        };
        let before = fixture.snapshot();
        let result = fixture.update(&[]);
        let error = String::from_utf8_lossy(&result.stderr);
        if !error.contains(expected)
            || !error.contains("own verify")
            || error.contains("NETWORK_ERROR")
        {
            ignored.push(format!(
                "{case}: expected {expected} before download, got {result:?}"
            ));
        }
        fixture.assert_unchanged(&before);
    }
    assert!(
        ignored.is_empty(),
        "current drift ignored:\n{}",
        ignored.join("\n")
    );
}

#[test]
fn update_rejects_invalid_diamond_strategy_values() {
    let fixture = Fixture::new(&[("a", "1.0.0")]);
    let before = fixture.snapshot();
    let result = fixture.update(&["--allow-diamond", "not-a-strategy"]);
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("USAGE_ERROR: --allow-diamond must be keep-external|unify|vendor-all"),
        "invalid value was not validated: {result:?}"
    );
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    fixture.assert_unchanged(&before);
}

#[test]
fn update_refuses_strategy_changes_instead_of_ignoring_valid_flags() {
    for strategy in ["keep-external", "unify", "vendor-all"] {
        let fixture = Fixture::new(&[("a", "1.0.0")]);
        let before = fixture.snapshot();
        let result = fixture.update(&["--allow-diamond", strategy]);
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(
            error.contains("USAGE_ERROR: UPDATE_STRATEGY_UNSUPPORTED:")
                && error.contains(strategy)
                && error.contains("omit --allow-diamond"),
            "strategy silently ignored: {result:?}"
        );
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        fixture.assert_unchanged(&before);
    }
}

#[test]
fn update_refuses_ambiguous_source_versions_before_fetching() {
    let fixture = Fixture::new(&[("a", "1.0.0"), ("a", "2.0.0")]);
    assert_eq!(fixture.lock().packages.len(), 2);
    let before = fixture.snapshot();
    let result = fixture.update(&[]);
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(
        error.contains("UPDATE_AMBIGUOUS:"),
        "source version silently selected: {result:?}"
    );
    assert!(
        error.contains("a@1.0.0")
            && error.contains("a@2.0.0")
            && error.contains("source-version selector")
            && error.contains("before retrying"),
        "not actionable: {error}"
    );
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    fixture.assert_unchanged(&before);
}
