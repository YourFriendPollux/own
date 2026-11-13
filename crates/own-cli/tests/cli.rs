//! Integration tests for the `own` binary (crates/own-cli, `[[bin]] name = "own"`).
//!
//! Everything here is offline: no `add`, `scan`, `update`, `osv-fetch`,
//! `check --remote`, no pnpm, no node. Each test runs the real binary through
//! `env!("CARGO_BIN_EXE_own")` inside its own temporary directory.
//!
//! Exit codes are asserted against SPEC §8.0 (0 success, 1 blocking finding,
//! 2 usage/IO/format/precondition, 3 network) and every observed divergence is
//! flagged with a `// SPEC: écart` comment next to the assertion that encodes
//! the real behaviour.
//!
//! Clock injection: INV-10/§8.0 say tests inject the clock through `OWN_NOW`
//! (RFC 3339 UTC). The helper always removes inherited `OWN_NOW` /
//! `SOURCE_DATE_EPOCH` so runs are reproducible.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const FIXED_NOW: &str = "2025-01-02T03:04:05Z";

// ---------------------------------------------------------------------------
// Temporary directory with the same guarantees as `tempfile::TempDir`
// (one per test, removed on drop) without adding a dev-dependency.
// ---------------------------------------------------------------------------

static NONCE: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> TempDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX_EPOCH")
            .as_nanos();
        let nonce = NONCE.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "own-cli-it-{}-{nanos}-{nonce}-{label}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

fn write(root: &Path, rel: &str, contents: impl AsRef<[u8]>) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, contents).unwrap();
}

fn read(root: &Path, rel: &str) -> String {
    let path = root.join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn read_bytes(root: &Path, rel: &str) -> Vec<u8> {
    let path = root.join(rel);
    fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Value of `key = "value"` in the `[metadata]` section (lock lines are unique).
fn metadata_string(lock: &str, key: &str) -> String {
    lock.lines()
        .find(|line| line.starts_with(&format!("{key} = ")))
        .and_then(|line| line.split('"').nth(1))
        .unwrap_or_else(|| panic!("{key} not found in own.lock:\n{lock}"))
        .to_string()
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

/// Run `own` with a controlled environment. Global/system git config is
/// neutralised because `init` and `ci` spawn `git` themselves.
fn run_own(cwd: &Path, envs: &[(&str, &str)], args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_own"));
    cmd.args(args)
        .current_dir(cwd)
        .env_remove("OWN_NOW")
        .env_remove("SOURCE_DATE_EPOCH")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn own {args:?}: {e}"));
    let code = out
        .status
        .code()
        .unwrap_or_else(|| panic!("own {args:?} terminated by a signal"));
    (
        code,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn own(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    run_own(cwd, &[], args)
}

fn assert_exit(result: &(i32, String, String), expected: i32, context: &str) {
    assert_eq!(
        result.0, expected,
        "{context}: unexpected exit code\nstdout={:?}\nstderr={:?}",
        result.1, result.2
    );
}

fn parse_json(stdout: &str, context: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{context}: stdout is not valid JSON: {e}\nstdout={stdout:?}"))
}

fn finding_codes(envelope: &serde_json::Value) -> Vec<String> {
    envelope
        .get("findings")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("envelope has no findings array: {envelope}"))
        .iter()
        .filter_map(|f| f.get("code").and_then(|c| c.as_str()).map(str::to_string))
        .collect()
}

// ---------------------------------------------------------------------------
// Project fixtures
// ---------------------------------------------------------------------------

const PACKAGE_JSON: &str = r#"{"name":"fixture","version":"0.0.0","private":true}"#;

fn write_package_json(root: &Path) {
    write(root, "package.json", PACKAGE_JSON);
}

/// Minimal git repository; no commit is made, so no identity is needed, but the
/// explicit `-c user.name/-c user.email` keeps the fixture independent of any
/// machine-level git configuration.
fn git_init(root: &Path) {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=own-test",
            "-c",
            "user.email=own-test@example.invalid",
            "init",
            "-q",
        ])
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git is required to test `own ci`");
    assert!(
        out.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// pnpm v9 lockfile with no dependency at all: the shape `own ci` parses.
fn write_empty_pnpm_lock(root: &Path) {
    write(
        root,
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n\npackages: {}\n",
    );
}

fn init_project(label: &str) -> TempDir {
    let dir = TempDir::new(label);
    write_package_json(dir.path());
    assert_exit(&own(dir.path(), &["init"]), 0, "init fixture");
    dir
}

/// Empty-lock project wired like a real pnpm repo (git + pnpm-lock.yaml).
fn pnpm_project(label: &str) -> TempDir {
    let dir = TempDir::new(label);
    git_init(dir.path());
    write_package_json(dir.path());
    assert_exit(&own(dir.path(), &["init"]), 0, "init pnpm fixture");
    write_empty_pnpm_lock(dir.path());
    dir
}

// Synthetic `[[package]]` appended to the canonical lock written by `init`.
// Only the drift-sensitive fields matter; the digests deliberately do not match
// (they are recomputed by `verify` and reported as LOCK_DIGEST_MISMATCH), which
// keeps the fixture free of any SHA-256 computation while still exercising the
// per-file checks. The key order/format mirrors `write_lock_canonical`, so the
// lock stays byte-canonical (no LOCK_NOT_CANONICAL finding).
const SYNTHETIC_PACKAGE: &str = r#"
[[package]]
name = "fakepkg"
ecosystem = "npm"
version = "1.0.0"
dir = "vendor/own/fakepkg@1.0.0"
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
file_count = 2
total_size = 19
"#;

const SYNTHETIC_MANIFEST: &str = r#"[manifest]
schema_version = 1
package = "fakepkg@1.0.0"
package_files_sha256 = "sha256:0002"
file_count = 2
total_size = 19

[[file]]
path = "dist/index.js"
sha256 = "sha256:0003"
size = 9
exec = false

[[file]]
path = "missing.js"
sha256 = "sha256:0004"
size = 10
exec = false
"#;

/// Project with one vendored package in the lock where the tree has been
/// tampered with: `dist/index.js` modified, `missing.js` deleted, `extra.txt`
/// added out of band.
fn drift_project(label: &str) -> TempDir {
    let dir = init_project(label);
    write(
        dir.path(),
        "package.json",
        r#"{"name":"fixture","version":"0.0.0","private":true,"pnpm":{"overrides":{"fakepkg":"file:vendor/own/fakepkg@1.0.0"}}}"#,
    );
    write(
        dir.path(),
        "vendor/own/fakepkg@1.0.0/dist/index.js",
        "tampered\n",
    );
    write(
        dir.path(),
        "vendor/own/fakepkg@1.0.0/extra.txt",
        "surprise\n",
    );
    let mut lock = read(dir.path(), "own.lock");
    lock.push_str(SYNTHETIC_PACKAGE);
    write(dir.path(), "own.lock", &lock);
    write(
        dir.path(),
        "vendor/own/.manifests/fakepkg@1.0.0.toml",
        SYNTHETIC_MANIFEST,
    );
    dir
}

// ---------------------------------------------------------------------------
// 1. `own init`
// ---------------------------------------------------------------------------

#[test]
fn init_creates_layout_lock_and_git_files() {
    let dir = TempDir::new("init-layout");
    write_package_json(dir.path());
    // Pre-existing project files must be preserved (append-only, idempotent).
    write(dir.path(), ".gitignore", "dist/\n");
    write(dir.path(), ".gitattributes", "*.bin binary\n");

    let result = own(dir.path(), &["init"]);
    assert_exit(&result, 0, "init");
    assert!(result.1.is_empty(), "init stdout: {:?}", result.1);
    assert!(result.2.is_empty(), "init stderr: {:?}", result.2);

    for rel in [
        "own.toml",
        "own.lock",
        ".own/cache",
        ".own/tmp",
        ".own/txn",
        "vendor/own",
    ] {
        assert!(dir.join(rel).exists(), "init must create {rel}");
    }
    for rel in [".own/cache", ".own/tmp", ".own/txn", "vendor/own"] {
        assert!(dir.join(rel).is_dir(), "{rel} must be a directory");
    }

    let config = read(dir.path(), "own.toml");
    assert!(config.contains("schema_version = 1"), "own.toml: {config}");
    assert!(config.contains("[license]"), "own.toml: {config}");
    assert!(config.contains("unknown = \"deny\""), "own.toml: {config}");

    let lock = read(dir.path(), "own.lock");
    for needle in [
        "[metadata]",
        "schema_version = 1",
        "license_policy_sha256 = \"sha256:",
        "vendor_files_sha256 = \"sha256:",
        "lock_digest = \"sha256:",
    ] {
        assert!(lock.contains(needle), "own.lock lacks {needle:?}:\n{lock}");
    }
    assert!(
        !lock.contains("[[package]]"),
        "fresh lock must be empty:\n{lock}"
    );
    assert!(lock.ends_with('\n'), "own.lock must end with a newline");

    let gitignore = read(dir.path(), ".gitignore");
    assert_eq!(
        gitignore.lines().next(),
        Some("dist/"),
        "existing line kept"
    );
    assert!(
        gitignore.lines().any(|line| line == ".own/"),
        ".gitignore: {gitignore}"
    );
    assert_eq!(
        gitignore.lines().last(),
        Some("!vendor/own/**"),
        "the negation must be the last .gitignore line: {gitignore}"
    );

    let gitattributes = read(dir.path(), ".gitattributes");
    assert_eq!(gitattributes.lines().next(), Some("*.bin binary"));
    for line in [
        "vendor/own/** -text",
        "own.lock text eol=lf",
        "own.toml text eol=lf",
    ] {
        assert!(
            gitattributes.lines().any(|l| l == line),
            ".gitattributes lacks {line:?}: {gitattributes}"
        );
    }

    // SPEC: écart (INV-9) — §8.0 requires every writing command (explicitly
    // including `init`) to take `.own/lock` and journal in `.own/txn/<id>/`;
    // the implementation writes own.toml/own.lock directly and leaves no lock
    // file behind.
    assert!(
        !dir.join(".own/lock").exists(),
        "observed: init does not take the .own/lock transaction lock"
    );

    let verify = own(dir.path(), &["verify"]);
    assert_exit(&verify, 0, "verify after init");
    assert_eq!(verify.1, "ok: no findings\n");
    assert!(verify.2.is_empty(), "verify stderr: {:?}", verify.2);
}

#[test]
fn init_twice_reports_already_initialized() {
    let dir = init_project("init-twice");
    let lock_before = read_bytes(dir.path(), "own.lock");

    let second = own(dir.path(), &["init"]);
    assert_exit(&second, 2, "second init");
    assert!(
        second.2.contains("ALREADY_INITIALIZED"),
        "stderr: {:?}",
        second.2
    );
    assert_eq!(
        read_bytes(dir.path(), "own.lock"),
        lock_before,
        "a refused init must not rewrite the lock"
    );
}

#[test]
fn init_root_option_initializes_given_directory() {
    let parent = TempDir::new("init-root");
    fs::create_dir_all(parent.join("sub")).unwrap();
    write(&parent.join("sub"), "package.json", PACKAGE_JSON);

    let result = own(parent.path(), &["--root", "sub", "init"]);
    assert_exit(&result, 0, "init --root sub");
    assert!(parent.join("sub/own.lock").is_file());
    assert!(parent.join("sub/own.toml").is_file());
    assert!(parent.join("sub/vendor/own").is_dir());
    assert!(
        !parent.join("own.toml").exists(),
        "--root must not initialise the current directory"
    );

    let verify = own(parent.path(), &["--root", "sub", "verify"]);
    assert_exit(&verify, 0, "verify --root sub");
    assert_eq!(verify.1, "ok: no findings\n");
}

#[test]
fn init_requires_package_json() {
    let dir = TempDir::new("init-no-package-json");
    let result = own(dir.path(), &["init"]);
    assert_exit(&result, 2, "init without package.json");
    assert!(result.2.contains("USAGE_ERROR"), "stderr: {:?}", result.2);
    assert!(!dir.join("own.toml").exists(), "nothing must be written");
    assert!(!dir.join("own.lock").exists(), "nothing must be written");
}

// ---------------------------------------------------------------------------
// 2. `own verify` on a clean and on a tampered tree
// ---------------------------------------------------------------------------

#[test]
fn verify_empty_lock_is_clean_and_deterministic() {
    let dir = init_project("verify-clean");

    let first = own(dir.path(), &["verify"]);
    assert_exit(&first, 0, "verify");
    assert_eq!(first.1, "ok: no findings\n");
    assert!(first.2.is_empty(), "stderr: {:?}", first.2);

    let second = own(dir.path(), &["verify"]);
    assert_exit(&second, 0, "verify (second run)");
    assert_eq!(first.1, second.1, "verify output must be deterministic");
    assert_eq!(first.2, second.2, "verify stderr must be deterministic");
}

#[test]
fn verify_reports_drift_codes_for_tampered_vendor_tree() {
    let dir = drift_project("verify-drift");

    let result = own(dir.path(), &["verify"]);
    assert_exit(&result, 1, "verify on drifted tree");

    let envelope = parse_json(&result.1, "verify drift");
    assert_eq!(envelope["schema_version"].as_u64(), Some(1));
    assert_eq!(envelope["command"].as_str(), Some("verify"));
    assert_eq!(envelope["status"].as_str(), Some("findings"));
    assert_eq!(envelope["exit_code"].as_u64(), Some(1));
    assert!(envelope["data"].is_object(), "data must be an object");

    let codes = finding_codes(&envelope);
    for expected in ["DRIFT_MODIFIED", "DRIFT_MISSING", "DRIFT_EXTRA"] {
        assert!(
            codes.iter().any(|code| code == expected),
            "missing {expected}; codes={codes:?}\nstdout={:?}",
            result.1
        );
    }
    let modified = envelope["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| {
            f["code"].as_str() == Some("DRIFT_MODIFIED")
                && f["path"].as_str() == Some("dist/index.js")
        })
        .expect("DRIFT_MODIFIED for dist/index.js");
    assert_eq!(modified["package"].as_str(), Some("fakepkg@1.0.0"));
    assert_eq!(modified["severity"].as_str(), Some("error"));

    for needle in ["DRIFT_MODIFIED", "DRIFT_MISSING", "DRIFT_EXTRA"] {
        assert!(
            result.2.contains(needle),
            "human findings go to stderr; missing {needle} in {:?}",
            result.2
        );
    }

    // The synthetic `[[package]]` was appended in canonical layout, so the only
    // digest finding is the unavoidable recomputation mismatch.
    assert!(
        !codes.iter().any(|code| code == "LOCK_NOT_CANONICAL"),
        "fixture lock must stay canonical; codes={codes:?}"
    );
    assert!(
        codes.iter().any(|code| code == "LOCK_DIGEST_MISMATCH"),
        "synthetic entry cannot match lock_digest; codes={codes:?}"
    );
}

#[test]
fn verify_installed_without_node_modules_only_warns() {
    let dir = init_project("verify-installed");
    assert!(!dir.join("node_modules").exists());

    // SPEC: écart (§8.1) — `verify --installed` must compare node_modules/.pnpm
    // against the manifests and report DRIFT_INSTALLED. The implementation only
    // prints "warning: --installed not yet implemented" on stderr and skips the
    // comparison (exit 0).
    let result = own(dir.path(), &["verify", "--installed"]);
    assert_exit(&result, 0, "verify --installed");
    assert_eq!(result.1, "ok: no findings\n");
    assert!(
        result
            .2
            .contains("warning: --installed not yet implemented"),
        "stderr: {:?}",
        result.2
    );
}

// ---------------------------------------------------------------------------
// 3. Read commands on an uninitialised directory
// ---------------------------------------------------------------------------

#[test]
fn verify_on_uninitialized_directory_exits_1() {
    let dir = TempDir::new("verify-uninitialized");
    write_package_json(dir.path());

    // SPEC: écart (§8.0/§8.1) — a missing own.toml is the NOT_INITIALIZED
    // precondition and must exit 2. The implementation reports
    // "NOT_INITIALIZED or IO_ERROR: own.toml: ..." and the error-code mapper
    // splits on ':' so the prefix never matches: observed exit 1.
    let result = own(dir.path(), &["verify"]);
    assert_exit(&result, 1, "verify on uninitialized directory");
    assert!(
        result.2.contains("NOT_INITIALIZED"),
        "stderr: {:?}",
        result.2
    );
}

#[test]
fn read_commands_on_uninitialized_directory_exit_2() {
    let dir = TempDir::new("uninitialized-commands");
    write_package_json(dir.path());

    // SPEC: écart (§8.0) — these commands surface `IO_ERROR` (exit 2) instead of
    // the catalogued `NOT_INITIALIZED` identifier; the exit code matches §8.0.
    let cases: &[&[&str]] = &[
        &["ci"],
        &["licenses"],
        &["policy-sync"],
        &["migrate"],
        &["slice"],
        &["sbom"],
    ];
    for args in cases {
        let result = own(dir.path(), args);
        assert_exit(&result, 2, &format!("own {args:?} uninitialized"));
        assert!(
            result.2.contains("IO_ERROR"),
            "own {args:?}: expected IO_ERROR, stderr={:?}",
            result.2
        );
        assert!(
            !result.2.contains("NOT_INITIALIZED"),
            "own {args:?}: observed IO_ERROR, not NOT_INITIALIZED: {:?}",
            result.2
        );
    }
}

// ---------------------------------------------------------------------------
// 4. `own ci`
// ---------------------------------------------------------------------------

#[test]
fn ci_without_pnpm_lock_fails_with_io_error() {
    let dir = TempDir::new("ci-no-pnpm-lock");
    git_init(dir.path());
    write_package_json(dir.path());
    assert_exit(&own(dir.path(), &["init"]), 0, "init");

    // SPEC: écart (attendu du cahier de test) — `own ci` requires a
    // pnpm-lock.yaml even when the own.lock is empty: observed exit 2 with
    // IO_ERROR instead of a green run on a bare package.json.
    let result = own(dir.path(), &["ci"]);
    assert_exit(&result, 2, "ci without pnpm-lock.yaml");
    assert!(result.2.contains("IO_ERROR"), "stderr: {:?}", result.2);
    assert!(
        result.2.contains("pnpm-lock.yaml"),
        "stderr: {:?}",
        result.2
    );
}

#[test]
fn ci_on_empty_initialized_repo_exits_0_and_is_stable() {
    let dir = pnpm_project("ci-empty");
    let lock_before = read_bytes(dir.path(), "own.lock");

    let first = own(dir.path(), &["ci"]);
    assert_exit(&first, 0, "ci");
    assert_eq!(first.1, "ok: no findings\n");
    assert!(first.2.is_empty(), "ci stderr: {:?}", first.2);

    let second = own(dir.path(), &["ci"]);
    assert_exit(&second, 0, "ci (second run)");
    assert_eq!(first.1, second.1, "ci output must be stable");
    assert_eq!(first.2, second.2, "ci stderr must be stable");
    assert_eq!(
        read_bytes(dir.path(), "own.lock"),
        lock_before,
        "ci is read-only"
    );
}

#[test]
fn ci_json_format_emits_the_common_envelope() {
    let dir = pnpm_project("ci-json");

    let result = own(dir.path(), &["ci", "--format", "json"]);
    assert_exit(&result, 0, "ci --format json");
    let envelope = parse_json(&result.1, "ci json");
    for key in [
        "schema_version",
        "command",
        "status",
        "exit_code",
        "findings",
        "data",
    ] {
        assert!(envelope.get(key).is_some(), "missing envelope key {key}");
    }
    assert_eq!(envelope["schema_version"].as_u64(), Some(1));
    assert_eq!(envelope["command"].as_str(), Some("ci"));
    assert_eq!(envelope["status"].as_str(), Some("ok"));
    assert_eq!(envelope["exit_code"].as_u64(), Some(0));
    assert_eq!(envelope["findings"].as_array().map(Vec::len), Some(0));
    assert!(envelope["data"].is_object());
}

// ---------------------------------------------------------------------------
// 5. `own licenses [--write]`
// ---------------------------------------------------------------------------

#[test]
fn licenses_empty_lock_read_then_write_is_idempotent() {
    let dir = init_project("licenses-idempotent");

    let read_only = own(dir.path(), &["licenses"]);
    assert_exit(&read_only, 0, "licenses");
    assert!(
        read_only.1.contains("Package") && read_only.1.contains("Version"),
        "expected the license table header, stdout={:?}",
        read_only.1
    );
    assert!(read_only.2.is_empty(), "stderr: {:?}", read_only.2);

    let first = own(dir.path(), &["licenses", "--write"]);
    assert_exit(&first, 0, "licenses --write");
    assert!(
        first
            .1
            .contains("wrote vendor/own/LICENSES.md (0 packages)"),
        "stdout: {:?}",
        first.1
    );
    assert!(dir.join("vendor/own/LICENSES.md").is_file());
    assert_eq!(
        read_bytes(dir.path(), "vendor/own/LICENSES.md"),
        b"",
        "an empty lock renders an empty LICENSES.md"
    );
    let lock_after_first = read_bytes(dir.path(), "own.lock");
    let md_after_first = read_bytes(dir.path(), "vendor/own/LICENSES.md");

    let second = own(dir.path(), &["licenses", "--write"]);
    assert_exit(&second, 0, "licenses --write (second run)");
    assert_eq!(first.1, second.1, "idempotent output");
    assert_eq!(
        read_bytes(dir.path(), "own.lock"),
        lock_after_first,
        "own.lock must be byte-identical after a second --write"
    );
    assert_eq!(
        read_bytes(dir.path(), "vendor/own/LICENSES.md"),
        md_after_first,
        "LICENSES.md must be byte-identical after a second --write"
    );

    // Once the lock tracks licenses_md_sha256, the read-only form is silent.
    let read_after = own(dir.path(), &["licenses"]);
    assert_exit(&read_after, 0, "licenses after --write");
    assert!(
        read_after.1.is_empty(),
        "tracked LICENSES.md is checked silently; stdout={:?}",
        read_after.1
    );

    let verify = own(dir.path(), &["verify"]);
    assert_exit(&verify, 0, "verify after licenses --write");
    assert_eq!(verify.1, "ok: no findings\n");
}

// ---------------------------------------------------------------------------
// 6. `own policy-sync` and `own migrate`
// ---------------------------------------------------------------------------

#[test]
fn policy_sync_recomputes_license_policy_digest() {
    let dir = init_project("policy-sync");
    let lock_before = read(dir.path(), "own.lock");
    let hash_before = metadata_string(&lock_before, "license_policy_sha256");

    // Extend the allow list: without a policy sync this must leave verify red.
    let config = read(dir.path(), "own.toml");
    let edited = config.replacen("\"ISC\"]", "\"ISC\", \"0BSD\"]", 1);
    assert_ne!(config, edited, "fixture: default allow list not found");
    write(dir.path(), "own.toml", &edited);

    let stale = own(dir.path(), &["verify"]);
    assert_exit(&stale, 1, "verify after own.toml edit");
    let envelope = parse_json(&stale.1, "verify after policy edit");
    let codes = finding_codes(&envelope);
    assert!(
        codes.iter().any(|code| code == "LOCK_DIGEST_MISMATCH"),
        "codes={codes:?}"
    );
    // The human output only prints code/package/path; the detail lives in the
    // JSON envelope.
    assert!(
        envelope["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["code"].as_str() == Some("LOCK_DIGEST_MISMATCH")
                    && finding["message"]
                        .as_str()
                        .map(|m| m.contains("license_policy_sha256 recomputed"))
                        .unwrap_or(false)
            }),
        "expected the policy-digest finding in the envelope: {}",
        stale.1
    );

    let sync = own(dir.path(), &["policy-sync"]);
    assert_exit(&sync, 0, "policy-sync");
    assert_eq!(sync.1, "policy synced\n");
    assert!(sync.2.is_empty(), "stderr: {:?}", sync.2);

    let lock_after = read(dir.path(), "own.lock");
    let hash_after = metadata_string(&lock_after, "license_policy_sha256");
    assert_ne!(
        hash_before, hash_after,
        "policy-sync must recompute license_policy_sha256"
    );
    assert_eq!(
        metadata_string(&lock_after, "vendor_files_sha256"),
        metadata_string(&lock_before, "vendor_files_sha256"),
        "policy-sync only rewrites the policy digest"
    );

    let verify = own(dir.path(), &["verify"]);
    assert_exit(&verify, 0, "verify after policy-sync");
    assert_eq!(verify.1, "ok: no findings\n");

    // Idempotent: a second sync rewrites the same bytes.
    let again = own(dir.path(), &["policy-sync"]);
    assert_exit(&again, 0, "policy-sync (second run)");
    assert_eq!(again.1, "policy synced\n");
    assert_eq!(
        read_bytes(dir.path(), "own.lock"),
        lock_after.into_bytes(),
        "policy-sync must be idempotent"
    );
}

#[test]
fn migrate_on_schema_version_1_is_a_no_op() {
    let dir = init_project("migrate-v1");
    let lock_before = read_bytes(dir.path(), "own.lock");

    let result = own(dir.path(), &["migrate"]);
    assert_exit(&result, 0, "migrate");
    assert_eq!(
        result.1, "schema_version 1 is current; nothing to migrate\n",
        "migrate message"
    );
    assert!(result.2.is_empty(), "stderr: {:?}", result.2);
    assert_eq!(
        read_bytes(dir.path(), "own.lock"),
        lock_before,
        "migrate v1 must not rewrite the lock"
    );
}

// ---------------------------------------------------------------------------
// 7. `own check` without an OSV dump
// ---------------------------------------------------------------------------

#[test]
fn check_without_osv_json_fails_osv_missing() {
    let dir = init_project("check-missing-osv");
    assert!(!dir.join(".own/osv.json").exists());

    let result = own(dir.path(), &["check"]);
    assert_exit(&result, 2, "check without .own/osv.json");
    assert!(result.2.contains("OSV_MISSING"), "stderr: {:?}", result.2);
    assert!(
        !dir.join(".own/osv.json").exists(),
        "check is read-only and must not create the dump"
    );
}

#[test]
fn check_allow_missing_osv_warns_and_exits_0() {
    let dir = init_project("check-allow-missing");

    let human = own(dir.path(), &["check", "--allow-missing-osv"]);
    assert_exit(&human, 0, "check --allow-missing-osv");
    assert!(
        human.2.contains("warning: W_OSV_MISSING"),
        "stderr: {:?}",
        human.2
    );
    assert!(
        human.1.contains("ok: no E0 alerts"),
        "stdout: {:?}",
        human.1
    );

    // A W_* warning never changes the exit code (§8.0).
    let json = own(
        dir.path(),
        &["check", "--allow-missing-osv", "--format", "json"],
    );
    assert_exit(&json, 0, "check --allow-missing-osv --format json");
    assert!(
        json.2.contains("warning: W_OSV_MISSING"),
        "stderr: {:?}",
        json.2
    );
    let envelope = parse_json(&json.1, "check json");
    assert_eq!(envelope["schema_version"].as_u64(), Some(1));
    assert_eq!(envelope["command"].as_str(), Some("check"));
    assert_eq!(envelope["status"].as_str(), Some("ok"));
    assert_eq!(envelope["exit_code"].as_u64(), Some(0));
    assert_eq!(envelope["findings"].as_array().map(Vec::len), Some(0));
    assert_eq!(envelope["data"]["alerts"].as_array().map(Vec::len), Some(0));
}

// ---------------------------------------------------------------------------
// 8. `own slice`
// ---------------------------------------------------------------------------

#[test]
fn slice_empty_lock_is_deterministic() {
    let dir = init_project("slice-empty");

    let first = own(dir.path(), &["slice"]);
    assert_exit(&first, 0, "slice");
    assert!(
        first.1.contains("TOTAL: 0.00MB -> 0.00MB  reduction 0.0%"),
        "stdout: {:?}",
        first.1
    );
    assert!(first.2.is_empty(), "stderr: {:?}", first.2);

    let second = own(dir.path(), &["slice"]);
    assert_exit(&second, 0, "slice (second run)");
    assert_eq!(first.1, second.1, "slice output must be deterministic");

    let json = own(dir.path(), &["slice", "--format", "json"]);
    assert_exit(&json, 0, "slice --format json");
    let envelope = parse_json(&json.1, "slice json");
    assert_eq!(envelope["command"].as_str(), Some("slice"));
    assert_eq!(envelope["status"].as_str(), Some("ok"));
    assert_eq!(envelope["exit_code"].as_u64(), Some(0));
    assert_eq!(
        envelope["data"]["packages"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(envelope["data"]["total_bytes"].as_u64(), Some(0));
    assert_eq!(envelope["data"]["kept_bytes"].as_u64(), Some(0));
}

// ---------------------------------------------------------------------------
// 9. `own sbom` (CycloneDX / OpenVEX) and determinism
// ---------------------------------------------------------------------------

#[test]
fn sbom_cyclonedx_on_empty_lock_is_valid() {
    let dir = init_project("sbom-cyclonedx");
    let lock_before = read_bytes(dir.path(), "own.lock");

    let result = run_own(dir.path(), &[("OWN_NOW", FIXED_NOW)], &["sbom"]);
    assert_exit(&result, 0, "sbom");
    let doc = parse_json(&result.1, "sbom cyclonedx");
    assert_eq!(doc["bomFormat"].as_str(), Some("CycloneDX"));
    assert_eq!(doc["specVersion"].as_str(), Some("1.5"));
    assert_eq!(doc["version"].as_u64(), Some(1));
    let serial = doc["serialNumber"].as_str().expect("serialNumber");
    assert!(
        serial.starts_with("urn:uuid:") && serial.len() == "urn:uuid:".len() + 36,
        "serialNumber: {serial}"
    );
    assert_eq!(
        doc["metadata"]["timestamp"].as_str(),
        Some(FIXED_NOW),
        "OWN_NOW must drive metadata.timestamp"
    );
    assert_eq!(
        doc["components"].as_array().map(Vec::len),
        Some(0),
        "empty lock has no component"
    );
    assert_eq!(
        read_bytes(dir.path(), "own.lock"),
        lock_before,
        "sbom is read-only"
    );
}

#[test]
fn sbom_vex_on_empty_lock_is_valid() {
    let dir = init_project("sbom-vex");

    // SPEC: écart (§8.3) — the spec makes --output optional ("sortie sur stdout
    // si pas de --output"); the implementation requires an output path for
    // --format vex and exits 2 with USAGE_ERROR.
    let missing_output = own(dir.path(), &["sbom", "--format", "vex"]);
    assert_exit(&missing_output, 2, "sbom --format vex without --output");
    assert!(
        missing_output.2.contains("USAGE_ERROR"),
        "stderr: {:?}",
        missing_output.2
    );
    assert!(
        missing_output.2.contains("vex output path required"),
        "stderr: {:?}",
        missing_output.2
    );

    let result = run_own(
        dir.path(),
        &[("OWN_NOW", FIXED_NOW)],
        &["sbom", "--format", "vex", "--output", "vex.json"],
    );
    assert_exit(&result, 0, "sbom --format vex --output");
    assert!(dir.join("vex.json").is_file());

    let doc = parse_json(&read(dir.path(), "vex.json"), "vex document");
    assert_eq!(
        doc["@context"].as_str(),
        Some("https://openvex.dev/ns/v0.2.0")
    );
    let id = doc["@id"].as_str().expect("@id");
    assert!(id.starts_with("https://openvex.dev/docs/own/"), "@id: {id}");
    assert_eq!(doc["author"].as_str(), Some("own"));
    assert_eq!(doc["timestamp"].as_str(), Some(FIXED_NOW));
    assert_eq!(doc["version"].as_u64(), Some(1));
    let statements = doc["statements"].as_array().expect("statements");
    assert!(statements.is_empty(), "no advisory in an empty lock");
    // §8.3: `justification` is reserved for not_affected and never emitted.
    assert!(
        statements
            .iter()
            .all(|statement| statement.get("justification").is_none()),
        "no justification allowed in VEX statements"
    );
}

#[test]
fn sbom_output_is_byte_identical_with_fixed_own_now() {
    let dir = init_project("sbom-determinism");
    let lock_before = read_bytes(dir.path(), "own.lock");

    for (first, second) in [("cdx-a.json", "cdx-b.json")] {
        for path in [first, second] {
            let result = run_own(
                dir.path(),
                &[("OWN_NOW", FIXED_NOW)],
                &["sbom", "--output", path],
            );
            assert_exit(&result, 0, &format!("sbom --output {path}"));
        }
        assert_eq!(
            read_bytes(dir.path(), first),
            read_bytes(dir.path(), second),
            "CycloneDX must be byte-identical for the same OWN_NOW"
        );
    }

    for path in ["vex-a.json", "vex-b.json"] {
        let result = run_own(
            dir.path(),
            &[("OWN_NOW", FIXED_NOW)],
            &["sbom", "--format", "vex", "--output", path],
        );
        assert_exit(&result, 0, &format!("sbom vex --output {path}"));
    }
    assert_eq!(
        read_bytes(dir.path(), "vex-a.json"),
        read_bytes(dir.path(), "vex-b.json"),
        "OpenVEX must be byte-identical for the same OWN_NOW"
    );

    // The injected clock is actually honoured: another OWN_NOW changes bytes.
    let other = run_own(
        dir.path(),
        &[("OWN_NOW", "2026-03-04T05:06:07Z")],
        &["sbom", "--output", "cdx-c.json"],
    );
    assert_exit(&other, 0, "sbom with a different OWN_NOW");
    let baseline = read_bytes(dir.path(), "cdx-a.json");
    let shifted = read_bytes(dir.path(), "cdx-c.json");
    assert_ne!(baseline, shifted, "OWN_NOW must change the timestamp");
    let doc = parse_json(&read(dir.path(), "cdx-c.json"), "cdx-c");
    assert_eq!(
        doc["metadata"]["timestamp"].as_str(),
        Some("2026-03-04T05:06:07Z")
    );

    assert_eq!(
        read_bytes(dir.path(), "own.lock"),
        lock_before,
        "sbom must not modify the lock"
    );
}

// ---------------------------------------------------------------------------
// 10. `own eject`
// ---------------------------------------------------------------------------

#[test]
fn eject_refuses_without_adopt_and_changes_nothing() {
    let dir = init_project("eject-refusal");
    let lock_before = read_bytes(dir.path(), "own.lock");
    let config_before = read_bytes(dir.path(), "own.toml");
    let gitignore_before = read_bytes(dir.path(), ".gitignore");
    let gitattributes_before = read_bytes(dir.path(), ".gitattributes");

    for args in [&["eject"][..], &["eject", "--yes"][..]] {
        let result = own(dir.path(), args);
        assert_exit(&result, 2, &format!("own {args:?}"));
        assert!(
            result.2.contains("USAGE_ERROR"),
            "own {args:?}: stderr={:?}",
            result.2
        );
        assert!(
            result.2.contains("only --adopt"),
            "own {args:?}: stderr={:?}",
            result.2
        );
    }

    for rel in ["own.lock", "own.toml", ".gitignore", ".gitattributes"] {
        assert!(dir.join(rel).exists(), "{rel} must survive a refused eject");
    }
    assert_eq!(read_bytes(dir.path(), "own.lock"), lock_before);
    assert_eq!(read_bytes(dir.path(), "own.toml"), config_before);
    assert_eq!(read_bytes(dir.path(), ".gitignore"), gitignore_before);
    assert_eq!(
        read_bytes(dir.path(), ".gitattributes"),
        gitattributes_before
    );
    assert!(dir.join(".own").is_dir(), ".own/ must survive");
    assert!(dir.join("vendor/own").is_dir(), "vendor/own/ must survive");
}

// ---------------------------------------------------------------------------
// 11. Usage errors
// ---------------------------------------------------------------------------

#[test]
fn usage_errors_exit_2() {
    let dir = init_project("usage-errors");

    let cases: &[(&[&str], &str)] = &[
        (&["bogus-command"], "unrecognized subcommand"),
        (&["add"], "required arguments"),
        (&["sbom", "--format", "xml"], "USAGE_ERROR"),
        // SPEC: écart (§8.0) — every command must accept --format human|json;
        // `verify` does not declare it and clap rejects it as an unknown flag.
        (&["verify", "--format", "json"], "unexpected argument"),
        (&["verify", "--format", "bogus"], "unexpected argument"),
    ];
    for (args, needle) in cases {
        let result = own(dir.path(), args);
        assert_exit(&result, 2, &format!("own {args:?}"));
        assert!(
            result.2.contains(needle),
            "own {args:?}: stderr must contain {needle:?}, got {:?}",
            result.2
        );
    }

    // SPEC: écart (§8.0) — unlike `sbom`, `check` does not validate --format:
    // an unknown value silently falls back to the human output (exit 0).
    let check = own(
        dir.path(),
        &["check", "--allow-missing-osv", "--format", "xml"],
    );
    assert_exit(&check, 0, "check --format xml");
    assert!(
        check.1.contains("ok: no E0 alerts"),
        "invalid --format silently ignored; stdout={:?}",
        check.1
    );
}
