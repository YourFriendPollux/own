//! CLI regressions for ignored options; synthetic state fixtures, no network.
use own_core::canonical::{empty_lock, write_lock_canonical};
use own_core::config::DEFAULT_OWN_TOML;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Project(PathBuf);
impl Project {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "own-options-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join(".own")).unwrap();
        fs::write(
            path.join("package.json"),
            "{\"name\":\"synthetic-options\",\"private\":true}\n",
        )
        .unwrap();
        fs::write(path.join("own.toml"), DEFAULT_OWN_TOML).unwrap();
        fs::write(
            path.join("own.lock"),
            write_lock_canonical(&empty_lock("0.1.0", "1", &serde_json::Map::new())),
        )
        .unwrap();
        fs::write(
            path.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\nimporters:\n  .: {}\n",
        )
        .unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_own"))
            .args(args)
            .current_dir(&self.0)
            .env_remove("OWN_OSV_LOCAL_PATH")
            .env_remove("OWN_OSV_MAX_AGE_DAYS")
            .output()
            .unwrap()
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn usage(output: Output, code: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(stderr.contains(code), "{stderr}");
}
#[test]
fn scan_rejects_unknown_format_before_empty_graph_rendering() {
    usage(
        Project::new().run(&["scan", "--format", "nonsense"]),
        "USAGE_ERROR",
    );
}
#[test]
fn pypi_vendor_all_is_refused_before_the_npm_path() {
    usage(
        Project::new().run(&[
            "add",
            "fakepkg@1.0.0",
            "--ecosystem",
            "pypi",
            "--allow-diamond",
            "vendor-all",
            "--no-install",
        ]),
        "ECOSYSTEM_UNSUPPORTED",
    );
}
#[test]
fn slice_rejects_unknown_consumer_model_before_empty_report() {
    usage(
        Project::new().run(&["slice", "--model", "nonsense"]),
        "USAGE_ERROR",
    );
}
#[test]
fn json_check_keeps_stale_override_warnings_visible() {
    let project = Project::new();
    fs::write(
        project.0.join(".own/osv.json"),
        serde_json::json!({
            "schema_version": 1, "generated_at": "2020-01-01T00:00:00Z",
            "source": "https://example.invalid/npm.zip", "source_last_modified": null,
            "covered_packages": [], "advisories": []
        })
        .to_string(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_own"))
        .args(["check", "--format", "json", "--allow-stale-osv"])
        .current_dir(&project.0)
        .env("OWN_NOW", "2025-01-02T03:04:05Z")
        .env_remove("OWN_OSV_LOCAL_PATH")
        .env_remove("OWN_OSV_MAX_AGE_DAYS")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["code"] == "W_OSV_STALE" && finding["severity"] == "warning"));
}
#[test]
fn scan_validates_network_configuration_even_without_dependencies() {
    let project = Project::new();
    fs::write(
        project.0.join("own.toml"),
        DEFAULT_OWN_TOML.replace("concurrency = 8", "concurrency = 0"),
    )
    .unwrap();
    usage(project.run(&["scan", "--format", "json"]), "PARSE_ERROR");
}
#[test]
fn scan_validates_extraction_limits_in_generated_configuration() {
    let project = Project::new();
    fs::write(
        project.0.join("own.toml"),
        DEFAULT_OWN_TOML.replace("max_entries = 20000", "max_entries = 0"),
    )
    .unwrap();
    usage(project.run(&["scan", "--format", "json"]), "PARSE_ERROR");
}
