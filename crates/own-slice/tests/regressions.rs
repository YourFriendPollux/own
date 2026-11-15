use own_slice::{e1, ConsumerModel};
use std::path::Path;
use std::process::Command;

fn write(root: &Path, name: &str, text: &str) {
    let path = root.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn fixture(source: &str) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "package.json",
        r#"{"name":"fixture","main":"index.js"}"#,
    );
    write(tmp.path(), "index.js", source);
    write(
        tmp.path(),
        "vuln.js",
        "module.exports = 'HARMLESS_LOADED';\n",
    );
    tmp
}

fn advisory(file: &str) -> serde_json::Value {
    serde_json::json!({"affected":[{"database_specific":{"vulnerable_files":[file]}}]})
}

fn node(root: &Path, script: &str) -> std::process::Output {
    let output = Command::new("node")
        .arg("--eval")
        .arg(script)
        .current_dir(root)
        .env_remove("NODE_OPTIONS")
        .output()
        .expect("real Node is required for these regression tests");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn assigned_require_alias_cannot_prove_unreachable() {
    let tmp = fixture("let r; r = require; module.exports = r('./vuln.js');\n");
    let root = tmp.path();
    let output = node(root, "console.log(require('./index.js'))");
    assert!(String::from_utf8_lossy(&output.stdout).contains("HARMLESS_LOADED"));
    assert_eq!(
        e1::evidence_level(root, &advisory("vuln.js"), ConsumerModel::Cjs).0,
        "E0"
    );
    let report = own_slice::slice_package(root, "fixture");
    assert!(report.keep_whole);
    assert!(report.dropped_files.is_empty());
}

#[test]
fn syntax_error_without_missing_nodes_is_not_evidence() {
    let tmp = fixture("const = ;\n");
    let root = tmp.path();
    let output = Command::new("node")
        .arg("--check")
        .arg(root.join("index.js"))
        .output()
        .expect("real Node required");
    assert!(!output.status.success());
    assert!(matches!(
        own_slice::ast::parse(Path::new("index.js"), b"const = ;"),
        own_slice::ast::ParseOutcome::Failed
    ));
    assert_eq!(
        e1::evidence_level(root, &advisory("vuln.js"), ConsumerModel::Cjs).0,
        "E0"
    );
    assert!(own_slice::slice_package(root, "fixture")
        .dropped_files
        .is_empty());
}

#[test]
fn node_file_resolution_precedes_directory_main_and_index() {
    let tmp = fixture("module.exports = require('./dep');\n");
    let root = tmp.path();
    write(root, "dep.js", "module.exports = 'NODE_FILE';\n");
    write(root, "dep/index.js", "module.exports = 'WRONG_INDEX';\n");
    let output = node(root, "console.log(require('./index.js'))");
    assert!(String::from_utf8_lossy(&output.stdout).contains("NODE_FILE"));
    assert_eq!(
        e1::evidence_level(root, &advisory("dep.js"), ConsumerModel::Cjs).0,
        "E0"
    );
    assert!(own_slice::slice_package(root, "fixture")
        .kept_files
        .contains(&"dep.js".into()));
    write(root, "dep/package.json", r#"{"main":"chosen"}"#);
    write(root, "dep/chosen.js", "module.exports = 'WRONG_MAIN';\n");
    let output = node(root, "console.log(require('./index.js'))");
    assert!(String::from_utf8_lossy(&output.stdout).contains("NODE_FILE"));
    assert_eq!(
        e1::evidence_level(root, &advisory("dep.js"), ConsumerModel::Cjs).0,
        "E0"
    );
}

#[test]
fn typescript_entry_keeps_reachable_js() {
    let tmp = fixture("module.exports = 1;\n");
    write(
        tmp.path(),
        "package.json",
        r#"{"name":"fixture","main":"index.ts"}"#,
    );
    write(
        tmp.path(),
        "index.ts",
        "module.exports = require('./vuln.js');\n",
    );
    let report = own_slice::slice_package(tmp.path(), "fixture");
    assert!(report.kept_files.contains(&"index.ts".into()));
    assert!(report.kept_files.contains(&"vuln.js".into()));
    assert!(!report.dropped_files.contains(&"vuln.js".into()));
}

#[test]
fn e2_package_cannot_erase_trace_by_replacing_stdout() {
    let tmp = fixture("process.stdout.write = () => true; require('./vuln.js');\n");
    match own_slice::e2::trace_loaded_files(tmp.path(), &tmp.path().join("index.js")) {
        own_slice::e2::E2Outcome::Loaded(loaded) => assert!(loaded.contains("vuln.js")),
        own_slice::e2::E2Outcome::Inconclusive => {
            panic!("harmless fixture should have a complete trace")
        }
    }
}

#[test]
fn e2_large_stdout_is_drained_while_child_runs() {
    let tmp = fixture("process.stdout.write('x'.repeat(200000)); require('./vuln.js');\n");
    let start = std::time::Instant::now();
    match own_slice::e2::trace_loaded_files(tmp.path(), &tmp.path().join("index.js")) {
        own_slice::e2::E2Outcome::Loaded(loaded) => assert!(loaded.contains("vuln.js")),
        own_slice::e2::E2Outcome::Inconclusive => panic!("bounded stdout must not deadlock"),
    }
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn e2_denies_reads_outside_the_package_and_driver() {
    let outside = tempfile::tempdir().unwrap();
    let file = outside.path().join("harmless.txt");
    std::fs::write(&file, "HARMLESS TEST DATA").unwrap();
    let tmp = fixture(&format!(
        "require('fs').readFileSync({});\n",
        serde_json::to_string(&file).unwrap()
    ));
    assert!(matches!(
        own_slice::e2::trace_loaded_files(tmp.path(), &tmp.path().join("index.js")),
        own_slice::e2::E2Outcome::Inconclusive
    ));
}
