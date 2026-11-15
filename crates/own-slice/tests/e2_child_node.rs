#![cfg(unix)]

use own_slice::e2::{trace_loaded_files, E2Outcome};
use own_slice::{e1, e2, ConsumerModel};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
    write(tmp.path(), "safe.js", "module.exports = 1;\n");
    write(tmp.path(), "vuln.js", "module.exports = 2;\n");
    tmp
}

fn real_node() -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").expect("Node PATH is required"))
        .map(|dir| dir.join("node"))
        .find(|path| {
            std::fs::metadata(path)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
        .and_then(|path| std::fs::canonicalize(path).ok())
        .expect("a real executable Node is required, never skip E2 tests")
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
}

fn run_probe(root: &Path, path: &std::ffi::OsStr, expected: &str) -> Output {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "e2_probe_child", "--ignored", "--nocapture"])
        .env("PATH", path)
        .env("OWN_E2_CHILD_ROOT", root)
        .env("OWN_E2_CHILD_EXPECT", expected)
        .env("OWN_E2_TEST_SECRET", "dummy-must-not-reach-node")
        .env("NODE_OPTIONS", "--not-a-valid-node-option")
        .env("NODE_PATH", "/dummy/must/not/reach/node")
        .output()
        .unwrap()
}

#[test]
#[ignore = "isolated child harness, explicitly executed by the parent tests"]
fn e2_probe_child() {
    let root = PathBuf::from(std::env::var_os("OWN_E2_CHILD_ROOT").unwrap());
    let outcome = trace_loaded_files(&root, &root.join("index.js"));
    match (
        std::env::var("OWN_E2_CHILD_EXPECT").unwrap().as_str(),
        outcome,
    ) {
        ("loaded", E2Outcome::Loaded(files)) => {
            assert!(
                files.contains("index.js"),
                "entry missing from complete trace"
            );
            assert!(
                files.contains("safe.js"),
                "dependency missing from complete trace"
            );
        }
        ("inconclusive", E2Outcome::Inconclusive) => {}
        (expected, _) => panic!("probe did not return expected {expected}"),
    }
}

#[test]
fn e2_uses_incoming_path_without_forwarding_environment() {
    let node = real_node();
    let pkg = fixture(
        "if (['OWN_E2_TEST_SECRET', 'OWN_E2_CHILD_ROOT', 'OWN_E2_CHILD_EXPECT', 'NODE_OPTIONS', 'NODE_PATH', 'HOME', 'USER'].some(k => process.env[k] !== undefined) || process.env.PATH !== '/usr/bin:/bin') throw new Error('caller environment leaked'); require('./safe.js');\n",
    );
    let bins = tempfile::tempdir().unwrap();
    let selected = bins.path().join("selected");
    let blocked = bins.path().join("not-executable");
    let marker = bins.path().join("arguments.txt");
    write(&blocked, "node", "not executable\n");
    write(
        &selected,
        "node",
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexec {} \"$@\"\n",
            shell_quote(&marker),
            shell_quote(&node),
        ),
    );
    std::fs::set_permissions(
        selected.join("node"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let path = std::env::join_paths([blocked, selected]).unwrap();
    let output = run_probe(pkg.path(), &path, "loaded");
    assert!(
        marker.is_file(),
        "the Node selected from incoming PATH was not executed: {output:?}"
    );
    assert!(output.status.success(), "{output:?}");
    let args = std::fs::read_to_string(marker).unwrap();
    let args: Vec<_> = args.lines().collect();
    assert!(args.contains(&"--max-old-space-size=256"));
    assert!(args.contains(&"--permission"));
    assert!(args.contains(&"--no-addons"));
    assert_eq!(
        args.iter()
            .filter(|arg| arg.starts_with("--allow-fs-read="))
            .count(),
        2
    );
    assert!(!args.contains(&"--allow-fs-read=/"));
    assert!(!args.iter().any(|arg| arg.starts_with("--allow-net")
        || arg.starts_with("--allow-fs-write")
        || arg.starts_with("--allow-child-process")
        || arg.starts_with("--allow-worker")));
}

#[test]
fn e2_requires_esm_registration_even_for_cjs_probes() {
    let pkg = fixture("require('./safe.js');\n");
    let bins = tempfile::tempdir().unwrap();
    write(
        bins.path(),
        "node",
        &format!(
            "#!/bin/sh\nprintf '\\nE2T %s\\nE2T %s\\nE2T RUN-COMPLETE\\n' {} {}\n",
            shell_quote(&pkg.path().join("index.js")),
            shell_quote(&pkg.path().join("safe.js")),
        ),
    );
    std::fs::set_permissions(
        bins.path().join("node"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let output = run_probe(pkg.path(), bins.path().as_os_str(), "inconclusive");
    assert!(
        output.status.success(),
        "CJS probe without the ESM hook was accepted: {output:?}"
    );
}

fn incomplete_hint_records() -> Vec<serde_json::Value> {
    let good = serde_json::json!({"database_specific":{"vulnerable_files":["vuln.js"]}});
    [
        serde_json::json!({}),
        serde_json::json!({"database_specific":null}),
        serde_json::json!({"database_specific":{"vulnerable_files":[]}}),
        serde_json::json!({"database_specific":{"vulnerable_files":"vuln.js"}}),
        serde_json::json!({"database_specific":{"vulnerable_files":["vuln.js",null]}}),
        serde_json::json!({"database_specific":{"vulnerable_files":["vuln.js"," "]}}),
        serde_json::json!({"database_specific":{"vulnerable_files":["vuln.js"],"files":false}}),
        serde_json::json!({"database_specific":{"vulnerable_files":["vuln.js"]},"ecosystem_specific":null}),
    ]
    .into_iter()
    .map(|partial| serde_json::json!({"affected":[good,partial]}))
    .collect()
}

#[test]
fn e1_record_hints_must_cover_every_supplied_record() {
    let pkg = fixture("require('./safe.js');\n");
    for advisory in incomplete_hint_records() {
        assert_eq!(
            e1::evidence_level(pkg.path(), &advisory, ConsumerModel::Esm).0,
            "E0",
            "partial hints: {advisory}"
        );
    }
}

#[test]
fn e2_record_hints_must_cover_every_supplied_record() {
    let pkg = fixture("require('./safe.js');\n");
    for advisory in incomplete_hint_records() {
        assert_eq!(
            e2::evidence_level_e2(pkg.path(), &advisory, &pkg.path().join("index.js")).0,
            "E0",
            "partial hints: {advisory}"
        );
    }
}

#[test]
fn e2_record_hints_accept_complete_records_without_changing_the_library_api() {
    let pkg = fixture("require('./safe.js');\n");
    write(pkg.path(), "other-vuln.js", "module.exports = 3;\n");
    let advisory = serde_json::json!({"affected":[
        {"database_specific":{"vulnerable_files":["package/vuln.js"]}},
        {"ecosystem_specific":{"paths":["./other-vuln.js"]}}
    ]});
    assert_eq!(
        e1::evidence_level(pkg.path(), &advisory, ConsumerModel::Esm).0,
        "E1"
    );
    assert_eq!(
        e2::evidence_level_e2(pkg.path(), &advisory, &pkg.path().join("index.js")).0,
        "E2"
    );
}

#[test]
fn e2_forged_completion_before_process_exit_is_not_evidence() {
    for exit in ["exit", "reallyExit"] {
        let pkg = fixture(&format!(
            "process.stdout.write('\\nE2T RUN-COMPLETE\\n'); process.{exit}(0);\n"
        ));
        let advisory = serde_json::json!({"affected":[{"database_specific":{"vulnerable_files":["vuln.js"]}}]});
        assert_eq!(
            e2::evidence_level_e2(pkg.path(), &advisory, &pkg.path().join("index.js")).0,
            "E0",
            "early process.{exit}(0) must not become E2"
        );
        assert!(matches!(
            trace_loaded_files(pkg.path(), &pkg.path().join("index.js")),
            E2Outcome::Inconclusive
        ));
    }
}

#[test]
fn e2_relative_path_is_resolved_before_entering_the_package() {
    let node = real_node();
    let pkg = fixture("require('./safe.js');\n");
    let bins = tempfile::tempdir().unwrap();
    std::fs::create_dir(bins.path().join("relative-bin")).unwrap();
    std::os::unix::fs::symlink(node, bins.path().join("relative-bin/node")).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "e2_probe_child", "--ignored", "--nocapture"])
        .current_dir(bins.path())
        .env("PATH", "relative-bin")
        .env("OWN_E2_CHILD_ROOT", pkg.path())
        .env("OWN_E2_CHILD_EXPECT", "loaded")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn e2_missing_node_does_not_fall_back_to_a_system_node() {
    let pkg = fixture("require('./safe.js');\n");
    let bins = tempfile::tempdir().unwrap();
    let output = run_probe(pkg.path(), bins.path().as_os_str(), "inconclusive");
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn e2_incomplete_or_over_budget_probes_remain_inconclusive() {
    for source in [
        "throw new Error('incomplete');\n",
        "process.exit(0);\n",
        "process.stdout.write(Buffer.from([255])); require('./safe.js');\n",
        "process.stdout.write('x'.repeat(8 * 1024 * 1024 + 1)); require('./safe.js');\n",
    ] {
        let pkg = fixture(source);
        let start = std::time::Instant::now();
        assert!(
            matches!(
                trace_loaded_files(pkg.path(), &pkg.path().join("index.js")),
                E2Outcome::Inconclusive
            ),
            "incomplete source accepted: {source}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "probe did not terminate promptly: {source}"
        );
    }
}

#[test]
fn e2_timeout_stays_at_ten_seconds_and_is_not_evidence() {
    let pkg = fixture("require('./safe.js'); setInterval(() => {}, 50);\n");
    let start = std::time::Instant::now();
    assert!(matches!(
        trace_loaded_files(pkg.path(), &pkg.path().join("index.js")),
        E2Outcome::Inconclusive
    ));
    assert!(start.elapsed() >= std::time::Duration::from_secs(10));
    assert!(start.elapsed() < std::time::Duration::from_secs(12));
}

#[test]
fn e2_keeps_network_child_process_and_file_writes_denied() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let pkg = fixture(&format!(
        "require('net').connect({}, '127.0.0.1');\n",
        address.port()
    ));
    assert!(matches!(
        trace_loaded_files(pkg.path(), &pkg.path().join("index.js")),
        E2Outcome::Inconclusive
    ));
    assert!(listener
        .accept()
        .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock));
    let pkg = fixture("require('child_process').execFileSync('/bin/true');\n");
    assert!(matches!(
        trace_loaded_files(pkg.path(), &pkg.path().join("index.js")),
        E2Outcome::Inconclusive
    ));
    let pkg = fixture("require('fs').writeFileSync('must-not-exist.txt', 'test');\n");
    assert!(matches!(
        trace_loaded_files(pkg.path(), &pkg.path().join("index.js")),
        E2Outcome::Inconclusive
    ));
    assert!(!pkg.path().join("must-not-exist.txt").exists());
}

#[test]
fn e2_esm_trace_is_complete_and_named_process_exit_cannot_forge_it() {
    let pkg = fixture("require('./safe.js');\n");
    write(
        pkg.path(),
        "package.json",
        r#"{"name":"fixture","main":"index.mjs"}"#,
    );
    write(
        pkg.path(),
        "index.mjs",
        "import './safe.js'; await Promise.resolve(); export default 1;\n",
    );
    match trace_loaded_files(pkg.path(), &pkg.path().join("index.mjs")) {
        E2Outcome::Loaded(files) => {
            assert!(files.contains("index.mjs") && files.contains("safe.js"));
            assert!(!files.contains("vuln.js"));
        }
        E2Outcome::Inconclusive => panic!("complete ESM entry should be traced"),
    }
    write(pkg.path(), "index.mjs", "import { exit } from 'node:process'; process.stdout.write('\\nE2T RUN-COMPLETE\\n'); exit(0);\n");
    assert!(matches!(
        trace_loaded_files(pkg.path(), &pkg.path().join("index.mjs")),
        E2Outcome::Inconclusive
    ));
}
