//! `own diff <pkg>@<old> <pkg>@<new>` (SPEC §8.2): compare two vendored dirs
//! (or two cache tarballs with --from-cache) and emit risk signals.
//!
//! Tree-sitter proper lands when the grammars are vendored; for 0.2 the signal
//! detection is a robust lexer-level scan over .js/.mjs/.cjs/.jsx/.ts/.mts/.cts/.tsx
//! (SPEC §8.2 signal list), which is what the tests assert.

use own_core::lock::{parse_lock, Lock};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Signal {
    pub kind: String,
    pub name: String,
    pub path: String,
    pub line: usize,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DiffReport {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    pub renamed: Vec<(String, String)>,
    pub signals: Vec<Signal>,
}

const JS_EXTS: [&str; 8] = ["js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx"];
const RISKY_FILES: [&str; 5] = [".node", ".wasm", ".sh", ".exe", "binding.gyp"];
const DANGEROUS_MODULES: [&str; 10] = [
    "child_process",
    "net",
    "dns",
    "fs",
    "crypto",
    "http",
    "https",
    "worker_threads",
    "vm",
    "os",
];
const DANGEROUS_GLOBALS: [&str; 8] = [
    "eval(",
    "new Function",
    "Function(",
    "process.exit",
    "process.kill",
    "process.env",
    "process.binding",
    "fetch(",
];

fn is_js(path: &str) -> bool {
    path.rsplit('.')
        .next()
        .map(|e| JS_EXTS.contains(&e))
        .unwrap_or(false)
}

fn scan_js_signals(content: &str, path: &str) -> Vec<Signal> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let ln = i + 1;
        // static imports/requires of dangerous modules (prefix node: allowed to name but flag)
        for m in DANGEROUS_MODULES {
            for pat in [
                format!("require(\"{m}\")"),
                format!("require('{m}')"),
                format!("from \"{m}\""),
                format!("from '{m}'"),
                format!("require(\"node:{m}\")"),
                format!("from \"node:{m}\""),
                format!("import(\"{m}\")"),
                format!("import(\"node:{m}\")"),
            ] {
                if line.contains(&pat) {
                    out.push(Signal {
                        kind: "import".into(),
                        name: m.into(),
                        path: path.into(),
                        line: ln,
                    });
                }
            }
        }
        // dynamic require/import with non-literal
        if line.contains("require(") || line.contains("import(") {
            // crude: contains a variable — look for require( followed by something not a quote
            for (idx, _) in line.match_indices("require(") {
                let rest = &line[idx + 8..];
                let rest = rest.trim_start();
                if !rest.starts_with('"') && !rest.starts_with('\'') && !rest.starts_with('`') {
                    out.push(Signal {
                        kind: "dynamic_require".into(),
                        name: "dynamic_require".into(),
                        path: path.into(),
                        line: ln,
                    });
                    break;
                }
            }
        }
        for g in DANGEROUS_GLOBALS {
            if line.contains(g) {
                out.push(Signal {
                    kind: "api".into(),
                    name: g.trim_end_matches('(').to_string(),
                    path: path.into(),
                    line: ln,
                });
            }
        }
        if line.contains("XMLHttpRequest") || line.contains("WebSocket") {
            out.push(Signal {
                kind: "api".into(),
                name: "net".into(),
                path: path.into(),
                line: ln,
            });
        }
    }
    out
}

fn scan_pkg_json(old: &str, new: &str, path: &str, out: &mut Vec<Signal>) -> Result<(), String> {
    let fields = [
        "scripts",
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "license",
        "bin",
        "os",
        "cpu",
        "main",
        "module",
        "exports",
        "type",
    ];
    let o: Value =
        serde_json::from_str(old).map_err(|e| format!("PARSE_ERROR: old {path}: {e}"))?;
    let n: Value =
        serde_json::from_str(new).map_err(|e| format!("PARSE_ERROR: new {path}: {e}"))?;
    if !o.is_object() || !n.is_object() {
        return Err(format!("PARSE_ERROR: {path}: expected an object"));
    }
    for f in fields {
        if o.get(f) != n.get(f) {
            out.push(Signal {
                kind: "package_json".into(),
                name: f.into(),
                path: path.into(),
                line: 0,
            });
        }
    }
    Ok(())
}

fn list_files(root: &Path) -> Result<Vec<(String, String, u64)>, String> {
    let mut out = Vec::new();
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, String, u64)>) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(dir)
            .map_err(|e| format!("IO_ERROR: {}: {e}", dir.display()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!("IO_ERROR: {}: unsafe directory", dir.display()));
        }
        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("IO_ERROR: {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("IO_ERROR: {}: {e}", dir.display()))?;
            let p = entry.path();
            let metadata = std::fs::symlink_metadata(&p)
                .map_err(|e| format!("IO_ERROR: {}: {e}", p.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!("IO_ERROR: {}: symlink refused", p.display()));
            }
            if metadata.is_dir() {
                walk(&p, base, out)?;
            } else if metadata.is_file() {
                let rel = p
                    .strip_prefix(base)
                    .ok()
                    .and_then(Path::to_str)
                    .ok_or_else(|| format!("IO_ERROR: {}: invalid path", p.display()))?;
                let bytes =
                    std::fs::read(&p).map_err(|e| format!("IO_ERROR: {}: {e}", p.display()))?;
                out.push((
                    rel.replace('\\', "/"),
                    own_core::sha256_hex(&bytes),
                    bytes.len() as u64,
                ));
            } else {
                return Err(format!("IO_ERROR: {}: special file refused", p.display()));
            }
        }
        Ok(())
    }
    walk(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

pub fn diff_dirs(root: &Path, old_dir: &str, new_dir: &str) -> Result<DiffReport, String> {
    let old_root = own_core::path_safety::project_path(root, old_dir)
        .map_err(|e| format!("IO_ERROR: {old_dir}: {e}"))?;
    let new_root = own_core::path_safety::project_path(root, new_dir)
        .map_err(|e| format!("IO_ERROR: {new_dir}: {e}"))?;
    let old = list_files(&old_root)?;
    let new = list_files(&new_root)?;
    let old_map: std::collections::HashMap<&str, &String> =
        old.iter().map(|(p, h, _)| (p.as_str(), h)).collect();
    let new_map: std::collections::HashMap<&str, &String> =
        new.iter().map(|(p, h, _)| (p.as_str(), h)).collect();
    let mut added: Vec<String> = Vec::new();
    let mut removed: Vec<String> = old
        .iter()
        .filter(|(p, _, _)| !new_map.contains_key(p.as_str()))
        .map(|(p, _, _)| p.clone())
        .collect();
    let mut modified: Vec<String> = Vec::new();
    let mut renamed: Vec<(String, String)> = Vec::new();
    for (p, h, _) in &new {
        match old_map.get(p.as_str()) {
            None => {
                // renamed? same hash elsewhere removed
                let match_old = removed
                    .iter()
                    .find(|op| old_map.get(op.as_str()).copied() == Some(h))
                    .cloned();
                if let Some(oldp) = match_old {
                    renamed.push((oldp.clone(), p.clone()));
                    removed.retain(|x| x != &oldp);
                } else {
                    added.push(p.clone());
                }
            }
            Some(oh) if oh != &h => modified.push(p.clone()),
            _ => {}
        }
    }
    // signals on added/modified JS + risky files + package.json
    let mut signals = Vec::new();
    let changed: Vec<&String> = added.iter().chain(modified.iter()).collect();
    for p in changed {
        let full = root.join(new_dir).join(p);
        if RISKY_FILES.iter().any(|e| p.ends_with(e)) {
            signals.push(Signal {
                kind: "risky_file".into(),
                name: p.rsplit('/').next().unwrap_or(p).to_string(),
                path: p.clone(),
                line: 0,
            });
            continue;
        }
        if is_js(p) {
            let content = std::fs::read_to_string(&full)
                .map_err(|e| format!("IO_ERROR: {}: {e}", full.display()))?;
            if content.len() <= 2 * 1_048_576 {
                signals.extend(scan_js_signals(&content, p));
            } else {
                signals.push(Signal {
                    kind: "too_large_to_parse".into(),
                    name: "parse".into(),
                    path: p.clone(),
                    line: 0,
                });
            }
        }
        if p == "package.json" {
            let old_content = if old_map.contains_key(p.as_str()) {
                let old_path = old_root.join(p);
                std::fs::read_to_string(&old_path)
                    .map_err(|e| format!("IO_ERROR: {}: {e}", old_path.display()))?
            } else {
                "{}".to_string()
            };
            let new_content = std::fs::read_to_string(&full)
                .map_err(|e| format!("IO_ERROR: {}: {e}", full.display()))?;
            scan_pkg_json(&old_content, &new_content, p, &mut signals)?;
        }
    }
    signals.sort_by(|a, b| {
        (a.kind.as_str(), a.path.as_str(), a.line).cmp(&(b.kind.as_str(), b.path.as_str(), b.line))
    });
    Ok(DiffReport {
        added,
        removed,
        modified,
        renamed,
        signals,
    })
}

/// Resolve `<pkg>@<ver>` to a vendored dir from own.lock.
pub fn resolve_dir(root: &Path, spec: &str) -> Result<String, String> {
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock: Lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let (name, ver) = split_spec(spec);
    let found: Option<String> = lock
        .packages
        .iter()
        .find(|p| p.name == name && p.version == ver)
        .map(|p| p.dir.clone());
    found.ok_or_else(|| "PACKAGE_NOT_VENDORED".to_string())
}

pub fn split_spec(spec: &str) -> (String, String) {
    if spec.starts_with('@') {
        match spec.rfind('@') {
            Some(i) if i > 0 => (spec[..i].to_string(), spec[i + 1..].to_string()),
            _ => (spec.to_string(), String::new()),
        }
    } else {
        match spec.split_once('@') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => (spec.to_string(), String::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "own-diff-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(root.join("old")).unwrap();
            std::fs::create_dir_all(root.join("new")).unwrap();
            Self(root)
        }

        fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
            std::fs::write(self.0.join(path), bytes).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn diff_renames_identical_files_one_to_one_deterministically() {
        let f = Fixture::new();
        f.write("old/b.js", "same bytes");
        f.write("old/a.js", "same bytes");
        f.write("new/z.js", "same bytes");
        f.write("new/y.js", "same bytes");
        f.write("new/x.js", "same bytes");
        let report = diff_dirs(&f.0, "old", "new").unwrap();
        assert_eq!(
            report.renamed,
            vec![
                ("a.js".into(), "x.js".into()),
                ("b.js".into(), "y.js".into())
            ]
        );
        assert_eq!(report.added, vec!["z.js"]);
        assert!(report.removed.is_empty());
        assert!(report.modified.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn diff_io_error_never_reports_missing_unreadable_or_unsafe_trees_as_clean() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let mut masked = Vec::new();
        for case in [
            "missing",
            "file_root",
            "unreadable_file",
            "unreadable_dir",
            "dangling",
            "outside",
            "special",
            "escape",
        ] {
            let f = Fixture::new();
            let mut socket = None;
            let mut old = "old";
            match case {
                "missing" => std::fs::remove_dir(f.0.join("old")).unwrap(),
                "file_root" => {
                    std::fs::remove_dir(f.0.join("old")).unwrap();
                    f.write("old", "not a directory");
                }
                "unreadable_file" | "unreadable_dir" => {
                    if unsafe { libc::geteuid() } == 0 {
                        continue;
                    }
                    f.write("old/a.txt", "must not hash empty bytes");
                    let path = if case == "unreadable_file" {
                        "old/a.txt"
                    } else {
                        "old"
                    };
                    std::fs::set_permissions(f.0.join(path), std::fs::Permissions::from_mode(0o0))
                        .unwrap();
                }
                "dangling" => symlink("absent", f.0.join("old/link")).unwrap(),
                "outside" => {
                    f.write("secret", "outside tree");
                    symlink("../secret", f.0.join("old/link")).unwrap();
                }
                "special" => {
                    socket = Some(
                        std::os::unix::net::UnixListener::bind(f.0.join("old/socket")).unwrap(),
                    );
                }
                "escape" => old = "../",
                _ => unreachable!(),
            }
            // Avoid traversing the temp directory in the unfixed implementation.
            let result = if case == "escape" {
                diff_dirs(&f.0, "old/../new", "new")
            } else {
                diff_dirs(&f.0, old, "new")
            };
            if !matches!(&result, Err(e) if e.starts_with("IO_ERROR:")) {
                masked.push(format!("{case}: {result:?}"));
            }
            if case == "unreadable_dir" {
                std::fs::set_permissions(f.0.join("old"), std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            drop(socket);
        }
        assert!(masked.is_empty(), "masked errors: {masked:#?}");
    }

    #[test]
    fn diff_io_error_invalid_utf8_js_cannot_silently_skip_risk_scan() {
        let f = Fixture::new();
        f.write("new/a.js", b"eval(code);\xff");
        let result = diff_dirs(&f.0, "old", "new");
        assert!(
            matches!(&result, Err(e) if e.starts_with("IO_ERROR:") && e.contains("a.js")),
            "{result:?}"
        );
    }

    #[test]
    fn diff_parse_error_malformed_package_json_is_not_an_empty_object() {
        let mut masked = Vec::new();
        for (old, new) in [
            (Some("broken"), "{}"),
            (Some("{}"), "broken"),
            (None, "[]"),
            (None, "broken"),
        ] {
            let f = Fixture::new();
            if let Some(old) = old {
                f.write("old/package.json", old);
            }
            f.write("new/package.json", new);
            let result = diff_dirs(&f.0, "old", "new");
            if !matches!(&result, Err(e) if e.starts_with("PARSE_ERROR:") && e.contains("package.json"))
            {
                masked.push(format!("{old:?} -> {new}: {result:?}"));
            }
        }
        assert!(masked.is_empty(), "masked errors: {masked:#?}");
    }

    #[test]
    fn detects_require_fs_and_eval() {
        let sigs = scan_js_signals("const fs = require(\"fs\");\neval(code);\n", "a.js");
        let kinds: Vec<&str> = sigs.iter().map(|s| s.kind.as_str()).collect();
        assert!(kinds.contains(&"import"));
        assert!(kinds.contains(&"api"));
        assert!(sigs.iter().any(|s| s.name == "eval"));
    }

    #[test]
    fn dynamic_require_flagged() {
        let sigs = scan_js_signals("const m = mod; require(m);\n", "a.js");
        assert!(sigs.iter().any(|s| s.kind == "dynamic_require"));
    }

    #[test]
    fn package_json_script_change_flagged() {
        let mut sigs = Vec::new();
        scan_pkg_json(
            r#"{"scripts":{}}"#,
            r#"{"scripts":{"postinstall":"x"}}"#,
            "package.json",
            &mut sigs,
        )
        .unwrap();
        assert!(sigs
            .iter()
            .any(|s| s.kind == "package_json" && s.name == "scripts"));
    }
}
