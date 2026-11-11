//! `own diff <pkg>@<old> <pkg>@<new>` (SPEC §8.2): compare two vendored dirs
//! (or two cache tarballs with --from-cache) and emit risk signals.
//!
//! Tree-sitter proper lands when the grammars are vendored; for 0.2 the signal
//! detection is a robust lexer-level scan over .js/.mjs/.cjs/.jsx/.ts/.mts/.cts/.tsx
//! (SPEC §8.2 signal list), which is what the tests assert.

use own_core::lock::{parse_lock, Lock};
use serde_json::{json, Value};
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

fn scan_pkg_json(old: &str, new: &str, path: &str, out: &mut Vec<Signal>) {
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
    let o: Value = serde_json::from_str(old).unwrap_or(json!({}));
    let n: Value = serde_json::from_str(new).unwrap_or(json!({}));
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
}

fn list_files(root: &Path) -> Vec<(String, String, u64)> {
    let mut out = Vec::new();
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, String, u64)>) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, base, out);
                } else if p.is_file() {
                    if let Ok(rel) = p.strip_prefix(base) {
                        let rel = rel.to_string_lossy().replace('\\', "/");
                        let h = own_core::sha256_hex(&std::fs::read(&p).unwrap_or_default());
                        let sz = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                        out.push((rel, h, sz));
                    }
                }
            }
        }
    }
    walk(root, root, &mut out);
    out.sort();
    out
}

pub fn diff_dirs(root: &Path, old_dir: &str, new_dir: &str) -> Result<DiffReport, String> {
    let old = list_files(&root.join(old_dir));
    let new = list_files(&root.join(new_dir));
    let old_map: std::collections::HashMap<&str, &String> =
        old.iter().map(|(p, h, _)| (p.as_str(), h)).collect();
    let new_map: std::collections::HashMap<&str, &String> =
        new.iter().map(|(p, h, _)| (p.as_str(), h)).collect();
    let mut added: Vec<String> = Vec::new();
    let mut removed: Vec<String> = Vec::new();
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
    for (p, _, _) in &old {
        if !new_map.contains_key(p.as_str()) {
            removed.push(p.clone());
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
            if let Ok(content) = std::fs::read_to_string(&full) {
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
        }
        if p == "package.json" {
            let old_content =
                std::fs::read_to_string(root.join(old_dir).join(p)).unwrap_or_default();
            let new_content = std::fs::read_to_string(&full).unwrap_or_default();
            scan_pkg_json(&old_content, &new_content, p, &mut signals);
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
        );
        assert!(sigs
            .iter()
            .any(|s| s.kind == "package_json" && s.name == "scripts"));
    }
}
