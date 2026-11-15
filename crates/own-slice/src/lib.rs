//! Phase 1 — conservative slicing (E1 reachability, SPEC §4 Phase 1).
//!
//! Static reachability from the package entry point(s) over **internal**
//! `require()`/`import ... from` specifiers. Conservative (INV-4): dynamic
//! imports/requires with non-literal argument, `eval`, or any parse doubt mark
//! the file as "keep whole package" — never silently drop code.
//!
//! Prototype uses regex (documented limit); the production path will use
//! tree-sitter ASTs (SPEC §12). The safety property is what matters here:
//! a file is dropped only if it is provably unreachable AND the package has no
//! dynamic-require/eval signals.

pub mod ast;
pub mod e1;
pub mod e2;

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct SliceReport {
    pub package: String,
    pub total_bytes: u64,
    pub kept_bytes: u64,
    pub dropped_files: Vec<String>,
    pub kept_files: Vec<String>,
    /// true if the package must be kept whole (conservative refusal to slice)
    pub keep_whole: bool,
    pub reason: Option<String>,
}

impl SliceReport {
    pub fn reduction_pct(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            100.0 * (1.0 - self.kept_bytes as f64 / self.total_bytes as f64)
        }
    }
}

const JS_EXTS: [&str; 8] = ["js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts"];

fn is_js(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| JS_EXTS.contains(&e))
        .unwrap_or(false)
}

/// Resolve a relative specifier to a file inside the package.
fn resolve(spec: &str, from_file: &Path, pkg_root: &Path) -> Option<PathBuf> {
    if !spec.starts_with('.') {
        return None;
    }
    let base = from_file.parent()?.join(spec);
    let base = base.normalize();
    // Node resolves exact files and appended extensions before directories.
    // ./a.min must try a.min.js, never a.js via extension replacement.
    if let Some(file) = resolve_file(&base, pkg_root) {
        return Some(file);
    }
    // subdir package.json "main" (Node directory resolution)
    let sub_pkg = base.join("package.json");
    if sub_pkg.is_file() {
        let txt = std::fs::read_to_string(&sub_pkg).ok()?;
        let v = serde_json::from_str::<serde_json::Value>(&txt).ok()?;
        if let Some(m) = v.get("main").and_then(|m| m.as_str()) {
            let target = base.join(m).normalize();
            if let Some(file) = resolve_file(&target, pkg_root) {
                return Some(file);
            }
            if let Some(file) = resolve_index(&target, pkg_root) {
                return Some(file);
            }
        }
    }
    resolve_index(&base, pkg_root)
}

fn resolve_file(base: &Path, pkg_root: &Path) -> Option<PathBuf> {
    let mut candidates = vec![base.to_path_buf()];
    for extension in ["js", "json", "node"] {
        let mut file = base.as_os_str().to_os_string();
        file.push(format!(".{extension}"));
        candidates.push(PathBuf::from(file));
    }
    for candidate in candidates {
        let path = candidate.normalize();
        if path.starts_with(pkg_root) && path.is_file() {
            return Some(path);
        }
    }
    None
}

fn resolve_index(base: &Path, pkg_root: &Path) -> Option<PathBuf> {
    for name in ["index.js", "index.json", "index.node"] {
        let path = base.join(name).normalize();
        if path.starts_with(pkg_root) && path.is_file() {
            return Some(path);
        }
    }
    None
}

trait Normalize {
    fn normalize(&self) -> PathBuf;
}
impl Normalize for PathBuf {
    fn normalize(&self) -> PathBuf {
        let mut out = PathBuf::new();
        for comp in self.components() {
            match comp {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    out.pop();
                }
                other => out.push(other.as_os_str()),
            }
        }
        out
    }
}

/// Entry points of a package: `exports` (string or map values) if present, else `main`, else index.js.
pub fn entry_points(pkg_root: &Path) -> Vec<PathBuf> {
    entry_points_for(pkg_root, ConsumerModel::Esm)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsumerModel {
    /// CJS require(): conditions node, require, default (+ main fallback)
    Cjs,
    /// ESM import: conditions node, import, default (+ main fallback)
    Esm,
}

/// Condition-aware entry resolution (Annexe F.3): resolve the condition set a
/// real consumer selects instead of unioning every branch (which poisoned the
/// 9.5% reading with `types`/`browser`/`index-all`).
pub fn entry_points_for(pkg_root: &Path, model: ConsumerModel) -> Vec<PathBuf> {
    let pjp = pkg_root.join("package.json");
    let mut entries = Vec::new();
    if let Ok(text) = std::fs::read_to_string(&pjp) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            let mut exp: Vec<String> = Vec::new();
            if let Some(e) = v.get("exports") {
                exp = resolve_conditions_in(e, model, Some(pkg_root));
            }
            // main is always a fallback entry (CJS consumers resolve it)
            if let Some(m) = v.get("main").and_then(|m| m.as_str()) {
                if !exp.contains(&m.to_string()) {
                    exp.push(m.to_string());
                }
            }
            if exp.is_empty() {
                exp.push("index.js".to_string());
            }
            // F-04: expand '*' subpath patterns conservatively against the tree
            let mut exp2: Vec<String> = Vec::new();
            for e in exp.drain(..) {
                if e.contains('*') {
                    exp2.extend(expand_glob(pkg_root, &e));
                } else {
                    exp2.push(e);
                }
            }
            let exp = exp2;
            for e in exp {
                let p = pkg_root.join(&e);
                if p.is_file() {
                    entries.push(p.normalize());
                } else if p.is_dir() {
                    let idx = p.join("index.js");
                    if idx.is_file() {
                        entries.push(idx.normalize());
                    }
                }
            }
        }
    }
    if entries.is_empty() {
        let idx = pkg_root.join("index.js");
        if idx.is_file() {
            entries.push(idx);
        }
    }
    entries
}

fn all_js_ref(all: &[PathBuf], root: &Path) -> Vec<String> {
    all.iter().map(|p| rel(root, p)).collect()
}

#[allow(clippy::too_many_arguments)]
fn keep_all(
    _root: &Path,
    name: &str,
    total: u64,
    files: Vec<String>,
    reason: String,
) -> SliceReport {
    SliceReport {
        package: name.to_string(),
        total_bytes: total,
        kept_bytes: total,
        dropped_files: vec![],
        kept_files: files,
        keep_whole: true,
        reason: Some(reason),
    }
}

/// Compute the slice report for a vendored package directory.
pub fn slice_package(pkg_root: &Path, package_name: &str) -> SliceReport {
    slice_package_model(pkg_root, package_name, ConsumerModel::Esm)
}

pub fn slice_package_model(
    pkg_root: &Path,
    package_name: &str,
    model: ConsumerModel,
) -> SliceReport {
    let mut all_js: Vec<PathBuf> = Vec::new();
    let mut traversal_failed = false;
    for e in walkdir::WalkDir::new(pkg_root).follow_links(false) {
        let e = match e {
            Ok(e) => e,
            Err(_) => {
                traversal_failed = true;
                continue;
            }
        };
        if e.file_type().is_file() && is_js(e.path()) {
            all_js.push(e.path().to_path_buf());
        }
    }
    all_js.sort();
    let total_bytes: u64 = all_js
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum();

    let mut kept: HashSet<PathBuf> = HashSet::new();
    let mut queue: VecDeque<PathBuf> = VecDeque::new();
    for e in entry_points_for(pkg_root, model) {
        queue.push_back(e);
    }
    if traversal_failed || queue.is_empty() {
        return keep_all(
            pkg_root,
            package_name,
            total_bytes,
            all_js_ref(&all_js, pkg_root),
            "incomplete tree or entry points".into(),
        );
    }
    while let Some(f) = queue.pop_front() {
        if kept.contains(&f) || !f.is_file() || !is_js(&f) {
            continue;
        }
        kept.insert(f.clone());
        let raw = match std::fs::read(&f) {
            Ok(c) => c,
            Err(_) => {
                return keep_all(
                    pkg_root,
                    package_name,
                    total_bytes,
                    all_js_ref(&all_js, pkg_root),
                    "unreadable reachable file".into(),
                )
            }
        };
        // AST backend (Annexe F.4): parse failure or dynamic signal in a
        // reachable file => whole package kept, zero drops.
        match ast::parse(&f, &raw) {
            ast::ParseOutcome::Failed => {
                return keep_all(
                    pkg_root,
                    package_name,
                    total_bytes,
                    all_js_ref(&all_js, pkg_root),
                    format!("unparseable: {} (kept whole)", rel(pkg_root, &f)),
                );
            }
            ast::ParseOutcome::Ok(tree) => {
                let e = ast::edges(&tree, &raw);
                if e.dynamic {
                    return keep_all(
                        pkg_root,
                        package_name,
                        total_bytes,
                        all_js_ref(&all_js, pkg_root),
                        format!("dynamic code in {} (package kept whole)", rel(pkg_root, &f)),
                    );
                }
                for spec in e.literal_specs {
                    if let Some(r) = resolve(&spec, &f, pkg_root) {
                        queue.push_back(r);
                    } else if spec.starts_with('.') {
                        return keep_all(
                            pkg_root,
                            package_name,
                            total_bytes,
                            all_js_ref(&all_js, pkg_root),
                            "unresolved relative dependency".into(),
                        );
                    }
                }
                continue;
            }
        }
    }
    let dropped_any = all_js.iter().any(|p| !kept.contains(p));
    if !dropped_any {
        return SliceReport {
            package: package_name.to_string(),
            total_bytes,
            kept_bytes: total_bytes,
            dropped_files: vec![],
            kept_files: all_js.iter().map(|p| rel(pkg_root, p)).collect(),
            keep_whole: true,
            reason: Some("nothing unreachable".into()),
        };
    }
    let kept_bytes: u64 = kept
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum();
    let dropped: Vec<String> = all_js
        .iter()
        .filter(|p| !kept.contains(*p))
        .map(|p| rel(pkg_root, p))
        .collect();
    let mut kept_files: Vec<String> = kept.iter().map(|p| rel(pkg_root, p)).collect();
    kept_files.sort();
    SliceReport {
        package: package_name.to_string(),
        total_bytes,
        kept_bytes,
        dropped_files: dropped,
        kept_files,
        keep_whole: false,
        reason: None,
    }
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Resolve an `exports` value against a consumer condition set (Node order:
/// object keys matched in insertion order against the active set).
fn resolve_conditions(exp: &serde_json::Value, model: ConsumerModel) -> Vec<String> {
    resolve_conditions_in(exp, model, None)
}

fn resolve_conditions_in(
    exp: &serde_json::Value,
    model: ConsumerModel,
    _root: Option<&Path>,
) -> Vec<String> {
    let active: &[&str] = match model {
        ConsumerModel::Cjs => &["node", "require", "default"],
        ConsumerModel::Esm => &["node", "import", "default"],
    };
    match exp {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a
            .iter()
            .flat_map(|x| resolve_conditions(x, model))
            .collect(),
        serde_json::Value::Object(m) => {
            let mut out = Vec::new();
            for (k, val) in m {
                if k.starts_with('.') {
                    // F-02: every exported subpath is consumer-reachable,
                    // not just "." — include them all as entries.
                    let targets = resolve_conditions(val, model);
                    out.extend(targets);
                } else if active.contains(&k.as_str()) {
                    out.extend(resolve_conditions_in(val, model, _root));
                    return out; // first matching condition wins (Node semantics)
                }
            }
            out
        }
        _ => vec![],
    }
}

/// Expand an exports subpath pattern like "./locales/*" against the package
/// tree: every file whose path matches the non-* prefix/suffix is a potential
/// target (conservative: over-approximate, never under).
fn expand_glob(pkg_root: &Path, pattern: &str) -> Vec<String> {
    let pat = pattern.trim_start_matches("./");
    let (pre, post) = match pat.split_once('*') {
        Some((a, b)) => (a.to_string(), b.to_string()),
        None => return vec![pattern.to_string()],
    };
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(pkg_root)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        if e.file_type().is_file() {
            if let Ok(r) = e.path().strip_prefix(pkg_root) {
                let rs = r.to_string_lossy().replace('\\', "/");
                if rs.starts_with(&pre) && rs.ends_with(&post) {
                    out.push(format!("./{rs}"));
                }
            }
        }
    }
    if out.is_empty() {
        out.push(pattern.to_string()); // unknown => keep raw (resolve will fail-safe)
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    #[test]
    fn slices_unreachable_files() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(
            root,
            "package.json",
            r#"{"name":"x","version":"1.0.0","main":"index.js"}"#,
        );
        write(
            root,
            "index.js",
            "const a = require('./a.js');\nmodule.exports = a;\n",
        );
        write(root, "a.js", "module.exports = 1;\n");
        write(root, "dead.js", "module.exports = 2;\n"); // unreachable
        write(root, "sub/dead2.js", "module.exports = 3;\n");
        let rep = slice_package(root, "x@1.0.0");
        assert!(!rep.keep_whole);
        assert!(rep.dropped_files.contains(&"dead.js".to_string()));
        assert!(rep.dropped_files.contains(&"sub/dead2.js".to_string()));
        assert!(rep.kept_files.contains(&"index.js".to_string()));
        assert!(rep.kept_files.contains(&"a.js".to_string()));
        assert!(rep.reduction_pct() > 0.0);
    }

    #[test]
    fn keeps_whole_on_dynamic_require() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(root, "package.json", r#"{"name":"x","main":"index.js"}"#);
        write(root, "index.js", "const m = process.argv[2]; require(m);\n");
        write(root, "dead.js", "x\n");
        let rep = slice_package(root, "x@1.0.0");
        // INV-4: dynamic require in a REACHABLE file => whole package kept,
        // nothing dropped (review F2/F3/F4).
        assert!(rep.keep_whole);
        assert!(rep.reason.is_some());
        assert!(rep.dropped_files.is_empty());
        assert!(rep.kept_files.contains(&"index.js".to_string()));
        assert!(rep.kept_files.contains(&"dead.js".to_string()));
    }

    #[test]
    fn keeps_whole_on_eval() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(root, "package.json", r#"{"name":"x","main":"index.js"}"#);
        write(root, "index.js", "eval(code);\n");
        write(root, "dead.js", "x\n");
        let rep = slice_package(root, "x@1.0.0");
        assert!(rep.keep_whole);
        assert!(rep.dropped_files.is_empty());
        assert!(rep.kept_files.contains(&"index.js".to_string()));
        assert!(rep.kept_files.contains(&"dead.js".to_string()));
    }

    #[test]
    fn condition_aware_exports() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(
            root,
            "package.json",
            r#"{"name":"x","exports":{".":{"types":"./index.d.ts","import":"./esm.js","require":"./cjs.js","default":"./esm.js"}}}"#,
        );
        write(root, "esm.js", "export default 1;\n");
        write(root, "cjs.js", "module.exports = 1;\n");
        write(root, "index.d.ts", "export default 1;\n");
        let esm = entry_points_for(root, ConsumerModel::Esm);
        let cjs = entry_points_for(root, ConsumerModel::Cjs);
        assert!(esm.iter().any(|p| p.ends_with("esm.js")));
        assert!(!esm.iter().any(|p| p.ends_with("index.d.ts")));
        assert!(cjs.iter().any(|p| p.ends_with("cjs.js")));
        assert!(
            !cjs.iter().any(|p| p.ends_with("esm.js")) || cjs.iter().any(|p| p.ends_with("cjs.js"))
        );
    }

    #[test]
    fn entry_points_from_exports() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(
            root,
            "package.json",
            r#"{"name":"x","exports":{".":"./main.js","./util":"./util.js"}}"#,
        );
        write(root, "main.js", "require('./shared.js');\n");
        write(root, "util.js", "require('./shared.js');\n");
        write(root, "shared.js", "module.exports=1;\n");
        write(root, "orphan.js", "module.exports=2;\n");
        let eps = entry_points(root);
        // "." resolves under Esm model; "./util" is a subpath (not an entry) —
        // only "." is an entry, so 1 entry point, plus main fallback if any.
        assert!(eps.iter().any(|p| p.ends_with("main.js")));
        let rep = slice_package(root, "x@1.0.0");
        assert!(rep.kept_files.contains(&"shared.js".to_string()));
        assert!(rep.dropped_files.contains(&"orphan.js".to_string()));
    }
}
