//! Phase 2 — E1 evidence: CVE reachable statically from the package entry
//! points over the internal require/import graph (own-slice AST backend).
//!
//! E1 downgrades an E0 alert to `not_affected` **only** when the vulnerable
//! code path is provably unreachable: the advisory's affected *files/functions*
//! (OSV `database_specific` / `ecosystem_specific` hints when present) never
//! intersect the reachable file set. Otherwise the alert stays E0.
//!
//! Conservative (INV-4/INV-7): any doubt (no file info in the advisory,
//! dynamic code in the package, unparseable file) ⇒ alert remains E0.
//! `own` NEVER emits `not_affected` without E1 proof (SPEC §9.4 Phase 2).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::{ast, entry_points_for, ConsumerModel};

pub fn all_package_files_pub(pkg_root: &Path) -> HashSet<String> {
    all_package_files(pkg_root)
}

fn all_package_files(pkg_root: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    for e in walkdir::WalkDir::new(pkg_root)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        if e.file_type().is_file() {
            if let Ok(r) = e.path().strip_prefix(pkg_root) {
                out.insert(r.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    out
}

fn pkg_name(pkg_root: &Path) -> Option<String> {
    let txt = std::fs::read_to_string(pkg_root.join("package.json")).ok()?;
    serde_json::from_str::<serde_json::Value>(&txt)
        .ok()?
        .get("name")?
        .as_str()
        .map(|s| s.to_string())
}

/// Reachable file set (relative paths, `/`-separated) from the package entry
/// points, or `None` if conservatism forces keep-whole (dynamic/unparseable).
use std::sync::LazyLock;
static FS_ANY: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"\bfs\s*\."#).unwrap());
static FS_LIT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?:readFileSync|readFile|readJsonSync)\s*\(\s*['"]([^'"]+)['"]"#).unwrap()
});

pub fn reachable_files(pkg_root: &Path, model: ConsumerModel) -> Option<HashSet<String>> {
    let entries = entry_points_for(pkg_root, model);
    if entries.is_empty() {
        return None; // F-01: no provable reachable set => E0 (INV-4)
    }
    let mut kept: HashSet<PathBuf> = HashSet::new();
    let mut queue: std::collections::VecDeque<PathBuf> = entries.into();
    while let Some(f) = queue.pop_front() {
        if kept.contains(&f) || !f.is_file() {
            continue;
        }
        let raw = match std::fs::read(&f) {
            Ok(r) => r,
            Err(_) => return None, // unreadable reachable file => no proof (INV-4)
        };
        // F-08: non-JS assets (.json etc.) are leaf reachable files, not parse errors
        if ast::language_for(&f).is_none() {
            kept.insert(f.clone());
            continue;
        }
        match ast::parse(&f, &raw) {
            ast::ParseOutcome::Failed => return None, // INV-4: keep whole, no E1 proof
            ast::ParseOutcome::Ok(tree) => {
                let e = ast::edges(&tree, &raw);
                if e.dynamic {
                    return None; // dynamic require can load anything ⇒ no E1 proof
                }
                kept.insert(f.clone());
                // F-high: ANY fs.* call in reachable code => runtime file loads
                // are unprovable => no E1 proof (return None).
                let content = String::from_utf8_lossy(&raw);
                if FS_ANY.is_match(&content) {
                    return None;
                }
                // literal fs-read paths (belt-and-braces, unreachable given above)
                for cap in FS_LIT.captures_iter(&content) {
                    if cap[1].starts_with('.') {
                        if let Some(r) = crate::resolve(&cap[1], &f, pkg_root) {
                            queue.push_back(r);
                        }
                    }
                }
                for spec in &e.literal_specs {
                    // F7: dangerous runtime modules ⇒ dynamic ⇒ no E1 proof
                    if matches!(
                        spec.as_str(),
                        "vm" | "node:vm"
                            | "worker_threads"
                            | "node:worker_threads"
                            | "child_process"
                            | "node:child_process"
                    ) {
                        return None;
                    }
                    let spec = spec.clone();
                    if spec.starts_with('.') {
                        let r = crate::resolve(&spec, &f, pkg_root)?; // F-06: unresolved relative literal => None
                        queue.push_back(r);
                    } else if let Some(name) = pkg_name(pkg_root) {
                        // self-reference: require('myownpkg/lib/x') -> exports subpath
                        if spec == name {
                            for e in crate::entry_points_for(pkg_root, model) {
                                queue.push_back(e);
                            }
                        } else if let Some(sub) = spec.strip_prefix(&format!("{name}/")) {
                            if let Some(r) = crate::resolve(&format!("./{sub}"), pkg_root, pkg_root)
                            {
                                queue.push_back(r);
                            }
                        }
                    }
                }
            }
        }
    }
    Some(
        kept.iter()
            .map(|p| {
                p.strip_prefix(pkg_root)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect(),
    )
}

/// Evidence level for an advisory against a vendored package dir.
/// Returns ("E1", reachable_files) if the advisory carries file-level info
/// that provably misses the reachable set; ("E0", None) otherwise.
pub fn evidence_level(
    pkg_root: &Path,
    advisory: &serde_json::Value,
    model: ConsumerModel,
) -> (&'static str, Option<HashSet<String>>) {
    // F-04: reachable set = UNION over Cjs + Esm consumer models (plus the
    // requested one); a file reachable under ANY model counts as reachable.
    let mut union: Option<HashSet<String>> = None;
    for m in [ConsumerModel::Cjs, ConsumerModel::Esm, model] {
        match reachable_files(pkg_root, m) {
            None => return ("E0", None), // any model unprovable => E0
            Some(r) => {
                let u = union.get_or_insert_with(HashSet::new);
                u.extend(r);
            }
        }
    }
    let Some(reach) = union else {
        return ("E0", None);
    };
    // File-level hints: OSV `affected[].database_specific` or
    // `ecosystem_specific` may carry `vulnerable_files` / `files`.
    let mut vuln_files: Vec<String> = Vec::new();
    if let Some(affected) = advisory.get("affected").and_then(|a| a.as_array()) {
        for aff in affected {
            for key in ["database_specific", "ecosystem_specific"] {
                if let Some(ds) = aff.get(key) {
                    for fkey in ["vulnerable_files", "files", "paths"] {
                        if let Some(arr) = ds.get(fkey).and_then(|v| v.as_array()) {
                            for f in arr {
                                if let Some(s) = f.as_str() {
                                    let n = s
                                        .trim_start_matches("package/")
                                        .trim_start_matches("./")
                                        .trim_start_matches('/')
                                        .replace('\\', "/");
                                    vuln_files.push(n);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if vuln_files.is_empty() {
        return ("E0", Some(reach)); // no file info ⇒ cannot prove unreachable
    }
    // F-02 (deepseek): E1 only if every vulnerable path EXISTS verbatim in the
    // package and is NOT reachable. Globs, directory prefixes, and paths absent
    // from the tarball all count as hits => E0 (conservative, INV-4).
    let all_files: HashSet<String> = all_package_files(pkg_root);
    let hit: Vec<&String> = vuln_files
        .iter()
        .filter(|f| {
            if f.contains('*') {
                return true; // glob => potential hit
            }
            if !all_files.contains(*f) {
                return true; // absent from tarball => cannot prove => E0
            }
            if reach.contains(*f) {
                return true; // reachable => E0
            }
            // directory prefix: any reachable file under it => hit
            let prefix = format!("{}/", f);
            reach.iter().any(|r| r.starts_with(&prefix))
        })
        .collect();
    if hit.is_empty() {
        ("E1", Some(reach))
    } else {
        ("E0", Some(reach))
    }
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
    fn e1_when_vuln_file_unreachable() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(root, "package.json", r#"{"name":"x","main":"index.js"}"#);
        write(
            root,
            "index.js",
            "const a = require('./a.js');\nmodule.exports = a;\n",
        );
        write(root, "a.js", "module.exports = 1;\n");
        write(root, "vuln.js", "module.exports = 'vulnerable';\n"); // not reachable
        let adv = serde_json::json!({
            "id": "GHSA-x",
            "affected": [{ "package": "x", "database_specific": { "vulnerable_files": ["vuln.js"] } }]
        });
        let (lvl, reach) = evidence_level(root, &adv, ConsumerModel::Cjs);
        assert_eq!(lvl, "E1");
        let r = reach.unwrap();
        assert!(r.contains("index.js") && r.contains("a.js"));
        assert!(!r.contains("vuln.js"));
    }

    #[test]
    fn e0_when_vuln_file_reachable() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(root, "package.json", r#"{"name":"x","main":"index.js"}"#);
        write(root, "index.js", "require('./vuln.js');\n");
        write(root, "vuln.js", "x\n");
        let adv = serde_json::json!({
            "id": "GHSA-y",
            "affected": [{ "package": "x", "database_specific": { "vulnerable_files": ["vuln.js"] } }]
        });
        let (lvl, _) = evidence_level(root, &adv, ConsumerModel::Cjs);
        assert_eq!(lvl, "E0");
    }

    #[test]
    fn e0_when_no_file_info() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(root, "package.json", r#"{"name":"x","main":"index.js"}"#);
        write(root, "index.js", "module.exports = 1;\n");
        let adv =
            serde_json::json!({ "id": "GHSA-z", "affected": [{ "package": "x", "ranges": [] }] });
        let (lvl, _) = evidence_level(root, &adv, ConsumerModel::Cjs);
        assert_eq!(lvl, "E0");
    }

    #[test]
    fn e0_when_dynamic_require_present() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(root, "package.json", r#"{"name":"x","main":"index.js"}"#);
        write(root, "index.js", "const m = argv[2]; require(m);\n");
        write(root, "vuln.js", "x\n");
        let adv = serde_json::json!({
            "id": "GHSA-w",
            "affected": [{ "package": "x", "database_specific": { "vulnerable_files": ["vuln.js"] } }]
        });
        let (lvl, reach) = evidence_level(root, &adv, ConsumerModel::Cjs);
        assert_eq!(lvl, "E0");
        assert!(reach.is_none()); // no proof possible
    }
}
