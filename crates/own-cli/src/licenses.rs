//! `own licenses [--write]` (SPEC §8.1) and `own policy sync` (SPEC §8.1).

use own_core::canonical::{compute_lock_digest, license_policy_sha256, write_lock_canonical};
use own_core::config::license_policy_json;
use own_core::lock::{parse_lock, Lock};
use own_core::txn::Txn;
use own_policy::license as lic;
use std::path::Path;

/// Render `vendor/own/LICENSES.md` per §8.1: one `## name@version — expr` per
/// package sorted by (name, version), then `### path` + fenced verbatim content
/// with a fence longer than any backtick run in the content.
pub fn render_licenses_md(root: &Path, lock: &Lock) -> Result<String, String> {
    let mut out = String::new();
    let mut pkgs = lock.packages.clone();
    pkgs.sort_by(|a, b| {
        (a.name.as_str(), a.version.as_str()).cmp(&(b.name.as_str(), b.version.as_str()))
    });
    for p in &pkgs {
        out.push_str(&format!(
            "## {}@{} — {}\n\n",
            p.name, p.version, p.license_expression
        ));
        let mut files = p.license_files.clone();
        files.sort_by(|a, b| {
            license_file_order(&a.path)
                .cmp(&license_file_order(&b.path))
                .then(a.path.cmp(&b.path))
        });
        for f in &files {
            let content = std::fs::read_to_string(root.join(&p.dir).join(&f.path))
                // Name the package too: a bare "LICENSE: No such file" leaves the
                // user guessing which vendored package lost its licence file.
                .map_err(|e| format!("IO_ERROR: {}/{}: {e}", p.dir, f.path))?;
            let max_run = longest_backtick_run(&content);
            let fence = "`".repeat(3.max(max_run + 1));
            out.push_str(&format!(
                "### {}\n\n{}\n{}\n{}\n\n",
                f.path,
                fence,
                content.trim_end_matches('\n'),
                fence
            ));
        }
    }
    Ok(out)
}

fn license_file_order(path: &str) -> u8 {
    let up = path.to_uppercase();
    let base = up.rsplit('/').next().unwrap_or(&up);
    if base.starts_with("LICENSE") || base.starts_with("LICENCE") {
        0
    } else if base.starts_with("COPYING") {
        1
    } else if base.starts_with("NOTICE") {
        2
    } else {
        3
    }
}

fn longest_backtick_run(s: &str) -> usize {
    let mut max = 0;
    let mut cur = 0;
    for c in s.chars() {
        if c == '`' {
            cur += 1;
            max = max.max(cur);
        } else {
            cur = 0;
        }
    }
    max
}

pub fn licenses(root: &Path, write: bool) -> Result<u8, String> {
    // Recover before reading any state that this writer will publish.
    let txn = if write { Some(Txn::begin(root)?) } else { None };
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let mut lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let rendered = render_licenses_md(root, &lock)?;
    if !write {
        // read-only: compare with existing file if tracked
        if let Some(expected) = &lock.metadata.licenses_md_sha256 {
            let path = root.join("vendor/own/LICENSES.md");
            match std::fs::read(&path) {
                Ok(bytes) if own_core::sha256_hex(&bytes) == *expected => {}
                _ => return Err("LICENSES_MD_STALE".to_string()),
            }
        }
        // print table (§8.1: Package | Version | SPDX | Policy | licence files | Hash)
        let header = format!(
            "{:<28} {:<10} {:<12} {:<8} {:<6} {}",
            "Package", "Version", "SPDX", "Policy", "Files", "Hash"
        );
        println!("{header}");
        for p in &lock.packages {
            println!(
                "{:<28} {:<10} {:<12} {:<8} {:<6} {}",
                p.name,
                p.version,
                p.license_expression,
                p.license_policy,
                p.license_files.len(),
                short_hash(&p.package_files_sha256)
            );
        }
        return Ok(0);
    }
    // --write: transaction, update licenses_md_sha256 + lock_digest (v0.6: always set)
    let txn = txn.expect("write branch holds a transaction");
    let res = (|| -> Result<(), String> {
        txn.write_file("vendor/own/LICENSES.md", rendered.as_bytes())?;
        lock.metadata.licenses_md_sha256 = Some(own_core::sha256_hex(rendered.as_bytes()));
        let toml_text =
            std::fs::read_to_string(root.join("own.toml")).map_err(|e| format!("IO_ERROR: {e}"))?;
        let pol = license_policy_json(&toml_text)?;
        lock.metadata.license_policy_sha256 = license_policy_sha256(&pol);
        let overrides = read_overrides(root)?;
        lock.metadata.lock_digest = compute_lock_digest(&lock, &overrides);
        let canonical = write_lock_canonical(&lock);
        txn.write_file("own.lock", canonical.as_bytes())?;
        Ok(())
    })();
    match res {
        Ok(()) => {
            txn.commit()?;
            println!(
                "wrote vendor/own/LICENSES.md ({} packages)",
                lock.packages.len()
            );
            Ok(0)
        }
        Err(e) => {
            let _ = txn.rollback();
            Err(e)
        }
    }
}

/// `own policy sync`: recompute license_policy_sha256 from own.toml, re-evaluate
/// each package's license_policy, rewrite own.lock. Fails LICENSE_DENIED /
/// LICENSE_REVIEW_REQUIRED without writing if a package becomes blocked.
pub fn policy_sync(root: &Path) -> Result<u8, String> {
    let txn = Txn::begin(root)?;
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let mut lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let toml_text =
        std::fs::read_to_string(root.join("own.toml")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let pol_json = license_policy_json(&toml_text)?;
    let pol = lic::LicensePolicy {
        allow: str_list(&pol_json, "allow"),
        review: str_list(&pol_json, "review"),
        deny: str_list(&pol_json, "deny"),
        unknown: pol_json
            .get("unknown")
            .and_then(|u| u.as_str())
            .unwrap_or("deny")
            .to_string(),
    };
    for p in &mut lock.packages {
        if p.license_expression.is_empty() {
            return Err("LICENSE_DENIED".to_string());
        }
        let (class, _sel) = lic::evaluate_expression(&p.license_expression, &pol)?;
        let new = match class {
            lic::LicenseClass::Allow => "allow",
            lic::LicenseClass::Review => {
                if p.license_policy == "human-review" {
                    "human-review"
                } else {
                    return Err("LICENSE_REVIEW_REQUIRED".to_string());
                }
            }
            lic::LicenseClass::Deny => return Err("LICENSE_DENIED".to_string()),
        };
        p.license_policy = new.to_string();
    }
    let res = (|| -> Result<(), String> {
        lock.metadata.license_policy_sha256 = license_policy_sha256(&pol_json);
        let overrides = read_overrides(root)?;
        lock.metadata.lock_digest = compute_lock_digest(&lock, &overrides);
        let canonical = write_lock_canonical(&lock);
        txn.write_file("own.lock", canonical.as_bytes())?;
        Ok(())
    })();
    match res {
        Ok(()) => {
            txn.commit()?;
            println!("policy synced");
            Ok(0)
        }
        Err(e) => {
            let _ = txn.rollback();
            Err(e)
        }
    }
}

/// `own migrate`: schema_version 1 is current — no-op, but the path is tested.
pub fn migrate(root: &Path) -> Result<u8, String> {
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    if lock.metadata.schema_version != own_core::canonical::SCHEMA_VERSION {
        return Err("LOCK_SCHEMA_UNSUPPORTED".to_string());
    }
    println!(
        "schema_version {} is current; nothing to migrate",
        lock.metadata.schema_version
    );
    Ok(0)
}

/// `sha256:<12 hex chars>` — the lock stores the full digest; the table shows a
/// stable, comparable prefix so the column stays readable (SPEC §8.1).
fn short_hash(s: &str) -> String {
    let h = s.strip_prefix("sha256:").unwrap_or(s);
    format!("sha256:{}", h.chars().take(12).collect::<String>())
}

fn read_overrides(root: &Path) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let text =
        std::fs::read_to_string(root.join("package.json")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("PARSE_ERROR: {e}"))?;
    let mut out = serde_json::Map::new();
    if let Some(ov) = v
        .get("pnpm")
        .and_then(|p| p.get("overrides"))
        .and_then(|o| o.as_object())
    {
        for (k, val) in ov {
            if let Some(s) = val.as_str() {
                if s.starts_with("file:vendor/own/") {
                    out.insert(k.clone(), serde_json::Value::String(s.to_string()));
                }
            }
        }
    }
    Ok(out)
}

fn str_list(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "own-license-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(root.join("vendor/own/pkg@1.0.0")).unwrap();
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn license_lock() -> Lock {
        let mut lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        let hash = own_core::sha256_hex(b"");
        lock.packages.push(
            serde_json::from_value(serde_json::json!({
                "name": "pkg", "ecosystem": "npm", "version": "1.0.0",
                "dir": "vendor/own/pkg@1.0.0", "registry": "https://registry.npmjs.org",
                "integrity": "sha512-AAAA", "tarball_sha256": hash,
                "version_manifest_sha256": hash, "provenance_level": "integrity-only",
                "mode": "verbatim", "roots": ["."], "dependents": ["importer:."],
                "license_expression": "MIT", "license_policy": "allow",
                "license_files": [{"path": "LICENSE", "sha256": hash}],
                "package_files_sha256": hash, "file_count": 1, "total_size": 0
            }))
            .unwrap(),
        );
        lock
    }

    #[test]
    fn licenses_markdown_fences_have_at_least_three_backticks_and_exceed_content_runs() {
        let f = Fixture::new();
        let lock = license_lock();
        let mut incorrect = Vec::new();
        for run in [0, 1, 2, 3, 5] {
            let content = format!("MIT license\n{}\nverbatim text", "`".repeat(run));
            std::fs::write(f.0.join("vendor/own/pkg@1.0.0/LICENSE"), &content).unwrap();
            let rendered = render_licenses_md(&f.0, &lock).unwrap();
            let fence = "`".repeat(3.max(run + 1));
            let expected =
                format!("## pkg@1.0.0 — MIT\n\n### LICENSE\n\n{fence}\n{content}\n{fence}\n\n");
            if rendered != expected {
                incorrect.push((run, rendered));
            }
        }
        assert!(
            incorrect.is_empty(),
            "invalid Markdown fences: {incorrect:#?}"
        );
    }
}
