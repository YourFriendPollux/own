//! `own ci` (SPEC §8.1, 0.1 without `check`): verify + overrides/pnpm-lock
//! coherence + offline diamond re-detection (§9.2 v0.6) + license policy
//! re-evaluation + LICENSES.md freshness + git-ignore probe. `--base-ref`
//! lists lock/config changes since the merge base (exit 0); `--fail-on-lock-change`
//! turns them into LOCK_CHANGED (exit 1).

use own_core::config::license_policy_json;
use own_core::lock::parse_lock;
use own_core::verify::{verify, Finding};

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
use own_policy::license as lic;
use own_policy::pnpm_lock::{
    file_dependency_path, parse_pnpm_lock, registry_dependency, split_pkg_key,
};
use std::path::Path;
use std::process::Command;

pub struct CiArgs {
    pub base_ref: Option<String>,
    pub fail_on_lock_change: bool,
}

pub fn ci(root: &Path, args: &CiArgs) -> Result<(Vec<Finding>, Vec<String>), String> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // 1. verify
    let toml_text0 =
        std::fs::read_to_string(root.join("own.toml")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let pol0 = license_policy_json(&toml_text0)?;
    let overrides0 = read_overrides(root)?;
    let outcome = verify(root, &pol0, &overrides0)?;
    findings.extend(outcome.findings);

    // 2. overrides / pnpm-lock coherence
    let text = std::fs::read_to_string(root.join("pnpm-lock.yaml"))
        .map_err(|e| format!("IO_ERROR: pnpm-lock.yaml: {e}"))?;
    let pnpm_lock = parse_pnpm_lock(&text)?;
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    // each vendored package must appear as file:vendor/own/<dir> in pnpm-lock importers or snapshots
    for p in &lock.packages {
        let referenced = !pnpm_lock.file_dependents(&p.dir).is_empty()
            || pnpm_lock
                .packages
                .iter()
                .any(|pk| file_dependency_path(&pk.key) == Some(p.dir.as_str()));
        if !referenced {
            findings.push(Finding {
                code: "OVERRIDE_MISMATCH".to_string(),
                severity: "error".to_string(),
                package: format!("{}@{}", p.name, p.version),
                path: "pnpm-lock.yaml".to_string(),
                message: "vendored package not referenced as file:vendor/own/ in pnpm-lock.yaml"
                    .to_string(),
            });
        }
    }

    // 3. offline diamond re-detection (§9.2 v0.6): any dependent or resolved version
    //    not covered by the recorded dependents or actual vendored versions
    //    -> DIAMOND_DETECTED. A strategy string alone is not version coverage.
    // Only known, integrity-checked vendored parents can retain their original
    // identity across pnpm's registry-to-directory rewrite. Unknown parents
    // and wrong directory/version targets remain distinct and are reported.
    let canonical_dependent = |dependent: &str| {
        lock.packages
            .iter()
            .find(|parent| dependent == format!("{}@file:{}", parent.name, parent.dir))
            .map(|parent| format!("{}@{}", parent.name, parent.version))
            .unwrap_or_else(|| dependent.to_string())
    };
    for p in &lock.packages {
        let mut current = pnpm_lock.registry_dependents(&p.name, &p.version);
        current.extend(pnpm_lock.file_dependents(&p.dir));
        let mut current: Vec<String> = current.iter().map(|d| canonical_dependent(d)).collect();
        current.sort();
        current.dedup();
        let recorded: Vec<String> = p
            .dependents
            .iter()
            .map(|d| canonical_dependent(d))
            .collect();
        let uncovered: Vec<&String> = current.iter().filter(|c| !recorded.contains(c)).collect();
        if !uncovered.is_empty() {
            findings.push(Finding {
                code: "DIAMOND_DETECTED".to_string(),
                severity: "error".to_string(),
                package: format!("{}@{}", p.name, p.version),
                path: "pnpm-lock.yaml".to_string(),
                message: format!(
                    "new dependents not covered by lock: {}",
                    uncovered
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
        let uncovered_versions: Vec<String> = pnpm_lock
            .resolved_versions(&p.name)
            .into_iter()
            .filter(|version| {
                !lock.packages.iter().any(|vendored| {
                    vendored.ecosystem == p.ecosystem
                        && vendored.name == p.name
                        && &vendored.version == version
                })
            })
            .collect();
        if !uncovered_versions.is_empty() {
            findings.push(Finding {
                code: "DIAMOND_DETECTED".to_string(),
                severity: "error".to_string(),
                package: format!("{}@{}", p.name, p.version),
                path: "pnpm-lock.yaml".to_string(),
                message: format!(
                    "resolved versions not covered by lock: {}",
                    uncovered_versions.join(", ")
                ),
            });
        }
        // dev-only dependents' ranges must satisfy the vendored version (v0.6 amendment 1)
        for im in &pnpm_lock.importers {
            for (n, spec, v) in im.all_deps() {
                // Aliases retain their declared names, while their registry
                // range belongs to the target. This is not a unify decision.
                // Local references have no registry semver range.
                let Some((name, version)) = registry_dependency(n, Some(spec), v) else {
                    continue;
                };
                // Catalog specifiers are indirections, not semver literals.
                // Check the locked target; diamond checks above still enforce
                // complete dependent and version coverage.
                let range = if spec.starts_with("catalog:") {
                    version.clone()
                } else {
                    spec.strip_prefix("npm:")
                        .map(|alias| split_pkg_key(alias).1)
                        .filter(|range| !range.is_empty())
                        .unwrap_or_else(|| spec.clone())
                };
                if name == p.name
                    && version == p.version
                    && !own_policy::semver::satisfies(&p.version, &range)
                {
                    findings.push(Finding {
                        code: "DIAMOND_DETECTED".to_string(),
                        severity: "error".to_string(),
                        package: format!("{}@{}", p.name, p.version),
                        path: format!("pnpm-lock.yaml:{}", im.path),
                        message: format!(
                            "specifier {spec} not satisfied by vendored {}",
                            p.version
                        ),
                    });
                }
            }
        }
    }

    // 4. license policy re-evaluation against current own.toml
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
    for p in &lock.packages {
        if p.license_expression.is_empty() {
            continue;
        }
        if let Ok((class, _)) = lic::evaluate_expression(&p.license_expression, &pol) {
            let expected = match class {
                lic::LicenseClass::Allow => "allow",
                lic::LicenseClass::Review => "human-review",
                lic::LicenseClass::Deny => "deny",
            };
            if p.license_policy != expected
                && !(class == lic::LicenseClass::Deny && p.license_policy == "deny")
            {
                findings.push(Finding {
                    code: if class == lic::LicenseClass::Deny {
                        "LICENSE_DENIED".to_string()
                    } else {
                        "LICENSE_REVIEW_REQUIRED".to_string()
                    },
                    severity: "error".to_string(),
                    package: format!("{}@{}", p.name, p.version),
                    path: "own.toml".to_string(),
                    message: format!(
                        "license {} now classifies as {} but lock says {}",
                        p.license_expression, expected, p.license_policy
                    ),
                });
            }
        }
    }

    // 5. LICENSES.md freshness (0.1: only if lock tracks it)
    if let Some(expected_hash) = &lock.metadata.licenses_md_sha256 {
        let path = root.join("vendor/own/LICENSES.md");
        match std::fs::read(&path) {
            Ok(bytes) => {
                let h = own_core::sha256_hex(&bytes);
                if &h != expected_hash {
                    findings.push(Finding {
                        code: "LICENSES_MD_STALE".to_string(),
                        severity: "error".to_string(),
                        package: String::new(),
                        path: "vendor/own/LICENSES.md".to_string(),
                        message: "LICENSES.md differs from lock hash; run own licenses --write"
                            .to_string(),
                    });
                }
            }
            Err(_) => {
                findings.push(Finding {
                    code: "LICENSES_MD_STALE".to_string(),
                    severity: "error".to_string(),
                    package: String::new(),
                    path: "vendor/own/LICENSES.md".to_string(),
                    message: "LICENSES.md tracked in lock but missing".to_string(),
                });
            }
        }
    }

    // 6. git-ignore probe on vendored files
    if !lock.packages.is_empty() {
        let mut paths = Vec::new();
        for p in &lock.packages {
            let base = root.join(&p.dir);
            collect_files(root, &base, &mut paths);
        }
        if !paths.is_empty() {
            let ignored = crate::git_ignore::ignored_paths(root, &paths)?;
            for path in ignored {
                findings.push(Finding {
                    code: "VENDOR_PATH_IGNORED".to_string(),
                    severity: "error".to_string(),
                    package: String::new(),
                    path,
                    message: "a vendored file is git-ignored; add '!vendor/own/**' as the last .gitignore line".to_string(),
                });
            }
        }
    }

    // 7. --base-ref: list changes of own.lock/own.toml since merge-base
    if let Some(base) = &args.base_ref {
        let mb = Command::new("git")
            .args(["merge-base", base, "HEAD"])
            .current_dir(root)
            .output()
            .map_err(|e| format!("GIT_ERROR: {e}"))?;
        if !mb.status.success() {
            return Err("GIT_ERROR: merge-base failed".to_string());
        }
        let mb = String::from_utf8_lossy(&mb.stdout).trim().to_string();
        for f in ["own.lock", "own.toml"] {
            let out = Command::new("git")
                .args(["diff", "--stat", &mb, "--", f])
                .current_dir(root)
                .output()
                .map_err(|e| format!("GIT_ERROR: {e}"))?;
            if !out.status.success() {
                return Err(format!("GIT_ERROR: diff exited {}", out.status));
            }
            if !out.stdout.is_empty() {
                notes.push(format!("changed: {f} since {mb}"));
                if args.fail_on_lock_change {
                    findings.push(Finding {
                        code: "LOCK_CHANGED".to_string(),
                        severity: "error".to_string(),
                        package: String::new(),
                        path: f.to_string(),
                        message: format!("{f} changed since {mb}"),
                    });
                }
            }
        }
    }
    findings.sort_by(|a, b| (&a.code, &a.package, &a.path).cmp(&(&b.code, &b.package, &b.path)));
    Ok((findings, notes))
}

fn collect_files(base: &Path, dir: &Path, out: &mut Vec<String>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_files(base, &p, out);
            } else if p.is_file() {
                if let Ok(rel) = p.strip_prefix(base) {
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
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
