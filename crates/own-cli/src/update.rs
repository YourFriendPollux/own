//! `own update <pkg>@<new>` (SPEC §8.2): single transaction replacing the vendored
//! dir, lock entry, manifest, package.json; runs diff, pnpm install, verify.
//! PR creation (branch/commit/push/gh) only with gh available; `--no-pr` skips it.

use own_core::canonical::{
    compute_lock_digest, compute_vendor_files_sha256, license_policy_sha256, write_lock_canonical,
};
use own_core::config::license_policy_json;
use own_core::lock::{parse_lock, LicenseFile, Lock, Package};
use own_core::txn::Txn;
use own_net::{build_client, fetch_packument, fetch_tarball, verify_sri_integrity, NetConfig};
use own_policy::license as lic;
use std::path::Path;
use std::process::Command;

pub struct UpdateArgs {
    pub pkg: String,
    pub new_version: String,
    pub no_pr: bool,
    #[allow(dead_code)]
    // diamond strategies recorded at add-time; re-eval path is update to same version
    pub allow_diamond: Option<String>,
    pub no_install: bool,
}

pub fn update(root: &Path, args: &UpdateArgs) -> Result<u8, String> {
    // preconditions
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let mut lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let old_idx = lock
        .packages
        .iter()
        .position(|p| p.name == args.pkg)
        .ok_or("PACKAGE_NOT_VENDORED")?;
    let old = lock.packages[old_idx].clone();
    // working tree must be clean
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("GIT_ERROR: {e}"))?;
    if !dirty.stdout.is_empty() {
        return Err("WORKTREE_DIRTY".to_string());
    }
    // verify current package passes
    {
        let toml =
            std::fs::read_to_string(root.join("own.toml")).map_err(|e| format!("IO_ERROR: {e}"))?;
        let pol = license_policy_json(&toml)?;
        let ov = read_overrides(root)?;
        let outcome = own_core::verify::verify(root, &pol, &ov)?;
        if outcome
            .findings
            .iter()
            .any(|f| f.severity == "error" && f.package.starts_with(&format!("{}@", args.pkg)))
        {
            return Err("DRIFT_MODIFIED: current package in drift; refusing to update".to_string());
        }
    }
    // fetch new version (same pipeline as add, minus the pnpm-lock precondition)
    let cfg = NetConfig::default();
    let client = build_client(&cfg)?;
    let packument = fetch_packument(&client, &cfg, &args.pkg)?;
    let pv: serde_json::Value =
        serde_json::from_slice(&packument).map_err(|e| format!("PARSE_ERROR: packument: {e}"))?;
    let vobj = pv
        .get("versions")
        .and_then(|vs| vs.get(&args.new_version))
        .ok_or("VERSION_NOT_FOUND")?;
    let integrity = vobj
        .pointer("/dist/integrity")
        .and_then(|i| i.as_str())
        .ok_or("NOT_ELIGIBLE:integrity_missing")?
        .to_string();
    let tarball_url = vobj
        .pointer("/dist/tarball")
        .and_then(|t| t.as_str())
        .ok_or("VERSION_NOT_FOUND")?
        .to_string();
    let dl = fetch_tarball(&client, &cfg, &tarball_url)?;
    let sha512_hex = verify_sri_integrity(&integrity, &dl.bytes)?;
    let vm_hash = crate::add::version_manifest_hash_pub(vobj)?;
    // provenance §8.1 step 4: detection only, same evaluator as `add`
    let prov = crate::add::evaluate_provenance(vobj);
    for w in &prov.warnings {
        eprintln!("warning: {w}");
    }

    // eligibility on new version
    let vendored: Vec<(String, String)> = lock
        .packages
        .iter()
        .filter(|p| p.name != args.pkg)
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    let elig = own_policy::eligibility::evaluate(vobj, &vendored, 500 * 1_048_576);
    if !elig.eligible {
        return Err(format!(
            "NOT_ELIGIBLE:{}",
            elig.blocking.unwrap_or("unknown")
        ));
    }
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
    let expr = elig.license_expression.clone().unwrap_or_default();
    let (class, selected) = if expr.is_empty() {
        (lic::LicenseClass::Deny, None)
    } else {
        lic::evaluate_expression(&expr, &pol)?
    };
    let license_policy = match class {
        lic::LicenseClass::Allow => "allow",
        lic::LicenseClass::Review => {
            if old.license_policy == "human-review" {
                "human-review"
            } else {
                return Err("LICENSE_REVIEW_REQUIRED".to_string());
            }
        }
        lic::LicenseClass::Deny => return Err("LICENSE_DENIED".to_string()),
    };

    // transaction
    let txn = Txn::begin(root)?;
    let res = update_inner(
        &txn,
        root,
        &mut lock,
        old_idx,
        &old,
        args,
        &dl.bytes,
        &sha512_hex,
        &dl.sha256,
        &vm_hash,
        &integrity,
        license_policy,
        selected,
        &expr,
        &prov,
    );
    match res {
        Ok((new_lock, report)) => {
            // package.json: override path changes if dir name changed
            let new_dir = format!(
                "vendor/own/{}",
                own_core::lock::dir_name(&args.pkg, &args.new_version)
            );
            update_override(
                &txn,
                root,
                &new_lock,
                &args.pkg,
                &old.version,
                &args.new_version,
                &new_dir,
            )?;
            let overrides = read_overrides(root)?;
            let mut new_lock = new_lock;
            new_lock.metadata.lock_digest = compute_lock_digest(&new_lock, &overrides);
            let canonical = write_lock_canonical(&new_lock);
            txn.write_file("own.lock", canonical.as_bytes())?;
            // pnpm install + verify
            if !args.no_install {
                let st = Command::new("pnpm")
                    .arg("install")
                    .current_dir(root)
                    .status()
                    .map_err(|e| format!("PNPM_FAILED: {e}"))?;
                if !st.success() {
                    let _ = txn.rollback();
                    return Err("PNPM_FAILED".to_string());
                }
            }
            let toml2 = std::fs::read_to_string(root.join("own.toml"))
                .map_err(|e| format!("IO_ERROR: {e}"))?;
            let pol2 = license_policy_json(&toml2)?;
            let ov2 = read_overrides(root)?;
            let outcome = match own_core::verify::verify(root, &pol2, &ov2) {
                Ok(o) => o,
                Err(e) => {
                    let _ = txn.rollback();
                    return Err(e);
                }
            };
            if outcome.findings.iter().any(|f| f.severity == "error") {
                let _ = txn.rollback();
                return Err(format!(
                    "{}: post-update verify failed",
                    outcome.findings[0].code
                ));
            }
            txn.commit()?;
            println!(
                "updated {}@{} -> {}@{} ({} files changed, {} signals)",
                args.pkg,
                old.version,
                args.pkg,
                args.new_version,
                report.modified.len() + report.added.len() + report.removed.len(),
                report.signals.len()
            );
            if !args.no_pr {
                create_pr(root, args, &report)?;
            }
            Ok(0)
        }
        Err(e) => {
            let _ = txn.rollback();
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn update_inner(
    txn: &Txn,
    root: &Path,
    lock: &mut Lock,
    old_idx: usize,
    old: &Package,
    args: &UpdateArgs,
    tarball: &[u8],
    sha512_hex: &str,
    tarball_sha256: &str,
    vm_hash: &str,
    integrity: &str,
    license_policy: &str,
    license_selected: Option<String>,
    license_expression: &str,
    prov: &crate::add::Provenance,
) -> Result<(Lock, crate::diff::DiffReport), String> {
    // cache
    let cache_dir = root.join(".own/cache");
    std::fs::create_dir_all(&cache_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
    let cache_path = cache_dir.join(format!("{sha512_hex}.tgz"));
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&cache_path, tarball).map_err(|e| format!("IO_ERROR: {e}"))?;
        std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o444))
            .map_err(|e| format!("IO_ERROR: {e}"))?;
    }
    // extract
    let tmp_extract = root.join(".own/tmp").join(format!("upd-{}", txn.id));
    std::fs::create_dir_all(&tmp_extract).map_err(|e| format!("IO_ERROR: {e}"))?;
    let limits = own_extract::SecurityLimits::default();
    let stats = own_extract::extract(&cache_path, &tmp_extract, &limits)?;
    // diff old vendor dir vs new extraction (use root-relative fake dirs)
    let report = crate::diff::diff_dirs(root, &old.dir, tmp_extract.to_str().ok_or("IO_ERROR")?)
        .unwrap_or_default();
    // license files
    let mut paths = Vec::new();
    collect_files(&tmp_extract, &tmp_extract, &mut paths);
    let mut license_files: Vec<LicenseFile> = Vec::new();
    for p in &paths {
        let base = p.rsplit('/').next().unwrap_or(p).to_uppercase();
        if base.starts_with("LICENSE")
            || base.starts_with("LICENCE")
            || base.starts_with("COPYING")
            || base.starts_with("NOTICE")
        {
            if std::fs::read_to_string(tmp_extract.join(p)).is_err() {
                return Err("NOT_ELIGIBLE:license_file_encoding".to_string());
            }
            let h = own_core::sha256_hex(
                &std::fs::read(tmp_extract.join(p)).map_err(|e| format!("IO_ERROR: {e}"))?,
            );
            license_files.push(LicenseFile {
                path: p.clone(),
                sha256: h,
            });
        }
    }
    // native check
    for p in &paths {
        let b = std::fs::read(tmp_extract.join(p)).map_err(|e| format!("IO_ERROR: {e}"))?;
        if b.starts_with(b"\x7fELF") || (b.len() >= 2 && &b[..2] == b"MZ") {
            return Err("NOT_ELIGIBLE:native_binary".to_string());
        }
        if p.ends_with("binding.gyp") {
            return Err("NOT_ELIGIBLE:binding_gyp".to_string());
        }
    }
    // replace old dir: backup handled by txn; remove old, move new
    let new_dir_rel = format!(
        "vendor/own/{}",
        own_core::lock::dir_name(&args.pkg, &args.new_version)
    );
    let old_dir_abs = root.join(&old.dir);
    txn.backup(&old.dir)?;
    if old_dir_abs.exists() {
        std::fs::remove_dir_all(&old_dir_abs).map_err(|e| format!("IO_ERROR: {e}"))?;
    }
    txn.move_dir_into(&tmp_extract, &new_dir_rel)?;
    // remove old manifest, write new
    let old_manifest = format!(
        "vendor/own/.manifests/{}.toml",
        own_core::lock::dir_name(&args.pkg, &old.version)
    );
    if root.join(&old_manifest).exists() {
        txn.backup(&old_manifest)?;
        std::fs::remove_file(root.join(&old_manifest)).map_err(|e| format!("IO_ERROR: {e}"))?;
    }
    let manifest = build_manifest_pub(&args.pkg, &args.new_version, root, &new_dir_rel)?;
    let manifest_rel = format!(
        "vendor/own/.manifests/{}.toml",
        own_core::lock::dir_name(&args.pkg, &args.new_version)
    );
    txn.write_file(&manifest_rel, manifest.as_bytes())?;
    // lock entry replace
    let pfs = manifest_pfs_pub(root, &new_dir_rel)?;
    let new_entry = Package {
        name: args.pkg.clone(),
        ecosystem: "npm".into(),
        version: args.new_version.clone(),
        dir: new_dir_rel,
        registry: old.registry.clone(),
        integrity: integrity.to_string(),
        tarball_sha256: tarball_sha256.to_string(),
        version_manifest_sha256: vm_hash.to_string(),
        provenance_level: prov.level.clone(),
        provenance_source: prov.source.clone(),
        mode: "verbatim".into(),
        roots: old.roots.clone(),
        dependents: old.dependents.clone(),
        license_expression: license_expression.to_string(),
        license_selected,
        license_policy: license_policy.to_string(),
        license_files,
        package_files_sha256: pfs,
        file_count: stats.files as u64,
        total_size: stats.total_unpacked,
        diamond_resolution: old.diamond_resolution.clone(),
        unified_ranges: old.unified_ranges.clone(),
    };
    lock.packages[old_idx] = new_entry;
    lock.packages.sort_by(|a, b| {
        (a.name.as_str(), a.version.as_str()).cmp(&(b.name.as_str(), b.version.as_str()))
    });
    let toml_text =
        std::fs::read_to_string(root.join("own.toml")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let pol = license_policy_json(&toml_text)?;
    lock.metadata.license_policy_sha256 = license_policy_sha256(&pol);
    lock.metadata.vendor_files_sha256 = compute_vendor_files_sha256(&lock.packages);
    Ok((lock.clone(), report))
}

fn create_pr(
    root: &Path,
    args: &UpdateArgs,
    report: &crate::diff::DiffReport,
) -> Result<(), String> {
    // INV-11: never leak local identity — the commit author is forced to the
    // neutral own bot, whatever the repo/user git config says.
    let author = "own-bot <own-bot@localhost>";
    let branch = format!(
        "own/update-{}",
        own_core::lock::dir_name(&args.pkg, &args.new_version)
    );
    let run = |args: &[&str]| -> Result<String, String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .map_err(|e| format!("GIT_ERROR: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "GIT_ERROR: git {} -> {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    };
    // refuse to run on a dirty tree: the branch+commit below must contain ONLY
    // the update's changes
    if run(&["status", "--porcelain"])
        .map(|s| !s.trim().is_empty())
        .unwrap_or(true)
    {
        return Err("GIT_ERROR: working tree not clean before own/update branch".to_string());
    }
    let _ = run(&["checkout", "-b", &branch])?;
    let _ = run(&["add", "-A"])?;
    let msg = format!(
        "chore(deps): update {} to {} (own)",
        args.pkg, args.new_version
    );
    let _ = run(&[
        "-c",
        &format!("user.name={}", author_name(author)),
        "-c",
        &format!("user.email={}", author_email(author)),
        "commit",
        "--author",
        author,
        "-m",
        &msg,
    ])?;
    // push + gh pr are best-effort; failure -> GH_FAILED exit 3 but commit is kept
    if let Err(e) = run(&["push", "--set-upstream", "origin", &branch]) {
        return Err(format!("GH_FAILED: {e} (local commit kept on {branch})"));
    }
    let body = format!(
        "## own update {} -> {}\n\nadded {} / removed {} / modified {} / renamed {}\n\n{} signals:\n{}",
        args.pkg, args.new_version,
        report.added.len(), report.removed.len(), report.modified.len(), report.renamed.len(),
        report.signals.len(),
        report.signals.iter().take(50).map(|s| format!("- {}: {} at {}:{}", s.kind, s.name, s.path, s.line)).collect::<Vec<_>>().join("\n")
    );
    let body_file = root.join(".own/tmp/pr-body.md");
    std::fs::write(&body_file, body).map_err(|e| format!("IO_ERROR: {e}"))?;
    let title = format!(
        "chore(deps): update {} to {} (own)",
        args.pkg, args.new_version
    );
    let out = Command::new("gh")
        .args([
            "pr",
            "create",
            "--title",
            &title,
            "--body-file",
            body_file.to_str().unwrap(),
            "--head",
            &branch,
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("GH_FAILED: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "GH_FAILED: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn update_override(
    txn: &Txn,
    root: &Path,
    lock: &Lock,
    pkg: &str,
    old_version: &str,
    new_version: &str,
    new_dir: &str,
) -> Result<(), String> {
    let rel = "package.json";
    let text = std::fs::read_to_string(root.join(rel)).map_err(|e| format!("IO_ERROR: {e}"))?;
    let mut v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("PARSE_ERROR: {e}"))?;
    if let Some(ov) = v
        .get_mut("pnpm")
        .and_then(|p| p.get_mut("overrides"))
        .and_then(|o| o.as_object_mut())
    {
        let val = format!("file:{new_dir}");
        // The key shape follows the lock that is about to be written: one version
        // of a name keeps the bare key, several need one versioned key each.
        // verify compares the same shape, so leaving the old spelling behind is a
        // hard OVERRIDE_MISMATCH rather than a silent drift.
        let versions = lock.packages.iter().filter(|p| p.name == pkg).count();
        let key = if versions > 1 {
            own_core::lock::versioned_override_key(pkg, new_version)
        } else {
            pkg.to_string()
        };
        for stale in [
            pkg.to_string(),
            own_core::lock::versioned_override_key(pkg, old_version),
        ] {
            if let Some(existing) = ov.get(&stale).and_then(|e| e.as_str()) {
                if !existing.starts_with("file:vendor/own/") {
                    // never clobber an override own did not write
                    return Err("OVERRIDE_CONFLICT".to_string());
                }
                ov.remove(&stale);
            }
        }
        ov.insert(key, serde_json::Value::String(val));
        let mut keys: Vec<String> = ov.keys().cloned().collect();
        keys.sort();
        let sorted: serde_json::Map<String, serde_json::Value> = keys
            .into_iter()
            .map(|k| (k.clone(), ov[&k].clone()))
            .collect();
        *ov = sorted;
    }
    let out = serde_json::to_string_pretty(&v).map_err(|e| format!("IO_ERROR: {e}"))?;
    txn.write_file(rel, format!("{out}\n").as_bytes())
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

pub fn build_manifest_pub(
    pkg: &str,
    version: &str,
    root: &Path,
    dir: &str,
) -> Result<String, String> {
    crate::add::build_manifest_pub(pkg, version, root, dir)
}

pub fn manifest_pfs_pub(root: &Path, dir: &str) -> Result<String, String> {
    crate::add::manifest_pfs_pub(root, dir)
}

pub fn split_spec_pub(spec: &str) -> (String, String) {
    crate::diff::split_spec(spec)
}

fn author_name(a: &str) -> &str {
    a.split('<').next().unwrap_or("own-bot").trim()
}
fn author_email(a: &str) -> &str {
    a.split('<')
        .nth(1)
        .and_then(|e| e.split('>').next())
        .unwrap_or("own-bot@localhost")
}

#[cfg(test)]
mod override_tests {
    use super::*;

    fn package(name: &str, version: &str) -> Package {
        Package {
            name: name.into(),
            ecosystem: "npm".into(),
            version: version.into(),
            dir: format!("vendor/own/{name}@{version}"),
            registry: "https://registry.npmjs.org".into(),
            integrity: "sha512-x".into(),
            tarball_sha256: "sha256:00".into(),
            version_manifest_sha256: "sha256:00".into(),
            provenance_level: "integrity-only".into(),
            provenance_source: None,
            mode: "verbatim".into(),
            roots: vec![".".into()],
            dependents: vec!["importer:.".into()],
            license_expression: "MIT".into(),
            license_selected: None,
            license_policy: "allow".into(),
            license_files: vec![LicenseFile {
                path: "LICENSE".into(),
                sha256: "sha256:00".into(),
            }],
            package_files_sha256: "sha256:00".into(),
            file_count: 0,
            total_size: 0,
            diamond_resolution: None,
            unified_ranges: None,
        }
    }

    fn fixture(tag: &str, overrides: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("own-update-override-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            format!("{{\"name\":\"f\",\"pnpm\":{{\"overrides\":{overrides}}}}}\n"),
        )
        .unwrap();
        root
    }

    fn read_overrides(root: &Path) -> serde_json::Value {
        let text = std::fs::read_to_string(root.join("package.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["pnpm"]["overrides"].clone()
    }

    #[test]
    fn update_keeps_one_versioned_key_per_version_p2_06() {
        let root = fixture(
            "multi",
            "{\"a@1.0.0\":\"file:vendor/own/a@1.0.0\",\"a@2.0.0\":\"file:vendor/own/a@2.0.0\"}",
        );
        let mut lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        lock.packages.push(package("a", "1.0.0"));
        lock.packages.push(package("a", "2.1.0"));
        let txn = Txn::begin(&root).unwrap();
        update_override(
            &txn,
            &root,
            &lock,
            "a",
            "2.0.0",
            "2.1.0",
            "vendor/own/a@2.1.0",
        )
        .unwrap();
        txn.commit().unwrap();
        assert_eq!(
            read_overrides(&root),
            serde_json::json!({
                "a@1.0.0": "file:vendor/own/a@1.0.0",
                "a@2.1.0": "file:vendor/own/a@2.1.0",
            })
        );
    }

    #[test]
    fn update_collapses_to_the_bare_key_when_one_version_remains_p2_06() {
        let root = fixture("single", "{\"a@2.0.0\":\"file:vendor/own/a@2.0.0\"}");
        let mut lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        lock.packages.push(package("a", "2.1.0"));
        let txn = Txn::begin(&root).unwrap();
        update_override(
            &txn,
            &root,
            &lock,
            "a",
            "2.0.0",
            "2.1.0",
            "vendor/own/a@2.1.0",
        )
        .unwrap();
        txn.commit().unwrap();
        assert_eq!(
            read_overrides(&root),
            serde_json::json!({"a": "file:vendor/own/a@2.1.0"})
        );
    }

    #[test]
    fn update_refuses_to_clobber_a_foreign_override_p2_06() {
        let root = fixture("foreign", "{\"a\":\"npm:other@1.0.0\"}");
        let mut lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        lock.packages.push(package("a", "2.1.0"));
        let txn = Txn::begin(&root).unwrap();
        let error = update_override(
            &txn,
            &root,
            &lock,
            "a",
            "2.0.0",
            "2.1.0",
            "vendor/own/a@2.1.0",
        )
        .unwrap_err();
        assert_eq!(error, "OVERRIDE_CONFLICT");
        let _ = txn.rollback();
        assert_eq!(
            read_overrides(&root),
            serde_json::json!({"a": "npm:other@1.0.0"})
        );
    }
}
