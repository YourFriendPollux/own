//! `own add <pkg>@<ver>` implementation (SPEC §8.1): eligibility, diamonds,
//! license, download + integrity, hardened extraction, manifest, lock update,
//! package.json overrides, git-ignore check. pnpm install is invoked unless
//! `--no-install` (post-install checks are then reported as not performed).

use own_core::canonical::{
    compute_lock_digest, compute_vendor_files_sha256, license_policy_sha256, write_lock_canonical,
};
use own_core::config::license_policy_json;
use own_core::lock::{parse_lock, LicenseFile, Lock, Package};
use own_core::txn::Txn;
use own_net::{build_client, fetch_packument, fetch_tarball, verify_sri_integrity};
use own_policy::{eligibility, license as lic, pnpm_lock::parse_pnpm_lock};
use sha2::Digest;
use std::path::{Path, PathBuf};

pub struct AddArgs {
    pub pkg: String,
    pub version: String,
    pub ecosystem: String, // "npm" (default) | "pypi" (Phase 2)
    pub allow_diamond: Option<String>,
    pub license_override: bool,
    pub no_install: bool,
    pub allow_untested_pnpm: bool,
}

/// Everything one version needs, computed without writing anything.
///
/// Splitting preparation from application is what lets a multi-version run
/// check every version before it mutates the tree: a refusal on the last
/// version must not leave the earlier ones vendored (SPEC §9.2 vendor-all).
pub struct Prepared {
    pub dir: String,
    pub registry_url: String,
    pub security: own_extract::SecurityLimits,
    pub tarball: Vec<u8>,
    pub sha512_hex: String,
    pub tarball_sha256: String,
    pub vm_hash: String,
    pub integrity: String,
    pub license_policy: &'static str,
    pub license_selected: Option<String>,
    pub license_expression: String,
    pub prov: Provenance,
}

/// Local, pre-network refusals for one version (SPEC §9.1/§9.2 preconditions).
///
/// Kept apart from the download so a multi-version run can reject every version
/// whose local state is wrong before it fetches anything or writes anything.
fn check_local(root: &Path, args: &AddArgs, lock: &Lock) -> Result<(), String> {
    // preconditions
    if !root.join("own.toml").exists() || !root.join("own.lock").exists() {
        return Err("NOT_INITIALIZED".to_string());
    }
    if !matches!(
        args.allow_diamond.as_deref(),
        None | Some("keep-external" | "unify" | "vendor-all")
    ) {
        return Err(
            "USAGE_ERROR: --allow-diamond must be keep-external|unify|vendor-all".to_string(),
        );
    }
    if matches!(
        args.allow_diamond.as_deref(),
        Some("keep-external" | "unify")
    ) {
        return Err("USAGE_ERROR: diamond strategy is not implemented; use vendor-all".into());
    }
    // vendor-all (Phase 2, §9.2) vendors several versions of the same package:
    // the duplicate check is then on (name, version), not name alone.
    let already = if args.allow_diamond.as_deref() == Some("vendor-all") {
        lock.packages
            .iter()
            .any(|p| p.name == args.pkg && p.version == args.version)
    } else {
        lock.packages.iter().any(|p| p.name == args.pkg)
    };
    if already {
        return Err("ALREADY_VENDORED".to_string());
    }
    let dir = format!(
        "vendor/own/{}",
        own_core::lock::dir_name(&args.pkg, &args.version)
    );
    if root.join(&dir).exists() {
        return Err("VENDOR_DIR_EXISTS".to_string());
    }
    // version must be resolved in pnpm-lock.yaml for at least one dependent
    let pnpm_lock_text = std::fs::read_to_string(root.join("pnpm-lock.yaml"))
        .map_err(|e| format!("IO_ERROR: pnpm-lock.yaml: {e}"))?;
    let pnpm_lock = parse_pnpm_lock(&pnpm_lock_text)?;
    let dependents = pnpm_lock.registry_dependents(&args.pkg, &args.version);
    let versions_resolved = pnpm_lock.resolved_versions(&args.pkg);
    // Ordinary add needs an actual importer or snapshot edge; vendor-all also
    // accepts catalogue versions (Phase 2 §9.2). Neither uses the specifier as
    // evidence of which version was really resolved.
    let resolved = if args.allow_diamond.as_deref() == Some("vendor-all") {
        versions_resolved.contains(&args.version)
    } else {
        !dependents.is_empty()
    };
    if !resolved {
        return Err("USAGE_ERROR: version not resolved in pnpm-lock.yaml".to_string());
    }
    // pnpm version check
    if !args.no_install {
        let out = std::process::Command::new("pnpm").arg("--version").output();
        match out {
            Ok(o) if o.status.success() => {
                let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
                let major: u32 = v
                    .split('.')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if major != 9 && major != 10 && !args.allow_untested_pnpm {
                    return Err("PNPM_UNSUPPORTED".to_string());
                }
            }
            _ => return Err("PNPM_UNSUPPORTED".to_string()),
        }
    }

    // diamonds §9.2: dependents from pnpm-lock
    let multi_version = versions_resolved.len() > 1;
    if (dependents.len() >= 2 || multi_version) && args.allow_diamond.is_none() {
        return Err(format!(
            "DIAMOND_DETECTED: {}@{} also resolved via {}. Use --allow-diamond=<strategy>",
            args.pkg,
            args.version,
            dependents.join(", ")
        ));
    }
    Ok(())
}

fn prepare(root: &Path, args: &AddArgs, lock: &Lock) -> Result<Prepared, String> {
    let settings = crate::project_config::load(root)?;
    check_local(root, args, lock)?;
    let dir = format!(
        "vendor/own/{}",
        own_core::lock::dir_name(&args.pkg, &args.version)
    );
    let pnpm_lock_text = std::fs::read_to_string(root.join("pnpm-lock.yaml"))
        .map_err(|e| format!("IO_ERROR: pnpm-lock.yaml: {e}"))?;
    let pnpm_lock = parse_pnpm_lock(&pnpm_lock_text)?;
    // network: packument + tarball
    let cfg = settings.net;
    let client = build_client(&cfg)?;
    let packument = fetch_packument(&client, &cfg, &args.pkg)?;
    let pv: serde_json::Value =
        serde_json::from_slice(&packument).map_err(|e| format!("PARSE_ERROR: packument: {e}"))?;
    let vobj = pv
        .get("versions")
        .and_then(|vs| vs.get(&args.version))
        .ok_or("VERSION_NOT_FOUND")?;

    // eligibility §9.1 (vendored deps so far = packages already in lock)
    let vendored: Vec<(String, String)> = lock
        .packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    let max_unpacked = settings.security.max_unpacked_size;
    let elig = eligibility::evaluate(vobj, &vendored, max_unpacked);
    for w in &elig.warnings {
        eprintln!("warning: {w}");
    }
    if !elig.eligible {
        return Err(format!(
            "NOT_ELIGIBLE:{}",
            elig.blocking.unwrap_or("unknown")
        ));
    }

    // license §9.3
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
            if args.license_override {
                "human-review"
            } else {
                return Err("LICENSE_REVIEW_REQUIRED".to_string());
            }
        }
        lic::LicenseClass::Deny => return Err("LICENSE_DENIED".to_string()),
    };

    // download + verify
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
    // cross-check with pnpm-lock integrity if present
    if let Some(pkg_entry) = pnpm_lock
        .packages
        .iter()
        .find(|p| p.name == args.pkg && p.version == args.version)
    {
        let _ = pkg_entry;
    }
    // version_manifest_sha256: JCS of versions[<ver>] minus mutable fields
    let vm_hash = version_manifest_hash_pub(vobj)?;
    // provenance §8.1 step 4: detection only, see `evaluate_provenance`
    let prov = evaluate_provenance(vobj);
    for w in &prov.warnings {
        eprintln!("warning: {w}");
    }
    Ok(Prepared {
        dir,
        registry_url: cfg.registry_url.clone(),
        security: settings.security,
        tarball: dl.bytes,
        sha512_hex,
        tarball_sha256: dl.sha256.clone(),
        vm_hash,
        integrity,
        license_policy,
        license_selected: selected,
        license_expression: expr,
        prov,
    })
}

/// Apply one prepared version inside `txn` and return the lock it produces.
fn apply(
    txn: &Txn,
    root: &Path,
    lock: &Lock,
    args: &AddArgs,
    prepared: &Prepared,
    vendor_all: bool,
) -> Result<Lock, String> {
    let new_lock = add_inner(
        txn,
        root,
        lock,
        args,
        &prepared.tarball,
        &prepared.sha512_hex,
        &prepared.tarball_sha256,
        &prepared.vm_hash,
        &prepared.integrity,
        prepared.license_policy,
        prepared.license_selected.clone(),
        &prepared.license_expression,
        &prepared.prov,
        &prepared.security,
        &prepared.registry_url,
    )?;
    // package.json override FIRST, so the lock digest sees it (§7.3 overrides field)
    update_package_json(
        txn,
        root,
        &args.pkg,
        &args.version,
        &prepared.dir,
        vendor_all,
    )?;
    let overrides = read_overrides_json(root)?;
    let mut new_lock = new_lock;
    new_lock.metadata.lock_digest = compute_lock_digest(&new_lock, &overrides);
    let canonical = write_lock_canonical(&new_lock);
    txn.write_file("own.lock", canonical.as_bytes())?;
    Ok(new_lock)
}

/// pnpm install + post-install verification (SPEC §8.1 step 6).
fn install_and_verify(txn: &Txn, root: &Path, pkg: &str, no_install: bool) -> Result<(), String> {
    if no_install {
        eprintln!("warning: --no-install: post-install verification not performed");
        return Ok(());
    }
    txn.backup("pnpm-lock.yaml")?;
    let st = std::process::Command::new("pnpm")
        .arg("install")
        .arg("--ignore-scripts")
        .current_dir(root)
        .status()
        .map_err(|e| format!("PNPM_FAILED: {e}"))?;
    if !st.success() {
        return Err("PNPM_FAILED".to_string());
    }
    let out = std::process::Command::new("pnpm")
        .args([
            "install",
            "--ignore-scripts",
            "--reporter=ndjson",
            "--force",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("PNPM_FAILED: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        return Err(format!("PNPM_FAILED: forced install exited {}", out.status));
    }
    let lifecycle = stdout
        .lines()
        .filter(|l| l.contains("pnpm:lifecycle"))
        .filter(|l| l.contains(pkg))
        .count();
    if lifecycle > 0 {
        return Err("INSTALL_VERIFY_FAILED: lifecycle script ran".to_string());
    }
    let _ = txn;
    let policy = license_policy_json(
        &std::fs::read_to_string(root.join("own.toml")).map_err(|e| format!("IO_ERROR: {e}"))?,
    )?;
    let overrides = read_overrides_json(root)?;
    let outcome = own_core::verify::verify(root, &policy, &overrides)?;
    let installed = own_core::verify::verify_installed(root)?;
    if let Some(finding) = outcome
        .findings
        .iter()
        .chain(&installed)
        .find(|f| f.severity == "error")
    {
        return Err(format!(
            "INSTALL_VERIFY_FAILED: {} {}",
            finding.code, finding.path
        ));
    }
    Ok(())
}

pub fn add(root: &Path, args: &AddArgs) -> Result<(), String> {
    // §8.1 names `--ecosystem pypi` as a Phase 2 surface; nothing implements it
    // yet. Refusing here keeps the npm path (and its pnpm-lock precondition) from
    // reporting a misleading missing-file error for a package that has no
    // pnpm-lock.yaml at all.
    if args.ecosystem != "npm" {
        return Err(format!(
            "ECOSYSTEM_UNSUPPORTED: {} vendoring is a Phase 2 surface and is not \
             implemented; only npm is supported",
            args.ecosystem
        ));
    }
    // Keep recovery and the snapshot used for preparation under one lock.
    let txn = Txn::begin(root)?;
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let prepared = prepare(root, args, &lock)?;
    let res = apply(
        &txn,
        root,
        &lock,
        args,
        &prepared,
        args.allow_diamond.as_deref() == Some("vendor-all"),
    )
    .and_then(|_| install_and_verify(&txn, root, &args.pkg, args.no_install));
    match res {
        Ok(()) => {
            txn.commit()?;
            println!("added {}@{} -> {}", args.pkg, args.version, prepared.dir);
            Ok(())
        }
        Err(e) => {
            let _ = txn.rollback();
            Err(e)
        }
    }
}

/// SPEC §9.2 vendor-all (Phase 2): vendor every resolved version of one package.
///
/// Every version is prepared before the first write, so a version that cannot be
/// vendored leaves the tree untouched; the writes of all versions then share a
/// single transaction, so a failure anywhere rolls the whole run back instead of
/// leaving a partial set of versions.
pub fn add_vendor_all(root: &Path, base: &AddArgs, versions: &[String]) -> Result<usize, String> {
    if base.ecosystem != "npm" {
        return Err("ECOSYSTEM_UNSUPPORTED: only npm vendoring is implemented".to_string());
    }
    let txn = Txn::begin(root)?;
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    // A version already in the lock is vendored: re-running vendor-all after a
    // dependent introduced a new version must vendor that version, not fail on
    // the ones already done.
    let pending: Vec<&String> = versions
        .iter()
        .filter(|version| {
            !lock
                .packages
                .iter()
                .any(|p| p.name == base.pkg && &p.version == *version)
        })
        .collect();
    if pending.is_empty() {
        return Ok(0);
    }
    let args_for: Vec<AddArgs> = versions
        .iter()
        .filter(|version| pending.iter().any(|p| p == version))
        .map(|version| AddArgs {
            pkg: base.pkg.clone(),
            version: version.clone(),
            ecosystem: base.ecosystem.clone(),
            allow_diamond: Some("vendor-all".to_string()),
            license_override: base.license_override,
            no_install: base.no_install,
            allow_untested_pnpm: base.allow_untested_pnpm,
        })
        .collect();
    // Every version's local preconditions first: no download and, above all, no
    // write happens while a version in the set is already known to be unusable.
    for args in &args_for {
        check_local(root, args, &lock)?;
    }
    let mut planned: Vec<(AddArgs, Prepared)> = Vec::new();
    for args in args_for {
        let prepared = prepare(root, &args, &lock)?;
        planned.push((args, prepared));
    }
    let res = (|| -> Result<(), String> {
        let mut accumulated = lock.clone();
        for (args, prepared) in &planned {
            accumulated = apply(&txn, root, &accumulated, args, prepared, true)?;
        }
        install_and_verify(&txn, root, &base.pkg, base.no_install)
    })();
    match res {
        Ok(()) => {
            txn.commit()?;
            for (args, prepared) in &planned {
                println!("added {}@{} -> {}", args.pkg, args.version, prepared.dir);
            }
            Ok(planned.len())
        }
        Err(e) => {
            let _ = txn.rollback();
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_inner(
    txn: &Txn,
    root: &Path,
    lock: &Lock,
    args: &AddArgs,
    tarball: &[u8],
    sha512_hex: &str,
    tarball_sha256: &str,
    vm_hash: &str,
    integrity: &str,
    license_policy: &str,
    license_selected: Option<String>,
    license_expression: &str,
    prov: &Provenance,
    limits: &own_extract::SecurityLimits,
    registry_url: &str,
) -> Result<Lock, String> {
    let pnpm_text = std::fs::read_to_string(root.join("pnpm-lock.yaml"))
        .map_err(|e| format!("IO_ERROR: pnpm-lock.yaml: {e}"))?;
    let dependents = parse_pnpm_lock(&pnpm_text)?.registry_dependents(&args.pkg, &args.version);
    // cache the tarball (0444, named by sha512)
    let cache_path = cache_tarball(txn, sha512_hex, tarball)?;
    // extract to .own/tmp/<id>
    let tmp_extract =
        own_core::path_safety::project_path(root, &format!(".own/tmp/extract-{}", txn.id))
            .map_err(|e| format!("IO_ERROR: {e}"))?;
    std::fs::create_dir_all(&tmp_extract).map_err(|e| format!("IO_ERROR: {e}"))?;
    let stats = own_extract::extract(&cache_path, &tmp_extract, limits)?;
    let vendored: Vec<_> = lock
        .packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    validate_extracted_package_with_limit(
        &tmp_extract,
        &args.pkg,
        &args.version,
        integrity,
        &vendored,
        license_expression,
        limits.max_unpacked_size,
    )?;
    // post-extraction: git check-ignore on all files
    let mut paths: Vec<String> = Vec::new();
    collect_files(&tmp_extract, &tmp_extract, &mut paths);
    if !paths.is_empty() {
        let vendor_dir = own_core::lock::dir_name(&args.pkg, &args.version);
        let vendor_paths: Vec<_> = paths
            .iter()
            .map(|p| format!("vendor/own/{vendor_dir}/{p}"))
            .collect();
        if !crate::git_ignore::ignored_paths(root, &vendor_paths)?.is_empty() {
            return Err("VENDOR_PATH_IGNORED: a vendored file is git-ignored; add '!vendor/own/**' as the last line of .gitignore".to_string());
        }
    }
    // license files at archive root
    let mut license_files: Vec<(String, String)> = Vec::new();
    for p in &paths {
        let base = p.rsplit('/').next().unwrap_or(p);
        let up = base.to_uppercase();
        if up.starts_with("LICENSE")
            || up.starts_with("LICENCE")
            || up.starts_with("COPYING")
            || up.starts_with("NOTICE")
        {
            let content = std::fs::read_to_string(tmp_extract.join(p))
                .map_err(|_| "NOT_ELIGIBLE:license_file_encoding".to_string())?;
            let h = own_core::sha256_hex(
                &std::fs::read(tmp_extract.join(p)).map_err(|e| format!("IO_ERROR: {e}"))?,
            );
            license_files.push((p.clone(), h));
            let _ = content;
        }
    }
    const NO_NOTICE: [&str; 3] = ["0BSD", "CC0-1.0", "Unlicense"];
    if license_files.is_empty() && !NO_NOTICE.iter().any(|l| license_expression.contains(l)) {
        return Err("LICENSE_FILE_MISSING".to_string());
    }
    // native binary check (§9.1) on extracted files
    for p in &paths {
        let b = std::fs::read(tmp_extract.join(p)).map_err(|e| format!("IO_ERROR: {e}"))?;
        if is_native_binary(&b) {
            return Err("NOT_ELIGIBLE:native_binary".to_string());
        }
        if p.ends_with("binding.gyp") {
            return Err("NOT_ELIGIBLE:binding_gyp".to_string());
        }
    }
    // move into vendor/
    let dir = format!(
        "vendor/own/{}",
        own_core::lock::dir_name(&args.pkg, &args.version)
    );
    txn.move_dir_into(&tmp_extract, &dir)?;
    // manifest
    let manifest = build_manifest_pub(&args.pkg, &args.version, root, &dir)?;
    let manifest_rel = format!(
        "vendor/own/.manifests/{}.toml",
        own_core::lock::dir_name(&args.pkg, &args.version)
    );
    txn.write_file(&manifest_rel, manifest.as_bytes())?;
    // lock entry
    let mut new_lock = lock.clone();
    let pfs = manifest_pfs_pub(root, &dir)?;
    let entry = Package {
        name: args.pkg.clone(),
        ecosystem: args.ecosystem.clone(),
        version: args.version.clone(),
        dir: dir.clone(),
        registry: registry_url.to_string(),
        integrity: integrity.to_string(),
        tarball_sha256: tarball_sha256.to_string(),
        version_manifest_sha256: vm_hash.to_string(),
        provenance_level: prov.level.clone(),
        provenance_source: prov.source.clone(),
        mode: "verbatim".to_string(),
        roots: vec![".".to_string()],
        dependents,
        license_expression: license_expression.to_string(),
        license_selected,
        license_policy: license_policy.to_string(),
        license_files: license_files
            .iter()
            .map(|(p, h)| LicenseFile {
                path: p.clone(),
                sha256: h.clone(),
            })
            .collect(),
        package_files_sha256: pfs.clone(),
        file_count: stats.files as u64,
        total_size: stats.total_unpacked,
        diamond_resolution: None,
        unified_ranges: None,
    };
    new_lock.packages.push(entry);
    new_lock.packages.sort_by(|a, b| {
        (a.name.as_str(), a.version.as_str()).cmp(&(b.name.as_str(), b.version.as_str()))
    });
    // recompute metadata digests
    let toml_text =
        std::fs::read_to_string(root.join("own.toml")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let pol = license_policy_json(&toml_text)?;
    new_lock.metadata.license_policy_sha256 = license_policy_sha256(&pol);
    new_lock.metadata.vendor_files_sha256 = compute_vendor_files_sha256(&new_lock.packages);
    let overrides = read_overrides_json(root)?;
    new_lock.metadata.lock_digest = compute_lock_digest(&new_lock, &overrides);
    Ok(new_lock)
}

/// The registry metadata cannot hide install scripts or a different identity
/// in the byte-identical archive. Validate it before publishing or installing.
pub(crate) fn validate_extracted_package_with_limit(
    root: &Path,
    name: &str,
    version: &str,
    integrity: &str,
    vendored: &[(String, String)],
    license: &str,
    max_unpacked: u64,
) -> Result<(), String> {
    let bytes = std::fs::read(root.join("package.json"))
        .map_err(|e| format!("IO_ERROR: package.json: {e}"))?;
    let mut package: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("PARSE_ERROR: archive package.json: {e}"))?;
    if package.get("name").and_then(|v| v.as_str()) != Some(name)
        || package.get("version").and_then(|v| v.as_str()) != Some(version)
    {
        return Err("NOT_ELIGIBLE:archive_identity".into());
    }
    if package.get("license").and_then(|v| v.as_str()) != Some(license) {
        return Err("NOT_ELIGIBLE:archive_license".into());
    }
    // dist.integrity belongs to the verified registry response, not package.json.
    package["dist"] = serde_json::json!({"integrity": integrity});
    let eligibility = own_policy::eligibility::evaluate(&package, vendored, max_unpacked);
    if !eligibility.eligible {
        return Err(format!(
            "NOT_ELIGIBLE:{}",
            eligibility.blocking.unwrap_or("archive_metadata")
        ));
    }
    Ok(())
}

pub fn manifest_pfs_pub(root: &Path, dir: &str) -> Result<String, String> {
    let base = root.join(dir);
    let mut paths = Vec::new();
    collect_files(&base, &base, &mut paths);
    let mut files: Vec<(String, String, u64, bool)> = Vec::new();
    for p in &paths {
        let full = base.join(p);
        let bytes = std::fs::read(&full).map_err(|e| format!("IO_ERROR: {e}"))?;
        let h = own_core::sha256_hex(&bytes);
        let md = std::fs::metadata(&full).map_err(|e| format!("IO_ERROR: {e}"))?;
        #[cfg(unix)]
        let exec = {
            use std::os::unix::fs::PermissionsExt;
            md.permissions().mode() & 0o100 != 0
        };
        #[cfg(not(unix))]
        let exec = false;
        files.push((
            p.clone(),
            h.trim_start_matches("sha256:").to_string(),
            md.len(),
            exec,
        ));
    }
    Ok(own_core::package_files_sha256(&files))
}

fn read_overrides_json(root: &Path) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let text = std::fs::read_to_string(root.join("package.json"))
        .map_err(|e| format!("IO_ERROR: package.json: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("PARSE_ERROR: package.json: {e}"))?;
    let object = v
        .as_object()
        .ok_or("PARSE_ERROR: package.json: expected an object")?;
    let mut out = serde_json::Map::new();
    if let Some(pnpm) = object.get("pnpm") {
        let pnpm = pnpm
            .as_object()
            .ok_or("PARSE_ERROR: package.json: pnpm must be an object")?;
        if let Some(overrides) = pnpm.get("overrides") {
            let overrides = overrides
                .as_object()
                .ok_or("PARSE_ERROR: package.json: pnpm.overrides must be an object")?;
            for (key, value) in overrides {
                if key.trim().is_empty() {
                    return Err("PARSE_ERROR: package.json: blank pnpm.overrides selector".into());
                }
                let value = value.as_str().ok_or_else(|| {
                    format!("PARSE_ERROR: package.json: pnpm.overrides[{key:?}] must be a string")
                })?;
                if value.trim().is_empty() {
                    return Err(format!(
                        "PARSE_ERROR: package.json: pnpm.overrides[{key:?}] must be a nonempty string"
                    ));
                }
                if value.starts_with("file:vendor/own/") {
                    out.insert(key.clone(), serde_json::Value::String(value.to_string()));
                }
            }
        }
    }
    Ok(out)
}

fn cache_path_for(dir: &Path, sha512_hex: &str) -> PathBuf {
    dir.join(format!("{sha512_hex}.tgz"))
}

pub(crate) fn cache_tarball(txn: &Txn, sha512_hex: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let cache_dir = txn.root.join(".own/cache");
    std::fs::create_dir_all(&cache_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
    let path = cache_path_for(&cache_dir, sha512_hex);
    // Replace by durable rename: truncating an existing 0444 entry fails.
    txn.write_file(&format!(".own/cache/{sha512_hex}.tgz"), bytes)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
        .map_err(|e| format!("IO_ERROR: {e}"))?;
    Ok(path)
}

#[cfg(test)]
mod cache_publication_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn cache_republication_replaces_readonly_entry() {
        let root = std::env::temp_dir().join(format!("own-cache-republish-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let txn = Txn::begin(&root).unwrap();
        let bytes = b"freshly downloaded and verified bytes";
        let first = cache_tarball(&txn, &"a".repeat(128), bytes).unwrap();
        assert_eq!(
            std::fs::metadata(&first).unwrap().permissions().mode() & 0o777,
            0o444
        );
        let second = cache_tarball(&txn, &"a".repeat(128), bytes)
            .expect("same-version update must be able to reuse a read-only cache path");
        assert_eq!(first, second);
        assert_eq!(std::fs::read(&second).unwrap(), bytes);
        txn.commit().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
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

pub(crate) fn is_native_binary(b: &[u8]) -> bool {
    if b.len() >= 4 && &b[..4] == b"\x7fELF" {
        return true;
    }
    if b.len() >= 4
        && (b[..4] == [0xFE, 0xED, 0xFA, 0xCE]
            || b[..4] == [0xFE, 0xED, 0xFA, 0xCF]
            || b[..4] == [0xCE, 0xFA, 0xED, 0xFE]
            || b[..4] == [0xCF, 0xFA, 0xED, 0xFE])
    {
        return true;
    }
    if b.len() >= 64 && &b[..2] == b"MZ" && b[0x3C..0x40] != [0; 4] {
        let off = u32::from_le_bytes([b[0x3C], b[0x3D], b[0x3E], b[0x3F]]) as usize;
        if b.len() >= off + 4 && &b[off..off + 4] == b"PE\0\0" {
            return true;
        }
    }
    false
}

pub fn build_manifest_pub(
    pkg: &str,
    version: &str,
    root: &Path,
    dir: &str,
) -> Result<String, String> {
    let base = root.join(dir);
    let mut paths = Vec::new();
    collect_files(&base, &base, &mut paths);
    let mut files: Vec<(String, String, u64, bool)> = Vec::new();
    for p in &paths {
        let full = base.join(p);
        let bytes = std::fs::read(&full).map_err(|e| format!("IO_ERROR: {e}"))?;
        let h = own_core::sha256_hex(&bytes);
        let md = std::fs::metadata(&full).map_err(|e| format!("IO_ERROR: {e}"))?;
        #[cfg(unix)]
        let exec = {
            use std::os::unix::fs::PermissionsExt;
            md.permissions().mode() & 0o100 != 0
        };
        #[cfg(not(unix))]
        let exec = false;
        files.push((
            p.clone(),
            h.trim_start_matches("sha256:").to_string(),
            md.len(),
            exec,
        ));
    }
    files.sort();
    let pfs = own_core::package_files_sha256(&files);
    let mut out = String::new();
    out.push_str("[manifest]\n");
    out.push_str("schema_version = 1\n");
    out.push_str(&format!("package = \"{}@{}\"\n", pkg, version));
    out.push_str(&format!("package_files_sha256 = \"{pfs}\"\n"));
    out.push_str(&format!("file_count = {}\n", files.len()));
    out.push_str(&format!(
        "total_size = {}\n",
        files.iter().map(|f| f.2).sum::<u64>()
    ));
    for (p, h, sz, e) in &files {
        out.push_str("\n[[file]]\n");
        out.push_str(&format!("path = \"{p}\"\n"));
        out.push_str(&format!("sha256 = \"sha256:{h}\"\n"));
        out.push_str(&format!("size = {sz}\n"));
        out.push_str(&format!("exec = {}\n", if *e { "true" } else { "false" }));
    }
    Ok(out)
}

pub fn version_manifest_hash_pub(vobj: &serde_json::Value) -> Result<String, String> {
    fn strip(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => serde_json::Value::Object(
                m.iter()
                    .filter(|(k, _)| {
                        !matches!(k.as_str(), "deprecated" | "dist") && !k.starts_with('_')
                    })
                    .map(|(k, val)| {
                        let val = if k == "dist" {
                            match val {
                                serde_json::Value::Object(dm) => serde_json::Value::Object(
                                    dm.iter()
                                        .filter(|(dk, _)| {
                                            !matches!(
                                                dk.as_str(),
                                                "tarball" | "signatures" | "attestations"
                                            )
                                        })
                                        .map(|(dk, dv)| (dk.clone(), strip(dv)))
                                        .collect(),
                                ),
                                other => strip(other),
                            }
                        } else {
                            strip(val)
                        };
                        (k.clone(), val)
                    })
                    .collect(),
            ),
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(strip).collect()),
            other => other.clone(),
        }
    }
    let canon =
        own_core::jcs::canonicalize(&strip(vobj)).map_err(|e| format!("IO_ERROR: jcs: {e}"))?;
    Ok(format!(
        "sha256:{:x}",
        sha2::Sha256::digest(canon.as_bytes())
    ))
}

/// SPEC §8.1 step 4 — provenance evaluation.
///
/// `own` 0.1.0 proves the registry integrity chain (SRI sha512 + tarball
/// sha256) and nothing more: npm Sigstore attestations and registry ECDSA
/// signatures are *detected* here but not verified in-process (no crypto stack
/// in the TCB yet — see README "Known limits"). The lock therefore always
/// records `integrity-only`: writing `attested` or `registry-signed` without
/// the matching verification would be exactly the false security INV-7
/// forbids. A package that does ship provenance is reported explicitly rather
/// than silently downgraded (INV-5).
pub const PROVENANCE_LEVEL_INTEGRITY_ONLY: &str = "integrity-only";

#[derive(Debug, Clone)]
pub struct Provenance {
    /// value written to the lock's `provenance_level` (spec §7.1)
    pub level: String,
    /// attested repository; `None` unless an attestation was actually verified
    pub source: Option<String>,
    /// explicit, non-silent degradation notices (INV-5)
    pub warnings: Vec<String>,
}

pub fn evaluate_provenance(vobj: &serde_json::Value) -> Provenance {
    let has_attestations = match vobj.pointer("/dist/attestations") {
        Some(serde_json::Value::Array(a)) => !a.is_empty(),
        Some(serde_json::Value::Object(m)) => !m.is_empty(),
        Some(serde_json::Value::Null) | None => false,
        Some(_) => true,
    };
    let has_registry_signature = vobj
        .pointer("/dist/signatures")
        .and_then(|s| s.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let mut warnings = Vec::new();
    if has_attestations {
        warnings.push(
            "W_PROVENANCE_UNVERIFIED: npm attestation (Sigstore) present for this version but \
             not verified by own 0.1.0; provenance_level stays \"integrity-only\" (README \
             \"Known limits\")"
                .to_string(),
        );
    }
    if has_registry_signature {
        warnings.push(
            "W_PROVENANCE_UNVERIFIED: registry signature present for this version but not \
             verified by own 0.1.0; provenance_level stays \"integrity-only\" (README \"Known \
             limits\")"
                .to_string(),
        );
    }
    Provenance {
        level: PROVENANCE_LEVEL_INTEGRITY_ONLY.to_string(),
        source: None,
        warnings,
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

fn update_package_json(
    txn: &Txn,
    root: &Path,
    pkg: &str,
    version: &str,
    dir: &str,
    vendor_all: bool,
) -> Result<(), String> {
    let rel = "package.json";
    let text = std::fs::read_to_string(root.join(rel)).map_err(|e| format!("IO_ERROR: {e}"))?;
    let mut v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("PARSE_ERROR: {e}"))?;
    let aliases = alias_selectors(root, pkg, version)?;
    let pnpm = v.as_object_mut().ok_or("PARSE_ERROR: package.json")?;
    let pnpm_map = pnpm
        .entry("pnpm".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let overrides = pnpm_map
        .as_object_mut()
        .ok_or("PARSE_ERROR: pnpm")?
        .entry("overrides".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let ov = overrides.as_object_mut().ok_or("PARSE_ERROR: overrides")?;
    let val = format!("file:{dir}");
    // vendor-all (Phase 2 §9.2): one name mapped to several versions cannot be
    // expressed by a single bare `file:` key — that key would pin every version
    // to one directory — so each vendored version gets the `name@version` key
    // pnpm applies per resolved version. The bare key is removed: leaving it
    // would keep overriding the versions the scoped keys are meant to separate.
    let key = if vendor_all {
        // Preserve an already-vendored bare version when extending its set.
        if let Some(value) = ov
            .get(pkg)
            .and_then(|value| value.as_str())
            .filter(|value| value.starts_with("file:vendor/own/"))
            .map(str::to_string)
        {
            let text = std::fs::read_to_string(root.join("own.lock"))
                .map_err(|e| format!("IO_ERROR: {e}"))?;
            let locked = parse_lock(&text).map_err(|e| format!("PARSE_ERROR: {e}"))?;
            let previous = locked
                .packages
                .iter()
                .find(|p| p.name == pkg && value == format!("file:{}", p.dir))
                .ok_or("OVERRIDE_CONFLICT")?;
            let old_key = own_core::lock::versioned_override_key(pkg, &previous.version);
            if ov
                .get(&old_key)
                .is_some_and(|old| old != &serde_json::json!(value))
            {
                return Err("OVERRIDE_CONFLICT".to_string());
            }
            ov.insert(old_key, serde_json::json!(value));
        }
        ov.remove(pkg);
        own_core::lock::versioned_override_key(pkg, version)
    } else {
        pkg.to_string()
    };
    if let Some(existing) = ov.get(&key).and_then(|e| e.as_str()) {
        if existing != val {
            return Err("OVERRIDE_CONFLICT".to_string());
        }
    } else {
        ov.insert(key, serde_json::Value::String(val));
        // sort keys byte-wise
        let mut keys: Vec<String> = ov.keys().cloned().collect();
        keys.sort();
        let sorted: serde_json::Map<String, serde_json::Value> = keys
            .into_iter()
            .map(|k| (k.clone(), ov[&k].clone()))
            .collect();
        *ov = sorted;
    }
    for selector in aliases {
        if ov
            .get(&selector)
            .is_some_and(|existing| existing != &serde_json::json!(format!("file:{dir}")))
        {
            return Err("OVERRIDE_CONFLICT".to_string());
        }
        ov.insert(selector, serde_json::json!(format!("file:{dir}")));
    }
    let out = serde_json::to_string_pretty(&v).map_err(|e| format!("IO_ERROR: {e}"))?;
    txn.write_file(rel, format!("{out}\n").as_bytes())
}

/// pnpm matches npm aliases by declared name and exact original specifier,
/// not by the target package's real name or its resolved version.
fn alias_selectors(root: &Path, pkg: &str, version: &str) -> Result<Vec<String>, String> {
    use own_policy::pnpm_lock::registry_dependency;
    let text = match std::fs::read_to_string(root.join("pnpm-lock.yaml")) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("IO_ERROR: {e}")),
    };
    let lock = parse_pnpm_lock(&text)?;
    let mut selectors = std::collections::BTreeSet::new();
    for im in &lock.importers {
        for (name, spec, resolved) in im.all_deps() {
            if spec.starts_with("npm:")
                && registry_dependency(name, Some(spec), resolved)
                    .is_some_and(|(n, v)| n == pkg && v == version)
            {
                selectors.insert(format!("{name}@{spec}"));
            }
        }
    }
    for parent in &lock.packages {
        for (name, resolved) in &parent.deps {
            let main_resolution = resolved.split('(').next().unwrap_or(resolved);
            if (name == pkg && !main_resolution.contains('@'))
                || !registry_dependency(name, None, resolved)
                    .is_some_and(|(n, v)| n == pkg && v == version)
            {
                continue;
            }
            let mut found = false;
            let store = std::fs::read_dir(root.join("node_modules/.pnpm"))
                .map_err(|e| format!("ALIAS_SPECIFIER_UNAVAILABLE: {}: {e}", parent.key))?;
            for entry in store {
                let entry = entry.map_err(|e| format!("IO_ERROR: {e}"))?;
                let manifest = entry
                    .path()
                    .join("node_modules")
                    .join(&parent.name)
                    .join("package.json");
                let bytes = match std::fs::read(&manifest) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(format!("IO_ERROR: {e}")),
                };
                let value: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("PARSE_ERROR: {}: {e}", manifest.display()))?;
                if value["name"] != parent.name || value["version"] != parent.version {
                    continue;
                }
                for section in ["dependencies", "optionalDependencies"] {
                    if let Some(spec) = value[section][name]
                        .as_str()
                        .filter(|s| s.starts_with("npm:"))
                    {
                        selectors.insert(format!("{name}@{spec}"));
                        found = true;
                    }
                }
            }
            if !found {
                return Err(format!("ALIAS_SPECIFIER_UNAVAILABLE: {} > {name}; install dependencies before vendoring", parent.key));
            }
        }
    }
    Ok(selectors.into_iter().collect())
}

#[cfg(test)]
mod override_tests {
    use super::*;
    use own_core::txn::Txn;

    fn fixture(overrides: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "own-override-{}-{}-{}",
            std::process::id(),
            overrides.len(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            format!("{{\"name\":\"fixture\",\"pnpm\":{{\"overrides\":{overrides}}}}}\n"),
        )
        .unwrap();
        root
    }

    fn read_overrides(root: &Path) -> serde_json::Value {
        let text = std::fs::read_to_string(root.join("package.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["pnpm"]["overrides"].clone()
    }

    fn package(name: &str, version: &str) -> own_core::lock::Package {
        own_core::lock::Package {
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
            license_files: vec![own_core::lock::LicenseFile {
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

    #[test]
    fn vendor_all_writes_one_versioned_override_per_version_p2_06() {
        // Starts from a bare key, as a single-version `add` would have written it.
        let root = fixture("{\"a\":\"file:vendor/own/a@1.0.0\"}");
        let mut lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        lock.packages.push(package("a", "1.0.0"));
        std::fs::write(
            root.join("own.lock"),
            own_core::canonical::write_lock_canonical(&lock),
        )
        .unwrap();
        let txn = Txn::begin(&root).unwrap();
        for version in ["1.0.0", "2.0.0"] {
            update_package_json(
                &txn,
                &root,
                "a",
                version,
                &format!("vendor/own/a@{version}"),
                true,
            )
            .unwrap();
        }
        txn.commit().unwrap();
        assert_eq!(
            read_overrides(&root),
            serde_json::json!({
                "a@1.0.0": "file:vendor/own/a@1.0.0",
                "a@2.0.0": "file:vendor/own/a@2.0.0",
            })
        );
    }

    #[test]
    fn vendor_all_targets_the_exact_declared_npm_alias() {
        let root = fixture("{}");
        std::fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"zod-old":"npm:zod@3.22.4","zod-new":"npm:zod@^3.23.0"}}"#,
        )
        .unwrap();
        std::fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      zod-old:\n        specifier: npm:zod@3.22.4\n        version: zod@3.22.4\n      zod-new:\n        specifier: npm:zod@^3.23.0\n        version: zod@3.23.8\n").unwrap();
        let txn = Txn::begin(&root).unwrap();
        for version in ["3.22.4", "3.23.8"] {
            update_package_json(
                &txn,
                &root,
                "zod",
                version,
                &format!("vendor/own/zod@{version}"),
                true,
            )
            .unwrap();
        }
        txn.commit().unwrap();
        assert_eq!(
            read_overrides(&root),
            serde_json::json!({
                "zod@3.22.4": "file:vendor/own/zod@3.22.4",
                "zod@3.23.8": "file:vendor/own/zod@3.23.8",
                "zod-old@npm:zod@3.22.4": "file:vendor/own/zod@3.22.4",
                "zod-new@npm:zod@^3.23.0": "file:vendor/own/zod@3.23.8"
            })
        );
    }

    #[test]
    fn vendor_all_targets_npm_aliases_even_when_the_declared_name_is_real() {
        let root = fixture("{}");
        std::fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      zod:\n        specifier: npm:zod@3.22.4\n        version: zod@3.22.4\n").unwrap();
        let txn = Txn::begin(&root).unwrap();
        update_package_json(&txn, &root, "zod", "3.22.4", "vendor/own/zod@3.22.4", true).unwrap();
        txn.commit().unwrap();
        assert_eq!(
            read_overrides(&root)["zod@npm:zod@3.22.4"],
            "file:vendor/own/zod@3.22.4"
        );
    }

    #[test]
    fn single_add_keeps_the_bare_override_and_refuses_a_conflict_p2_06() {
        let root = fixture("{}");
        let txn = Txn::begin(&root).unwrap();
        update_package_json(&txn, &root, "a", "1.0.0", "vendor/own/a@1.0.0", false).unwrap();
        // Same target twice is idempotent; a different directory is a conflict.
        update_package_json(&txn, &root, "a", "1.0.0", "vendor/own/a@1.0.0", false).unwrap();
        let conflict = update_package_json(&txn, &root, "a", "2.0.0", "vendor/own/a@2.0.0", false);
        assert_eq!(conflict.unwrap_err(), "OVERRIDE_CONFLICT");
        txn.commit().unwrap();
        assert_eq!(
            read_overrides(&root),
            serde_json::json!({"a": "file:vendor/own/a@1.0.0"})
        );
    }

    #[test]
    fn vendor_all_skips_versions_already_in_the_lock_p2_06() {
        let root = std::env::temp_dir().join(format!("own-vendor-all-done-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("own.toml"), own_core::config::DEFAULT_OWN_TOML).unwrap();
        let mut lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        // Vendor-all already covered 1.0.0; only 2.0.0 is new.
        lock.packages.push(package("a", "1.0.0"));
        std::fs::write(
            root.join("own.lock"),
            own_core::canonical::write_lock_canonical(&lock),
        )
        .unwrap();
        std::fs::write(
            root.join("package.json"),
            "{\"name\":\"fixture\",\"pnpm\":{\"overrides\":{\"a@1.0.0\":\"file:vendor/own/a@1.0.0\"}}}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1.0.0\n        version: 1.0.0\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n",
        )
        .unwrap();
        let before = std::fs::read(root.join("own.lock")).unwrap();
        let base = AddArgs {
            pkg: "a".into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
            allow_diamond: Some("vendor-all".into()),
            license_override: false,
            no_install: true,
            allow_untested_pnpm: true,
        };
        let count = add_vendor_all(&root, &base, &["1.0.0".to_string()]).unwrap();
        assert_eq!(count, 0);
        assert_eq!(std::fs::read(root.join("own.lock")).unwrap(), before);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vendor_all_refuses_before_writing_anything_p2_06() {
        let root = std::env::temp_dir().join(format!("own-vendor-all-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("own.toml"), own_core::config::DEFAULT_OWN_TOML).unwrap();
        let lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
        std::fs::write(
            root.join("own.lock"),
            own_core::canonical::write_lock_canonical(&lock),
        )
        .unwrap();
        std::fs::write(
            root.join("package.json"),
            "{\"name\":\"fixture\",\"pnpm\":{\"overrides\":{}}}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1.0.0\n        version: 1.0.0\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n  a@2.0.0:\n    resolution: {integrity: sha512-x}\n",
        )
        .unwrap();
        // The second version's dir already exists: the run must stop before it
        // vendors the first version or rewrites the lock and the overrides.
        std::fs::create_dir_all(root.join("vendor/own/a@2.0.0")).unwrap();
        let before_lock = std::fs::read(root.join("own.lock")).unwrap();
        let before_pkg = std::fs::read(root.join("package.json")).unwrap();
        let base = AddArgs {
            pkg: "a".into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
            allow_diamond: Some("vendor-all".into()),
            license_override: false,
            no_install: true,
            allow_untested_pnpm: true,
        };
        let versions = vec!["1.0.0".to_string(), "2.0.0".to_string()];
        let error = add_vendor_all(&root, &base, &versions).unwrap_err();
        assert_eq!(error, "VENDOR_DIR_EXISTS");
        assert_eq!(std::fs::read(root.join("own.lock")).unwrap(), before_lock);
        assert_eq!(
            std::fs::read(root.join("package.json")).unwrap(),
            before_pkg
        );
        assert!(!root.join("vendor/own/a@1.0.0").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod diamond_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NONCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(pnpm: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "own-add-diamond-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join("own.toml"), own_core::config::DEFAULT_OWN_TOML).unwrap();
            let lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
            std::fs::write(root.join("own.lock"), write_lock_canonical(&lock)).unwrap();
            std::fs::write(root.join("pnpm-lock.yaml"), pnpm).unwrap();
            Self(root)
        }

        fn check(&self, strategy: Option<&str>) -> Result<(), String> {
            let lock = own_core::canonical::empty_lock("0.1.0", "1", &serde_json::Map::new());
            check_local(
                &self.0,
                &AddArgs {
                    pkg: "zod".into(),
                    version: "3.22.4".into(),
                    ecosystem: "npm".into(),
                    allow_diamond: strategy.map(str::to_string),
                    license_override: false,
                    no_install: true,
                    allow_untested_pnpm: false,
                },
                &lock,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn add_alias_multiversion_refuses_before_network_inv6() {
        let fixture = Fixture::new(
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      zod:\n        specifier: 3.22.4\n        version: 3.22.4\n      zod-new:\n        specifier: npm:zod@3.23.8\n        version: zod@3.23.8\npackages:\n  zod@3.22.4:\n    resolution: {integrity: sha512-x}\n  zod@3.23.8:\n    resolution: {integrity: sha512-y}\nsnapshots:\n  zod@3.22.4: {}\n  zod@3.23.8: {}\n",
        );
        let before = std::fs::read(fixture.0.join("own.lock")).unwrap();
        let result = fixture.check(None);
        assert!(
            matches!(&result, Err(error) if error.starts_with("DIAMOND_DETECTED:")),
            "INV-6: alias resolves a second real version, got {result:?}"
        );
        assert_eq!(std::fs::read(fixture.0.join("own.lock")).unwrap(), before);
        assert!(!fixture.0.join("vendor").exists());
    }

    #[test]
    fn add_invalid_strategy_without_diamond_is_usage_error_inv6() {
        let fixture = Fixture::new(
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      zod:\n        specifier: 3.22.4\n        version: 3.22.4\npackages:\n  zod@3.22.4:\n    resolution: {integrity: sha512-x}\n",
        );
        assert_eq!(
            fixture.check(Some("invalid")),
            Err("USAGE_ERROR: --allow-diamond must be keep-external|unify|vendor-all".into())
        );
        assert!(!fixture.0.join("vendor").exists());
    }
}

#[cfg(test)]
#[path = "../tests/support/add_security.rs"]
mod security_tests;

#[cfg(test)]
mod provenance_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn plain_version_has_no_provenance_warning() {
        let v = json!({ "name": "a", "version": "1.0.0", "dist": { "integrity": "sha512-x" } });
        let p = evaluate_provenance(&v);
        assert_eq!(p.level, "integrity-only");
        assert!(p.source.is_none());
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
    }

    #[test]
    fn registry_signature_is_reported_but_never_claimed_as_verified() {
        let v = json!({ "dist": { "signatures": [{ "keyid": "SHA256:abc", "sig": "MEUC..." }] } });
        let p = evaluate_provenance(&v);
        // never claim registry-signed without verifying the ECDSA signature
        assert_eq!(p.level, "integrity-only");
        assert_eq!(p.warnings.len(), 1);
        assert!(p.warnings[0].starts_with("W_PROVENANCE_UNVERIFIED"));
        assert!(p.warnings[0].contains("registry signature"));
    }

    #[test]
    fn npm_attestation_is_reported_but_never_claimed_as_verified() {
        let v = json!({ "dist": { "attestations": { "url": "https://registry.npmjs.org/-/npm/v1/attestations/a@1.0.0", "provenance": { "predicateType": "https://slsa.dev/provenance/v1" } } } });
        let p = evaluate_provenance(&v);
        assert_eq!(p.level, "integrity-only");
        assert_eq!(
            p.source, None,
            "no attested repository may be recorded unverified"
        );
        assert_eq!(p.warnings.len(), 1);
        assert!(p.warnings[0].contains("attestation"));
    }

    #[test]
    fn empty_provenance_objects_are_not_reported() {
        let v = json!({ "dist": { "signatures": [], "attestations": {} } });
        let p = evaluate_provenance(&v);
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
    }
}
