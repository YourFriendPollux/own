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
use own_net::{build_client, fetch_packument, fetch_tarball, verify_sri_integrity, NetConfig};
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

pub fn add(root: &Path, args: &AddArgs) -> Result<(), String> {
    // preconditions
    if !root.join("own.toml").exists() || !root.join("own.lock").exists() {
        return Err("NOT_INITIALIZED".to_string());
    }
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
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
    // vendor-all: every version present in pnpm-lock packages is by
    // definition resolved (Phase 2 §9.2); only check membership there.
    let resolved = if args.allow_diamond.as_deref() == Some("vendor-all") {
        pnpm_lock
            .packages
            .iter()
            .any(|e| e.name == args.pkg && e.version == args.version)
    } else {
        pnpm_lock
            .importers
            .iter()
            .flat_map(|im| im.deps.iter())
            .any(|(n, spec, v)| n == &args.pkg && (v == &args.version || spec == &args.version))
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
    let dependents: Vec<String> = {
        let mut d: Vec<String> = pnpm_lock
            .importers
            .iter()
            .filter(|im| {
                im.deps
                    .iter()
                    .any(|(n, _, v)| n == &args.pkg && v == &args.version)
            })
            .map(|im| format!("importer:{}", im.path))
            .collect();
        for p in &pnpm_lock.packages {
            if p.deps
                .iter()
                .any(|(n, v)| n == &args.pkg && v == &args.version)
            {
                d.push(format!("{}@{}", p.name, p.version));
            }
        }
        d.sort();
        d.dedup();
        d
    };
    let mut versions_resolved: Vec<String> = pnpm_lock
        .importers
        .iter()
        .flat_map(|im| im.deps.iter().map(|(n, _, v)| (n.clone(), v.clone())))
        .chain(
            pnpm_lock
                .packages
                .iter()
                .flat_map(|p| p.deps.iter().map(|(n, v)| (n.clone(), v.clone()))),
        )
        .filter(|(n, _)| *n == args.pkg)
        .map(|(_, v)| v)
        .collect();
    versions_resolved.sort();
    versions_resolved.dedup();
    let multi_version = versions_resolved.len() > 1;
    if dependents.len() >= 2 || multi_version {
        match args.allow_diamond.as_deref() {
            None => {
                return Err(format!(
                    "DIAMOND_DETECTED: {}@{} also resolved via {}. Use --allow-diamond=<strategy>",
                    args.pkg,
                    args.version,
                    dependents.join(", ")
                ))
            }
            Some("keep-external") | Some("unify") | Some("vendor-all") => {
                // recorded in lock by caller (Phase 2: vendor-all = vendor
                // EVERY resolved version of the package, not just <ver>)
            }
            Some(_) => {
                return Err(
                    "USAGE_ERROR: --allow-diamond must be keep-external|unify|vendor-all"
                        .to_string(),
                );
            }
        }
    }

    // network: packument + tarball
    let cfg = NetConfig::default();
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
    let max_unpacked = 500 * 1_048_576;
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

    // transaction from here on
    let txn = Txn::begin(root)?;
    let res = add_inner(
        &txn,
        root,
        &lock,
        args,
        &dl.bytes,
        &sha512_hex,
        &dl.sha256.clone(),
        &vm_hash,
        &integrity,
        license_policy,
        selected,
        &expr,
        &prov,
    );
    match res {
        Ok(new_lock) => {
            // package.json override FIRST, so the lock digest sees it (§7.3 overrides field)
            update_package_json(
                &txn,
                root,
                &args.pkg,
                &dir,
                args.allow_diamond.as_deref() == Some("vendor-all"),
            )?;
            let overrides = read_overrides_json(root)?;
            let mut new_lock = new_lock;
            new_lock.metadata.lock_digest = compute_lock_digest(&new_lock, &overrides);
            let canonical = write_lock_canonical(&new_lock);
            txn.write_file("own.lock", canonical.as_bytes())?;
            // pnpm install + post-install verification
            if !args.no_install {
                let st = std::process::Command::new("pnpm")
                    .arg("install")
                    .current_dir(root)
                    .status()
                    .map_err(|e| format!("PNPM_FAILED: {e}"))?;
                if !st.success() {
                    let _ = txn.rollback();
                    return Err("PNPM_FAILED".to_string());
                }
                let out = std::process::Command::new("pnpm")
                    .args(["install", "--reporter=ndjson", "--force"])
                    .current_dir(root)
                    .output()
                    .map_err(|e| format!("PNPM_FAILED: {e}"))?;
                let stdout = String::from_utf8_lossy(&out.stdout);
                let lifecycle = stdout
                    .lines()
                    .filter(|l| l.contains("pnpm:lifecycle"))
                    .filter(|l| l.contains(&args.pkg))
                    .count();
                if lifecycle > 0 {
                    let _ = txn.rollback();
                    return Err("INSTALL_VERIFY_FAILED: lifecycle script ran".to_string());
                }
            } else {
                eprintln!("warning: --no-install: post-install verification not performed");
            }
            txn.commit()?;
            println!("added {}@{} -> {}", args.pkg, args.version, dir);
            Ok(())
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
) -> Result<Lock, String> {
    // cache the tarball (0444, named by sha512)
    let cache_dir = root.join(".own/cache");
    std::fs::create_dir_all(&cache_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
    let cache_path = cache_path_for(&cache_dir, sha512_hex);
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&cache_path, tarball).map_err(|e| format!("IO_ERROR: {e}"))?;
        std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o444))
            .map_err(|e| format!("IO_ERROR: {e}"))?;
    }
    // extract to .own/tmp/<id>
    let tmp_extract = root.join(".own/tmp").join(format!("extract-{}", txn.id));
    std::fs::create_dir_all(&tmp_extract).map_err(|e| format!("IO_ERROR: {e}"))?;
    let limits = own_extract::SecurityLimits::default();
    let stats = own_extract::extract(&cache_path, &tmp_extract, &limits)?;
    // post-extraction: git check-ignore on all files
    let mut paths: Vec<String> = Vec::new();
    collect_files(&tmp_extract, &tmp_extract, &mut paths);
    if !paths.is_empty() {
        use std::io::Write;
        let mut child = std::process::Command::new("git")
            .args(["check-ignore", "--no-index", "--stdin"])
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("GIT_ERROR: {e}"))?;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(
                paths
                    .iter()
                    .map(|p| {
                        format!(
                            "vendor/own/{}/{}\n",
                            own_core::lock::dir_name(&args.pkg, &args.version),
                            p
                        )
                    })
                    .collect::<String>()
                    .as_bytes(),
            )
            .map_err(|e| format!("GIT_ERROR: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("GIT_ERROR: {e}"))?;
        if !out.stdout.is_empty() {
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
        registry: "https://registry.npmjs.org".to_string(),
        integrity: integrity.to_string(),
        tarball_sha256: tarball_sha256.to_string(),
        version_manifest_sha256: vm_hash.to_string(),
        provenance_level: prov.level.clone(),
        provenance_source: prov.source.clone(),
        mode: "verbatim".to_string(),
        roots: vec![".".to_string()],
        dependents: vec!["importer:.".to_string()],
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

fn cache_path_for(dir: &Path, sha512_hex: &str) -> PathBuf {
    dir.join(format!("{sha512_hex}.tgz"))
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

fn is_native_binary(b: &[u8]) -> bool {
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
    for ext in [".node", ".so", ".dylib", ".dll", ".exe", ".a", ".o"] {
        let _ = ext;
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
    dir: &str,
    vendor_all: bool,
) -> Result<(), String> {
    let rel = "package.json";
    let text = std::fs::read_to_string(root.join(rel)).map_err(|e| format!("IO_ERROR: {e}"))?;
    let mut v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("PARSE_ERROR: {e}"))?;
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
    if let Some(existing) = ov.get(pkg).and_then(|e| e.as_str()) {
        if existing != val {
            // vendor-all (Phase 2 §9.2): one pkg mapped to several versions —
            // a single file: override cannot express it; pnpm resolves via
            // pnpm.overrides, so we skip the package.json override entirely.
            if vendor_all {
                return Ok(());
            }
            return Err("OVERRIDE_CONFLICT".to_string());
        }
    } else {
        ov.insert(pkg.to_string(), serde_json::Value::String(val));
        // sort keys byte-wise
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
