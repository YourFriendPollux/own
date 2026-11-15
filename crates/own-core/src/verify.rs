//! Offline verification of the vendored tree against `own.lock` (SPEC §8.1 `verify`,
//! without `--installed`/`--remote` which belong to later crates).
//!
//! Order of checks (normative, §8.1): schema, canonical bytes, dir form,
//! manifest consistency, per-file drift, extra files/symlinks, license files,
//! orphans, overrides, LICENSES.md, recomputed digests.

use crate::canonical::{
    compute_lock_digest, compute_vendor_files_sha256, license_policy_sha256, write_lock_canonical,
};
use crate::lock::{parse_manifest, Lock, Manifest};
use crate::toml_write;
use crate::{package_files_sha256, sha256_hex};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Finding {
    pub code: String,
    pub severity: String, // "error" | "warning"
    pub package: String,
    pub path: String,
    pub message: String,
}

impl Finding {
    fn err(code: &str, package: &str, path: &str, message: &str) -> Self {
        Finding {
            code: code.to_string(),
            severity: "error".into(),
            package: package.into(),
            path: path.into(),
            message: message.into(),
        }
    }
}

pub struct VerifyOutcome {
    pub findings: Vec<Finding>,
    /// The canonical re-serialization of the parsed lock (for LOCK_NOT_CANONICAL check).
    pub lock_canonical: String,
}

/// Verify `root` against its `own.lock`. `policy_json` is the `[license]` section
/// of own.toml as JSON (for license_policy_sha256). `overrides` = file:vendor/own/
/// entries of the root package.json pnpm.overrides.
pub fn verify(
    root: &Path,
    policy_json: &serde_json::Value,
    overrides: &serde_json::Map<String, serde_json::Value>,
) -> Result<VerifyOutcome, String> {
    crate::config::validate_license_policy(policy_json)?;
    let canonical_root = fs::canonicalize(root).map_err(|e| format!("IO_ERROR: {e}"))?;
    let root = canonical_root.as_path();
    let mut findings: Vec<Finding> = Vec::new();

    let lock_path =
        crate::path_safety::project_path(root, "own.lock").map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock_text = fs::read_to_string(&lock_path)
        .map_err(|e| format!("IO_ERROR: own.lock unreadable: {e}"))?;
    let lock: Lock =
        crate::lock::parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    if lock.metadata.schema_version != crate::canonical::SCHEMA_VERSION {
        return Err(format!(
            "LOCK_SCHEMA_UNSUPPORTED: {}",
            lock.metadata.schema_version
        ));
    }
    let canonical = write_lock_canonical(&lock);
    if canonical != lock_text {
        findings.push(Finding::err(
            "LOCK_NOT_CANONICAL",
            "",
            "own.lock",
            "lock bytes differ from canonical serialization",
        ));
    }

    let vendor = crate::path_safety::project_path(root, "vendor/own")
        .map_err(|e| format!("IO_ERROR: {e}"))?;
    let manifests = crate::path_safety::project_path(root, "vendor/own/.manifests")
        .map_err(|e| format!("IO_ERROR: {e}"))?;

    let mut seen_dirs: BTreeSet<String> = BTreeSet::new();
    let mut seen_manifests: BTreeSet<String> = BTreeSet::new();

    for pkg in &lock.packages {
        seen_dirs.insert(pkg.dir.clone());
        let expected_dir = format!(
            "vendor/own/{}",
            crate::lock::dir_name(&pkg.name, &pkg.version)
        );
        if pkg.dir != expected_dir {
            findings.push(Finding::err(
                "DRIFT_ORPHAN",
                &format!("{}@{}", pkg.name, pkg.version),
                &pkg.dir,
                "dir field != vendor/own/<name>@<version>",
            ));
            continue; // Never read a path that disagrees with the lock identity.
        }
        // manifest
        let pkg_root = crate::path_safety::project_path(root, &pkg.dir)
            .map_err(|e| format!("IO_ERROR: {e}"))?;
        let manifest_rel = format!(
            "vendor/own/.manifests/{}.toml",
            crate::lock::dir_name(&pkg.name, &pkg.version)
        );
        let mpath = crate::path_safety::project_path(root, &manifest_rel)
            .map_err(|e| format!("IO_ERROR: {e}"))?;
        seen_manifests.insert(format!(
            "{}.toml",
            crate::lock::dir_name(&pkg.name, &pkg.version)
        ));
        let mtext = match fs::read_to_string(&mpath) {
            Ok(t) => t,
            Err(_) => {
                findings.push(Finding::err(
                    "DRIFT_MISSING",
                    &format!("{}@{}", pkg.name, pkg.version),
                    &mpath.display().to_string(),
                    "manifest missing",
                ));
                continue;
            }
        };
        let manifest: Manifest = match parse_manifest(&mtext) {
            Ok(m) => m,
            Err(e) => {
                findings.push(Finding::err(
                    "PARSE_ERROR",
                    &pkg.name,
                    &mpath.display().to_string(),
                    &format!("manifest: {e}"),
                ));
                continue;
            }
        };
        let pdir = format!("{}@{}", pkg.name, pkg.version);
        // The header is not an integrity anchor by itself: bind the actual
        // [[file]] records to the digest stored in own.lock before trusting them.
        let manifest_files: Vec<_> = manifest
            .files
            .iter()
            .map(|f| {
                (
                    f.path.clone(),
                    f.sha256
                        .strip_prefix("sha256:")
                        .unwrap_or(&f.sha256)
                        .to_string(),
                    f.size,
                    f.exec,
                )
            })
            .collect();
        let manifest_size = manifest
            .files
            .iter()
            .try_fold(0u64, |total, f| total.checked_add(f.size));
        if package_files_sha256(&manifest_files) != pkg.package_files_sha256
            || manifest.files.len() as u64 != pkg.file_count
            || manifest_size != Some(pkg.total_size)
        {
            findings.push(Finding::err(
                "DRIFT_MODIFIED",
                &pdir,
                &format!(
                    "vendor/own/.manifests/{}.toml",
                    crate::lock::dir_name(&pkg.name, &pkg.version)
                ),
                "manifest file digest/count/size differ from lock entry",
            ));
        }
        if manifest.manifest.package != pdir
            || manifest.manifest.package_files_sha256 != pkg.package_files_sha256
            || manifest.manifest.file_count != pkg.file_count
            || manifest.manifest.total_size != pkg.total_size
        {
            findings.push(Finding::err(
                "DRIFT_MODIFIED",
                &pdir,
                "vendor/own/.manifests",
                "manifest header != lock entry",
            ));
        }

        // per-file checks under vendor/own/<dir>
        let mut manifest_paths: BTreeSet<String> = BTreeSet::new();
        for f in &manifest.files {
            manifest_paths.insert(f.path.clone());
            let fp =
                match crate::path_safety::project_path(root, &format!("{}/{}", pkg.dir, f.path)) {
                    Ok(path) => path,
                    Err(e) => {
                        findings.push(Finding::err("DRIFT_EXTRA", &pdir, &f.path, &e.to_string()));
                        continue;
                    }
                };
            match fs::symlink_metadata(&fp) {
                Err(_) => findings.push(Finding::err(
                    "DRIFT_MISSING",
                    &pdir,
                    &f.path,
                    "file missing",
                )),
                Ok(md) => {
                    if md.file_type().is_symlink() || !md.is_file() {
                        findings.push(Finding::err(
                            "DRIFT_EXTRA",
                            &pdir,
                            &f.path,
                            "symlink or special file",
                        ));
                        continue;
                    }
                    let data = match fs::read(&fp) {
                        Ok(d) => d,
                        Err(e) => {
                            findings.push(Finding::err("IO_ERROR", &pdir, &f.path, &e.to_string()));
                            continue;
                        }
                    };
                    let h = sha256_hex(&data);
                    if h != f.sha256 || data.len() as u64 != f.size {
                        // CRLF->LF re-check for LINE_ENDINGS_REWRITTEN: convert
                        // each CRLF pair to a single LF (a lone CR is kept).
                        let crlf_fixed = data
                            .iter()
                            .enumerate()
                            .any(|(i, b)| *b == b'\r' && data.get(i + 1) == Some(&b'\n'));
                        if crlf_fixed {
                            let mut fixed: Vec<u8> = Vec::with_capacity(data.len());
                            let mut i = 0;
                            while i < data.len() {
                                if data[i] == b'\r' && data.get(i + 1) == Some(&b'\n') {
                                    fixed.push(b'\n');
                                    i += 2;
                                } else {
                                    fixed.push(data[i]);
                                    i += 1;
                                }
                            }
                            if sha256_hex(&fixed) == f.sha256 {
                                findings.push(Finding::err(
                                    "LINE_ENDINGS_REWRITTEN",
                                    &pdir,
                                    &f.path,
                                    "hash matches after CRLF->LF conversion",
                                ));
                                continue;
                            }
                        }
                        findings.push(Finding::err(
                            "DRIFT_MODIFIED",
                            &pdir,
                            &f.path,
                            "sha256/size differ from manifest",
                        ));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let exec = md.permissions().mode() & 0o100 != 0;
                        if exec != f.exec {
                            findings.push(Finding::err(
                                "DRIFT_MODIFIED",
                                &pdir,
                                &f.path,
                                "exec bit differs",
                            ));
                        }
                    }
                }
            }
        }

        // extra files in pkg dir
        if pkg_root.is_dir() {
            for entry in WalkDir::new(&pkg_root).follow_links(false) {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        findings.push(Finding::err("IO_ERROR", &pdir, &pkg.dir, &e.to_string()));
                        continue;
                    }
                };
                let rel = pathdiff(&pkg_root, entry.path());
                if rel.is_empty() {
                    continue;
                }
                if entry.file_type().is_symlink() {
                    findings.push(Finding::err("DRIFT_EXTRA", &pdir, &rel, "symlink present"));
                    continue;
                }
                if entry.file_type().is_dir() {
                    let prefix = format!("{rel}/");
                    if !manifest_paths.iter().any(|file| file.starts_with(&prefix)) {
                        findings.push(Finding::err(
                            "DRIFT_EXTRA",
                            &pdir,
                            &rel,
                            "directory not in manifest tree",
                        ));
                    }
                    continue;
                }
                if entry.file_type().is_file() {
                    if !manifest_paths.contains(&rel) {
                        findings.push(Finding::err(
                            "DRIFT_EXTRA",
                            &pdir,
                            &rel,
                            "file not in manifest",
                        ));
                    }
                } else {
                    findings.push(Finding::err(
                        "DRIFT_EXTRA",
                        &pdir,
                        &rel,
                        "special file present",
                    ));
                }
            }
        } else {
            findings.push(Finding::err(
                "DRIFT_MISSING",
                &pdir,
                &pkg.dir,
                "vendor dir missing",
            ));
        }

        // license files present and matching lock.license_files
        for lf in &pkg.license_files {
            let fp = crate::path_safety::project_path(root, &format!("{}/{}", pkg.dir, lf.path))
                .map_err(|e| format!("IO_ERROR: {e}"))?;
            match fs::read(&fp) {
                Ok(d) => {
                    if sha256_hex(&d) != lf.sha256 {
                        findings.push(Finding::err(
                            "DRIFT_MODIFIED",
                            &pdir,
                            &lf.path,
                            "license file hash differs",
                        ));
                    }
                }
                Err(_) => findings.push(Finding::err(
                    "DRIFT_MISSING",
                    &pdir,
                    &lf.path,
                    "license file missing",
                )),
            }
        }
    }

    // orphans: dirs in vendor/own not in lock; manifests without lock entry
    if vendor.is_dir() {
        for entry in fs::read_dir(&vendor).map_err(|e| format!("IO_ERROR: {e}"))? {
            let entry = entry.map_err(|e| format!("IO_ERROR: {e}"))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".manifests" || name == "LICENSES.md" {
                continue;
            }
            let dir_field = format!("vendor/own/{}", name);
            if !seen_dirs.contains(&dir_field) {
                findings.push(Finding::err(
                    "DRIFT_ORPHAN",
                    "",
                    &dir_field,
                    "vendor dir not in lock",
                ));
            }
        }
        if manifests.is_dir() {
            for entry in fs::read_dir(&manifests).map_err(|e| format!("IO_ERROR: {e}"))? {
                let entry = entry.map_err(|e| format!("IO_ERROR: {e}"))?;
                let name = entry.file_name().to_string_lossy().to_string();
                if !seen_manifests.contains(&name) {
                    findings.push(Finding::err(
                        "DRIFT_ORPHAN",
                        "",
                        &format!("vendor/own/.manifests/{}", name),
                        "manifest without lock entry",
                    ));
                }
            }
        }
    }

    // overrides == lock packages, one key per vendored package *version*.
    // vendor-all (Phase 2 §9.2): several versions of one name cannot be
    // expressed by a single bare `file:` override — that key would pin every
    // version to one directory — so each version carries the `name@version` key
    // pnpm applies per resolved version. A bare key for a multi-version name is
    // therefore a mismatch, not something to skip: skipping it is what left
    // vendor-all packages unverified.
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for p in &lock.packages {
        *counts.entry(p.name.as_str()).or_insert(0) += 1;
    }
    let mut lock_overrides: serde_json::Map<String, serde_json::Value> = lock
        .packages
        .iter()
        .map(|p| {
            // vendor-all also uses an exact version selector when only one
            // version is locked. Accept either single-version spelling, not
            // both; the complete map equality below still rejects extras.
            let key = if counts.get(p.name.as_str()) == Some(&1) && overrides.contains_key(&p.name)
            {
                p.name.clone()
            } else {
                crate::lock::versioned_override_key(&p.name, &p.version)
            };
            (key, serde_json::json!(format!("file:{}", p.dir)))
        })
        .collect();
    // Alias selectors supplement, never replace, the canonical real-name keys.
    // Every selector is bound to an existing locked package and its exact dir.
    for (selector, value) in overrides {
        if let Some(target) = npm_alias_target(selector) {
            if lock
                .packages
                .iter()
                .any(|p| p.name == target && *value == serde_json::json!(format!("file:{}", p.dir)))
            {
                lock_overrides.insert(selector.clone(), value.clone());
            }
        }
    }
    if lock_overrides != *overrides {
        findings.push(Finding::err(
            "OVERRIDE_MISMATCH",
            "",
            "package.json",
            "pnpm.overrides file:vendor/own/ != lock packages",
        ));
    }

    // LICENSES.md
    let lm_path = crate::path_safety::project_path(root, "vendor/own/LICENSES.md")
        .map_err(|e| format!("IO_ERROR: {e}"))?;
    match &lock.metadata.licenses_md_sha256 {
        Some(h) => {
            if !lm_path.exists() {
                findings.push(Finding::err(
                    "DRIFT_MISSING",
                    "",
                    "vendor/own/LICENSES.md",
                    "LICENSES.md missing but hash in lock",
                ));
            } else {
                let d = fs::read(&lm_path).map_err(|e| format!("IO_ERROR: {e}"))?;
                if sha256_hex(&d) != *h {
                    findings.push(Finding::err(
                        "DRIFT_MODIFIED",
                        "",
                        "vendor/own/LICENSES.md",
                        "LICENSES.md hash differs",
                    ));
                }
            }
        }
        None => {
            if lm_path.exists() {
                findings.push(Finding::err(
                    "DRIFT_EXTRA",
                    "",
                    "vendor/own/LICENSES.md",
                    "LICENSES.md present but not in lock",
                ));
            }
        }
    }

    // recomputed digests
    if compute_vendor_files_sha256(&lock.packages) != lock.metadata.vendor_files_sha256 {
        findings.push(Finding::err(
            "LOCK_DIGEST_MISMATCH",
            "",
            "own.lock",
            "vendor_files_sha256 recomputed differs",
        ));
    }
    if license_policy_sha256(policy_json) != lock.metadata.license_policy_sha256 {
        findings.push(Finding::err(
            "LOCK_DIGEST_MISMATCH",
            "",
            "own.lock",
            "license_policy_sha256 recomputed from own.toml differs",
        ));
    }
    if compute_lock_digest(&lock, overrides) != lock.metadata.lock_digest {
        findings.push(Finding::err(
            "LOCK_DIGEST_MISMATCH",
            "",
            "own.lock",
            "lock_digest recomputed differs",
        ));
    }

    // sort findings by (code, package, path) byte-wise (§8.0)
    findings.sort_by(|a, b| (&a.code, &a.package, &a.path).cmp(&(&b.code, &b.package, &b.path)));

    Ok(VerifyOutcome {
        findings,
        lock_canonical: canonical,
    })
}

fn pathdiff(base: &Path, p: &Path) -> String {
    p.strip_prefix(base)
        .map(|r| r.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default()
}

/// Target name of pnpm's exact npm-alias selector. Parent selectors and empty
/// identities are not generated by own and must not become ignored overrides.
pub fn npm_alias_target(selector: &str) -> Option<&str> {
    let (alias, spec) = selector.split_once("@npm:")?;
    let (name, range) = spec.rsplit_once('@')?;
    if alias.is_empty()
        || name.is_empty()
        || range.is_empty()
        || selector.contains('>')
        || range.contains(':')
    {
        return None;
    }
    Some(name)
}

/// SPEC §8.1 `verify --installed`: compare the copies pnpm materialised in
/// `node_modules/.pnpm` against the manifests. Every **installed** file must
/// exist in the manifest with the same bytes and size (`DRIFT_INSTALLED`);
/// files absent from the installed copy are not reported — §5 says pnpm may
/// install only the publication subset of the directory, and the source of
/// truth stays `vendor/own/`. Packages that were never installed are skipped
/// entirely, so the command is meaningful on a repo without `node_modules/`.
///
/// `verify()` has already reported a missing or inconsistent manifest; this
/// function skips those packages rather than reporting twice.
pub fn verify_installed(root: &Path) -> Result<Vec<Finding>, String> {
    let lock_text =
        fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock: Lock =
        crate::lock::parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let mut findings: Vec<Finding> = Vec::new();
    for pkg in &lock.packages {
        let label = format!("{}@{}", pkg.name, pkg.version);
        let copies = installed_copies(root, pkg)?;
        if copies.is_empty() {
            continue;
        }
        let mpath = root.join("vendor/own/.manifests").join(format!(
            "{}.toml",
            crate::lock::dir_name(&pkg.name, &pkg.version)
        ));
        let mtext = match fs::read_to_string(&mpath) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let manifest: Manifest = match parse_manifest(&mtext) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let known: std::collections::BTreeMap<&str, (&str, u64)> = manifest
            .files
            .iter()
            .map(|f| (f.path.as_str(), (f.sha256.as_str(), f.size)))
            .collect();
        for installed in copies {
            for entry in WalkDir::new(&installed).follow_links(false) {
                let entry = entry.map_err(|e| format!("IO_ERROR: {e}"))?;
                let rel = match entry.path().strip_prefix(&installed) {
                    Ok(r) => r.to_string_lossy().replace('\\', "/"),
                    Err(_) => continue,
                };
                if rel.is_empty() {
                    continue;
                }
                let md = entry.metadata().map_err(|e| format!("IO_ERROR: {e}"))?;
                if md.is_dir() {
                    continue;
                }
                if !md.is_file() {
                    findings.push(Finding::err(
                        "DRIFT_INSTALLED",
                        &label,
                        &rel,
                        "installed entry is not a regular file",
                    ));
                    continue;
                }
                let data = fs::read(entry.path()).map_err(|e| format!("IO_ERROR: {e}"))?;
                let h = sha256_hex(&data);
                match known.get(rel.as_str()) {
                    Some((expected, size)) if *expected == h && *size == data.len() as u64 => {}
                    Some(_) => findings.push(Finding::err(
                        "DRIFT_INSTALLED",
                        &label,
                        &rel,
                        "installed bytes differ from manifest",
                    )),
                    None => findings.push(Finding::err(
                        "DRIFT_INSTALLED",
                        &label,
                        &rel,
                        "installed file is not in the manifest",
                    )),
                }
            }
        }
    }
    findings.sort_by(|a, b| {
        (a.code.as_str(), a.package.as_str(), a.path.as_str()).cmp(&(
            b.code.as_str(),
            b.package.as_str(),
            b.path.as_str(),
        ))
    });
    Ok(findings)
}

/// Discover physical copies instead of guessing one virtual-store key. File
/// dependencies, aliases and peer contexts all use different pnpm keys.
/// The store key remains an identity anchor if package.json itself is tampered.
fn installed_copies(
    root: &Path,
    pkg: &crate::lock::Package,
) -> Result<BTreeSet<std::path::PathBuf>, String> {
    fn entries(dir: &Path) -> Result<Vec<std::fs::DirEntry>, String> {
        match fs::read_dir(dir) {
            Ok(rd) => rd
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("IO_ERROR: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(format!("IO_ERROR: {}: {e}", dir.display())),
        }
    }
    fn key_matches(key: &str, prefix: &str) -> bool {
        key.strip_prefix(prefix)
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(['_', '(']))
    }
    let modules = root.join("node_modules");
    let store = modules.join(".pnpm");
    let registry_key = crate::lock::dir_name(&pkg.name, &pkg.version);
    let file_key = format!(
        "{}@file+{}",
        pkg.name.replace('/', "+"),
        pkg.dir.replace('/', "+")
    );
    let mut locations = vec![(modules, false)];
    for entry in entries(&store)? {
        if entry
            .file_type()
            .map_err(|e| format!("IO_ERROR: {e}"))?
            .is_dir()
        {
            let key = entry.file_name().to_string_lossy().into_owned();
            locations.push((
                entry.path().join("node_modules"),
                key_matches(&key, &registry_key) || key_matches(&key, &file_key),
            ));
        }
    }
    let mut copies = BTreeSet::new();
    for (location, anchored) in locations {
        let mut candidates = Vec::new();
        for entry in entries(&location)? {
            if entry.file_name().to_string_lossy().starts_with('@') {
                candidates.extend(entries(&entry.path())?.into_iter().map(|e| e.path()));
            } else if !entry.file_name().to_string_lossy().starts_with('.') {
                candidates.push(entry.path());
            }
        }
        for path in candidates {
            let metadata_matches = fs::read(path.join("package.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .is_some_and(|value| value["name"] == pkg.name && value["version"] == pkg.version);
            if path.is_dir() && (metadata_matches || anchored && path == location.join(&pkg.name)) {
                copies.insert(fs::canonicalize(&path).map_err(|e| format!("IO_ERROR: {e}"))?);
            }
        }
    }
    Ok(copies)
}

/// Recompute `package_files_sha256` for a directory tree (used by add/update and tests).
pub fn hash_dir(root: &Path) -> Result<(String, u64, u64), String> {
    let mut files: Vec<(String, String, u64, bool)> = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|e| format!("IO_ERROR: {e}"))?;
        if entry.file_type().is_file() {
            let rel = pathdiff(root, entry.path());
            let data = fs::read(entry.path()).map_err(|e| format!("IO_ERROR: {e}"))?;
            let h = sha256_hex(&data);
            let exec = is_exec(entry.path());
            files.push((
                rel,
                h.trim_start_matches("sha256:").to_string(),
                data.len() as u64,
                exec,
            ));
        } else if entry.file_type().is_symlink() {
            return Err("EXTRACT_REFUSED:symlink".to_string());
        }
    }
    let total: u64 = files.iter().map(|f| f.2).sum();
    Ok((package_files_sha256(&files), files.len() as u64, total))
}

#[cfg(unix)]
fn is_exec(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o100 != 0)
        .unwrap_or(false)
}
#[cfg(not(unix))]
fn is_exec(_p: &Path) -> bool {
    false
}

// silence unused import warning for toml_write when only some fns used
#[allow(unused)]
fn _t(_: &toml_write::TomlWriter) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::empty_lock;
    use std::fs;

    fn make_pkg_dir(root: &Path, dir: &str) -> std::path::PathBuf {
        let d = root.join(dir);
        fs::create_dir_all(d.join("dist")).unwrap();
        fs::write(d.join("LICENSE"), b"MIT License\n").unwrap();
        fs::write(d.join("dist/index.js"), b"module.exports=1\n").unwrap();
        fs::write(
            d.join("package.json"),
            br#"{"name":"a","version":"1.0.0"}
"#,
        )
        .unwrap();
        d
    }

    #[test]
    fn verify_clean_tree_inv8_inv9() {
        let tmp = std::env::temp_dir().join(format!("own-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("vendor/own/.manifests")).unwrap();
        let pdir = make_pkg_dir(&tmp, "vendor/own/a@1.0.0");
        let (pfs, count, size) = hash_dir(&pdir).unwrap();
        // build manifest
        let mut w = crate::toml_write::TomlWriter::new();
        w.section("[manifest]")
            .key_int("schema_version", 1)
            .key_string("package", "a@1.0.0")
            .key_string("package_files_sha256", &pfs)
            .key_int("file_count", count)
            .key_int("total_size", size);
        let files = walkdir::WalkDir::new(&pdir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file());
        for f in files {
            let rel = f
                .path()
                .strip_prefix(&pdir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let data = fs::read(f.path()).unwrap();
            w.section("[[file]]")
                .key_string("path", &rel)
                .key_string("sha256", &sha256_hex(&data))
                .key_int("size", data.len() as u64)
                .key_value("exec", if is_exec(f.path()) { "true" } else { "false" });
        }
        fs::write(tmp.join("vendor/own/.manifests/a@1.0.0.toml"), w.finish()).unwrap();

        // lock with the package
        let mut lock = empty_lock("0.1.0", "1", &serde_json::Map::new());
        let license_hash = sha256_hex(b"MIT License\n");
        lock.packages.push(crate::lock::Package {
            name: "a".into(),
            ecosystem: "npm".into(),
            version: "1.0.0".into(),
            dir: "vendor/own/a@1.0.0".into(),
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
            license_files: vec![crate::lock::LicenseFile {
                path: "LICENSE".into(),
                sha256: license_hash,
            }],
            package_files_sha256: pfs.clone(),
            file_count: count,
            total_size: size,
            diamond_resolution: None,
            unified_ranges: None,
        });
        lock.metadata.vendor_files_sha256 =
            crate::canonical::compute_vendor_files_sha256(&lock.packages);
        let mut ov = serde_json::Map::new();
        ov.insert(
            "a".to_string(),
            serde_json::json!("file:vendor/own/a@1.0.0"),
        );
        lock.metadata.lock_digest = crate::canonical::compute_lock_digest(&lock, &ov);
        fs::write(
            tmp.join("own.lock"),
            crate::canonical::write_lock_canonical(&lock),
        )
        .unwrap();

        let out = verify(&tmp, &crate::canonical::default_license_policy(), &ov).unwrap();
        assert!(out.findings.is_empty(), "findings: {:?}", out.findings);

        // now tamper one file
        fs::write(pdir.join("dist/index.js"), b"module.exports=2\n").unwrap();
        let out = verify(&tmp, &crate::canonical::default_license_policy(), &ov).unwrap();
        assert!(
            out.findings
                .iter()
                .any(|f| f.code == "DRIFT_MODIFIED" && f.path == "dist/index.js"),
            "{:?}",
            out.findings
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    /// Two versions of one name in the lock, each with its own dir and manifest,
    /// plus the override map the lock digest is computed over.
    fn two_version_tree(
        tmp: &Path,
        overrides: &serde_json::Map<String, serde_json::Value>,
    ) -> crate::lock::Lock {
        fs::create_dir_all(tmp.join("vendor/own/.manifests")).unwrap();
        let mut lock = empty_lock("0.1.0", "1", &serde_json::Map::new());
        for version in ["1.0.0", "2.0.0"] {
            let dir = format!("vendor/own/a@{version}");
            let pdir = make_pkg_dir(tmp, &dir);
            let (pfs, count, size) = hash_dir(&pdir).unwrap();
            let mut w = crate::toml_write::TomlWriter::new();
            w.section("[manifest]")
                .key_int("schema_version", 1)
                .key_string("package", &format!("a@{version}"))
                .key_string("package_files_sha256", &pfs)
                .key_int("file_count", count)
                .key_int("total_size", size);
            for f in walkdir::WalkDir::new(&pdir)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                let rel = f
                    .path()
                    .strip_prefix(&pdir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let data = fs::read(f.path()).unwrap();
                w.section("[[file]]")
                    .key_string("path", &rel)
                    .key_string("sha256", &sha256_hex(&data))
                    .key_int("size", data.len() as u64)
                    .key_value("exec", "false");
            }
            fs::write(
                tmp.join(format!("vendor/own/.manifests/a@{version}.toml")),
                w.finish(),
            )
            .unwrap();
            let license_hash = sha256_hex(b"MIT License\n");
            lock.packages.push(crate::lock::Package {
                name: "a".into(),
                ecosystem: "npm".into(),
                version: version.into(),
                dir,
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
                license_files: vec![crate::lock::LicenseFile {
                    path: "LICENSE".into(),
                    sha256: license_hash,
                }],
                package_files_sha256: pfs,
                file_count: count,
                total_size: size,
                diamond_resolution: None,
                unified_ranges: None,
            });
        }
        lock.metadata.vendor_files_sha256 =
            crate::canonical::compute_vendor_files_sha256(&lock.packages);
        lock.metadata.lock_digest = crate::canonical::compute_lock_digest(&lock, overrides);
        fs::write(
            tmp.join("own.lock"),
            crate::canonical::write_lock_canonical(&lock),
        )
        .unwrap();
        lock
    }

    fn versioned_overrides() -> serde_json::Map<String, serde_json::Value> {
        let mut ov = serde_json::Map::new();
        ov.insert(
            "a@1.0.0".to_string(),
            serde_json::json!("file:vendor/own/a@1.0.0"),
        );
        ov.insert(
            "a@2.0.0".to_string(),
            serde_json::json!("file:vendor/own/a@2.0.0"),
        );
        ov
    }

    #[test]
    fn installed_verifier_checks_file_alias_and_every_peer_copy() {
        let tmp = tempfile::tempdir().unwrap();
        two_version_tree(tmp.path(), &versioned_overrides());
        for store in [
            "a@file+vendor+own+a@1.0.0",
            "a@file+vendor+own+a@1.0.0_peer@2.0.0",
            "a@1.0.0_peer@3.0.0",
        ] {
            let installed = tmp
                .path()
                .join("node_modules/.pnpm")
                .join(store)
                .join("node_modules/a");
            fs::create_dir_all(installed.join("dist")).unwrap();
            fs::write(installed.join("dist/index.js"), b"tampered\n").unwrap();
            let findings = verify_installed(tmp.path()).unwrap();
            assert!(
                findings.iter().any(|f| f.code == "DRIFT_INSTALLED"
                    && f.package == "a@1.0.0"
                    && f.path == "dist/index.js"),
                "unobserved pnpm copy {store}: {findings:?}"
            );
            fs::write(installed.join("dist/index.js"), b"module.exports=1\n").unwrap();
            assert!(verify_installed(tmp.path()).unwrap().is_empty());
        }
    }

    #[test]
    fn alias_overrides_are_bound_to_the_real_locked_target() {
        let tmp = tempfile::tempdir().unwrap();
        let mut overrides = versioned_overrides();
        overrides.insert(
            "old@npm:a@^1.0.0".into(),
            serde_json::json!("file:vendor/own/a@1.0.0"),
        );
        two_version_tree(tmp.path(), &overrides);
        assert!(verify(
            tmp.path(),
            &crate::canonical::default_license_policy(),
            &overrides
        )
        .unwrap()
        .findings
        .is_empty());
        for bad in [
            "old",
            "old@npm:b@1.0.0",
            "old@npm:a@",
            "old@npm:a@1.0.0>other",
        ] {
            let mut invalid = versioned_overrides();
            invalid.insert(bad.into(), serde_json::json!("file:vendor/own/a@1.0.0"));
            let findings = verify(
                tmp.path(),
                &crate::canonical::default_license_policy(),
                &invalid,
            )
            .unwrap()
            .findings;
            assert!(
                findings.iter().any(|f| f.code == "OVERRIDE_MISMATCH"),
                "accepted {bad}: {findings:?}"
            );
        }
    }

    #[test]
    fn override_check_covers_every_vendored_version_inv5() {
        let tmp = std::env::temp_dir().join(format!("own-test-multi-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let ov = versioned_overrides();
        let mut lock = two_version_tree(&tmp, &ov);
        let out = verify(&tmp, &crate::canonical::default_license_policy(), &ov).unwrap();
        assert!(out.findings.is_empty(), "findings: {:?}", out.findings);

        // A single bare override cannot express two versions: it pins both to one
        // directory, so it must be reported instead of skipped.
        let mut bare = serde_json::Map::new();
        bare.insert(
            "a".to_string(),
            serde_json::json!("file:vendor/own/a@1.0.0"),
        );
        lock.metadata.lock_digest = crate::canonical::compute_lock_digest(&lock, &bare);
        fs::write(
            tmp.join("own.lock"),
            crate::canonical::write_lock_canonical(&lock),
        )
        .unwrap();
        let out = verify(&tmp, &crate::canonical::default_license_policy(), &bare).unwrap();
        assert!(
            out.findings.iter().any(|f| f.code == "OVERRIDE_MISMATCH"),
            "{:?}",
            out.findings
        );

        // Dropping one version's key must be caught as well.
        let mut partial = versioned_overrides();
        partial.remove("a@2.0.0");
        lock.metadata.lock_digest = crate::canonical::compute_lock_digest(&lock, &partial);
        fs::write(
            tmp.join("own.lock"),
            crate::canonical::write_lock_canonical(&lock),
        )
        .unwrap();
        let out = verify(&tmp, &crate::canonical::default_license_policy(), &partial).unwrap();
        assert!(
            out.findings.iter().any(|f| f.code == "OVERRIDE_MISMATCH"),
            "{:?}",
            out.findings
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
