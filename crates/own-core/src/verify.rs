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
    let mut findings: Vec<Finding> = Vec::new();

    let lock_path = root.join("own.lock");
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

    let vendor = root.join("vendor/own");
    let manifests = vendor.join(".manifests");

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
        }
        // manifest
        let mpath = manifests.join(format!(
            "{}.toml",
            crate::lock::dir_name(&pkg.name, &pkg.version)
        ));
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
        let pkg_root = root.join(&pkg.dir);
        let mut manifest_paths: BTreeSet<String> = BTreeSet::new();
        for f in &manifest.files {
            manifest_paths.insert(f.path.clone());
            let fp = pkg_root.join(&f.path);
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
                    Err(_) => continue,
                };
                if entry.file_type().is_symlink() {
                    let rel = pathdiff(&pkg_root, entry.path());
                    findings.push(Finding::err("DRIFT_EXTRA", &pdir, &rel, "symlink present"));
                    continue;
                }
                if entry.file_type().is_file() {
                    let rel = pathdiff(&pkg_root, entry.path());
                    if !manifest_paths.contains(&rel) {
                        findings.push(Finding::err(
                            "DRIFT_EXTRA",
                            &pdir,
                            &rel,
                            "file not in manifest",
                        ));
                    }
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
            let fp = pkg_root.join(&lf.path);
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

    // overrides == lock packages.
    // vendor-all (Phase 2 §9.2): several versions of one package cannot be
    // expressed as a single file: override in pnpm.overrides — the package is
    // then expected to be ABSENT from overrides, so compare only packages that
    // appear exactly once in the lock.
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for p in &lock.packages {
        *counts.entry(p.name.as_str()).or_insert(0) += 1;
    }
    let lock_overrides: serde_json::Map<String, serde_json::Value> = lock
        .packages
        .iter()
        .filter(|p| counts.get(p.name.as_str()) == Some(&1))
        .map(|p| (p.name.clone(), serde_json::json!(format!("file:{}", p.dir))))
        .collect();
    // vendor-all packages (several lock entries, one name) may still carry a
    // legacy single override — ignore those keys on both sides.
    let multi: std::collections::HashSet<&str> = counts
        .iter()
        .filter(|(_, c)| **c > 1)
        .map(|(n, _)| *n)
        .collect();
    let ov_filtered: serde_json::Map<String, serde_json::Value> = overrides
        .iter()
        .filter(|(k, _)| !multi.contains(k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let lock_filtered: serde_json::Map<String, serde_json::Value> = lock_overrides
        .into_iter()
        .filter(|(k, _)| !multi.contains(k.as_str()))
        .collect();
    if lock_filtered != ov_filtered {
        findings.push(Finding::err(
            "OVERRIDE_MISMATCH",
            "",
            "package.json",
            "pnpm.overrides file:vendor/own/ != lock packages",
        ));
    }

    // LICENSES.md
    let lm_path = vendor.join("LICENSES.md");
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
}
