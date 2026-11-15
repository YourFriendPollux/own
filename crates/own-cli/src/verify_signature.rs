//! Verify a release artifact's cosign keyless signature and optionally its
//! signed SLSA DSSE `.intoto.jsonl` using trusted, preinstalled verifiers.
//! Provenance requires explicit `--source-uri` and exact `--source-tag`; the
//! artifact must be a published subject (e.g. a tarball, not its extracted binary).
//! A local `--trusted-root` supplies cosign's trust material for the Sigstore
//! bundle. It does not apply to slsa-verifier, which may fetch Rekor/TUF data:
//! this command does not promise offline SLSA verification.
//! Verifier rejection is PROVENANCE_INVALID (exit 1); unreadable inputs or
//! unavailable tools are IO_ERROR (exit 2).

use std::path::{Path, PathBuf};
use std::process::Command;

pub struct VerifySignatureArgs {
    pub file: String,
    pub bundle: String,
    pub provenance: Option<String>,
    pub source_uri: Option<String>,
    pub source_tag: Option<String>,
    pub trusted_root: Option<String>,
    pub identity: String,
    pub issuer: String,
}

pub fn verify_signature(root: &Path, args: &VerifySignatureArgs) -> Result<u8, String> {
    if args.provenance.is_some() && (args.source_uri.is_none() || args.source_tag.is_none()) {
        return Err("USAGE_ERROR: --provenance requires --source-uri and --source-tag".to_string());
    }
    for (flag, value) in [
        ("--source-uri", &args.source_uri),
        ("--source-tag", &args.source_tag),
    ] {
        if value
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(format!("USAGE_ERROR: {flag} must not be empty"));
        }
    }
    // Validate every input before any verifier can run or report success.
    let file = readable_file(root, &args.file)?;
    let bundle = readable_file(root, &args.bundle)?;
    let provenance = args
        .provenance
        .as_deref()
        .map(|path| readable_file(root, path))
        .transpose()?;
    let trusted_root = args
        .trusted_root
        .as_deref()
        .map(|path| readable_file(root, path))
        .transpose()?;
    // Discover both trusted, preinstalled tools before the first subprocess.
    // Never download a verifier from the release it is meant to authenticate.
    let cosign = trusted_verifier("cosign")?;
    let slsa = if provenance.is_some() {
        Some(trusted_verifier("slsa-verifier")?)
    } else {
        None
    };
    // 1. signature bundle
    let mut cmd = Command::new(&cosign);
    cmd.arg("verify-blob")
        .arg("--new-bundle-format=true")
        .arg("--bundle")
        .arg(&bundle)
        .arg("--certificate-identity-regexp")
        .arg(&args.identity)
        .arg("--certificate-oidc-issuer")
        .arg(&args.issuer);
    if let Some(tr) = &trusted_root {
        cmd.arg("--trusted-root").arg(tr);
    }
    cmd.arg(&file);
    let out = cmd
        .output()
        .map_err(|e| format!("IO_ERROR: {}: {e}", cosign.display()))?;
    if !out.status.success() {
        return Err(format!(
            "PROVENANCE_INVALID: signature (cosign {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // 2. optional SLSA provenance
    if let (Some(prov_path), Some(slsa)) = (&provenance, &slsa) {
        let source_uri = args
            .source_uri
            .as_deref()
            .ok_or("USAGE_ERROR: --source-uri required")?;
        let source_tag = args
            .source_tag
            .as_deref()
            .ok_or("USAGE_ERROR: --source-tag required")?;
        // The generic generator publishes a signed DSSE .intoto.jsonl, not a
        // cosign bundle. verify-artifact checks the artifact digest (subject),
        // the expected repository, exact tag, and pinned builder identity.
        let out = Command::new(slsa)
            .arg("verify-artifact")
            .arg(&file)
            .arg("--provenance-path")
            .arg(prov_path)
            .arg("--source-uri")
            .arg(source_uri)
            .arg("--source-tag")
            .arg(source_tag)
            .arg("--builder-id")
            .arg("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0")
            .output()
            .map_err(|e| format!("IO_ERROR: {}: {e}", slsa.display()))?;
        if !out.status.success() {
            return Err(format!(
                "PROVENANCE_INVALID: SLSA provenance (slsa-verifier {}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        println!("ok: SLSA provenance verified (source {source_uri} @ {source_tag})");
    }
    println!(
        "ok: signature verified (identity {} @ {})",
        args.identity, args.issuer
    );
    Ok(0)
}

fn readable_file(root: &Path, given: &str) -> Result<PathBuf, String> {
    let path = root.join(given);
    let metadata = std::fs::metadata(&path)
        .map_err(|error| format!("IO_ERROR: {given} not readable: {error}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "IO_ERROR: {given} not readable: not a regular file"
        ));
    }
    std::fs::File::open(&path)
        .map_err(|error| format!("IO_ERROR: {given} not readable: {error}"))?;
    Ok(path)
}

fn trusted_verifier(name: &str) -> Result<PathBuf, String> {
    let missing = || {
        format!("IO_ERROR: {name} binary not found or not executable on PATH (install a trusted, preinstalled {name})")
    };
    let search_path = std::env::var_os("PATH").ok_or_else(missing)?;
    let cwd = std::env::current_dir().map_err(|error| format!("IO_ERROR: {name}: {error}"))?;
    for dir in std::env::split_paths(&search_path) {
        let path = cwd.join(dir).join(name);
        if !std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
                continue;
            };
            // SAFETY: c_path is NUL-terminated and lives throughout this call.
            if unsafe {
                libc::faccessat(
                    libc::AT_FDCWD,
                    c_path.as_ptr(),
                    libc::X_OK,
                    libc::AT_EACCESS,
                )
            } != 0
            {
                continue;
            }
        }
        return Ok(path);
    }
    Err(missing())
}
