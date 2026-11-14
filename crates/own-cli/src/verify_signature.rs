//! `own verify-signature <file> --bundle <path> [--provenance <path>]
//! --identity <regex> --issuer <url>` (SPEC §8.3): offline verification of a
//! cosign keyless signature (+ optional SLSA provenance) of an `own` binary.
//! Delegates to the external `cosign` binary (SPEC §8.3: until 0.3 the install
//! script uses cosign; this command shells out and reports PROVENANCE_INVALID
//! on mismatch, exit 2 if unreadable).

use std::path::Path;
use std::process::Command;

pub struct VerifySignatureArgs {
    pub file: String,
    pub bundle: String,
    pub provenance: Option<String>,
    pub trusted_root: Option<String>,
    pub identity: String,
    pub issuer: String,
}

pub fn verify_signature(root: &Path, args: &VerifySignatureArgs) -> Result<u8, String> {
    let file = root.join(&args.file);
    let bundle = root.join(&args.bundle);
    // Name the missing path: "file not readable" alone does not say whether the
    // artifact or the bundle is the one that is absent.
    for (p, given) in [(&file, &args.file), (&bundle, &args.bundle)] {
        if !p.is_file() {
            return Err(format!("IO_ERROR: {given} not readable"));
        }
    }
    let cosign = Command::new("cosign")
        .arg("--version")
        .output()
        .map_err(|_| "IO_ERROR: cosign binary not found (install pinned cosign)".to_string())?;
    if !cosign.status.success() {
        return Err("IO_ERROR: cosign not executable".to_string());
    }
    // 1. signature bundle
    let mut cmd = Command::new("cosign");
    cmd.arg("verify-blob")
        .arg("--bundle")
        .arg(&bundle)
        .arg("--certificate-identity-regexp")
        .arg(&args.identity)
        .arg("--certificate-oidc-issuer")
        .arg(&args.issuer);
    if let Some(tr) = &args.trusted_root {
        cmd.arg("--trusted-root").arg(root.join(tr));
    }
    cmd.arg(&file);
    let out = cmd.output().map_err(|e| format!("IO_ERROR: {e}"))?;
    if !out.status.success() {
        return Err("PROVENANCE_INVALID: signature".to_string());
    }
    // 2. optional SLSA provenance
    if let Some(prov) = &args.provenance {
        let prov_path = root.join(prov);
        if !prov_path.is_file() {
            return Err("IO_ERROR: provenance file not readable".to_string());
        }
        let out = Command::new("cosign")
            .args([
                "verify-blob-attestation",
                "--bundle",
                prov_path.to_str().unwrap(),
                "--type",
                "https://slsa.dev/provenance/v1",
                "--certificate-identity-regexp",
                "^https://github.com/slsa-framework/slsa-github-generator/.*@refs/tags/v.*$",
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                file.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| format!("IO_ERROR: {e}"))?;
        if !out.status.success() {
            return Err("PROVENANCE_INVALID: SLSA provenance".to_string());
        }
    }
    println!(
        "ok: signature verified (identity {} @ {})",
        args.identity, args.issuer
    );
    Ok(0)
}
