//! `own sbom` (SPEC §8.3): CycloneDX 1.5 JSON + OpenVEX statements from the
//! lock. purls preserved (`pkg:npm/<name>@<ver>`, scope `@` -> `%40`),
//! serialNumber = UUIDv5(DNS ns, lock_digest), timestamp per INV-10
//! (OWN_NOW > SOURCE_DATE_EPOCH > clock).

use own_core::lock::parse_lock;
use serde_json::{json, Value};
use std::path::Path;

pub struct SbomArgs {
    pub format: String, // cyclonedx | vex | both
    /// Compute E1 reachability evidence for VEX statements (Phase 2, Annexe G)
    pub e1: bool,
    pub output: Option<String>,
    pub vex_output: Option<String>,
    pub author: String,
    pub now: Option<String>, // OWN_NOW
}

fn now_rfc3339(now: &Option<String>) -> String {
    if let Some(n) = now {
        return n.clone();
    }
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        if let Ok(e) = epoch.parse::<i64>() {
            return epoch_to_rfc3339(e);
        }
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    epoch_to_rfc3339(secs)
}

fn epoch_to_rfc3339(secs: i64) -> String {
    // civil-from-days algorithm (Howard Hinnant), no chrono dependency
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

pub fn purl(name: &str, version: &str) -> String {
    if let Some(scope_rest) = name.strip_prefix('@') {
        // @scope/name -> %40scope/name
        let enc = format!("%40{scope_rest}");
        format!("pkg:npm/{enc}@{version}")
    } else {
        format!("pkg:npm/{name}@{version}")
    }
}

pub fn cyclonedx(root: &Path, args: &SbomArgs) -> Result<Value, String> {
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let ts = now_rfc3339(&args.now);
    let serial = format!(
        "urn:uuid:{}",
        uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_DNS,
            lock.metadata.lock_digest.as_bytes()
        )
    );
    let mut components = Vec::new();
    let mut pkgs = lock.packages.clone();
    pkgs.sort_by(|a, b| {
        (a.name.as_str(), a.version.as_str()).cmp(&(b.name.as_str(), b.version.as_str()))
    });
    for p in &pkgs {
        components.push(json!({
            "type": "library",
            "bom-ref": purl(&p.name, &p.version),
            "purl": purl(&p.name, &p.version),
            "name": p.name,
            "version": p.version,
            "hashes": [{ "alg": "SHA-256", "content": p.tarball_sha256.trim_start_matches("sha256:") }],
            "licenses": [{ "expression": p.license_expression }],
            "properties": [
                { "name": "own:vendored", "value": "true" },
                { "name": "own:provenance_level", "value": p.provenance_level },
                { "name": "own:package_files_sha256", "value": p.package_files_sha256 },
            ],
        }));
    }
    Ok(json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [{ "vendor": "own", "name": "own", "version": env!("CARGO_PKG_VERSION") }],
            "component": { "type": "application", "name": "project" },
        },
        "components": components,
    }))
}

/// OpenVEX: one statement per E0 alert, status under_investigation, no
/// justification, status_notes mention evidence_level=E0 (SPEC §8.3).
pub fn openvex(
    root: &Path,
    args: &SbomArgs,
    alerts: &[crate::osv::Alert],
) -> Result<Value, String> {
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let ts = now_rfc3339(&args.now);
    let mut statements = Vec::new();
    for a in alerts {
        let p = lock
            .packages
            .iter()
            .find(|p| p.name == a.package)
            .ok_or("PACKAGE_NOT_VENDORED")?;
        // Phase 2 (Annexe G): E1 evidence is auditable — status_notes carry the
        // evidence level AND the sha256 of the reachable file set, so the proof
        // can be re-verified offline. Status stays under_investigation, never
        // not_affected (INV-7).
        let mut notes = format!(
            "evidence_level={}: {}@{} in affected range; aliases: {}",
            a.evidence_level,
            a.package,
            a.current_version,
            a.aliases.join(", ")
        );
        if let Some(ref rh) = a.reachable_sha256 {
            notes.push_str(&format!("; reachable_set_sha256={rh}"));
        }
        statements.push(json!({
            "vulnerability": { "name": a.advisory_id },
            "status": "under_investigation",
            "status_notes": notes,
            "products": [{ "@id": purl(&p.name, &p.version) }],
        }));
    }
    // @id = sha256 of content without @id
    let mut doc = json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "author": args.author,
        "timestamp": ts,
        "version": 1,
        "statements": statements,
    });
    let content = own_core::jcs::canonicalize(&doc).map_err(|e| format!("IO_ERROR: {e}"))?;
    let hash = own_core::sha256_hex(content.as_bytes());
    doc["@id"] = json!(format!(
        "https://openvex.dev/docs/own/{}",
        hash.trim_start_matches("sha256:")
    ));
    Ok(doc)
}

pub fn sbom(root: &Path, args: &SbomArgs) -> Result<u8, String> {
    match args.format.as_str() {
        "cyclonedx" => {
            let doc = cyclonedx(root, args)?;
            let s = serde_json::to_string_pretty(&doc).map_err(|e| format!("IO_ERROR: {e}"))?;
            match &args.output {
                Some(p) => {
                    std::fs::write(root.join(p), format!("{s}\n"))
                        .map_err(|e| format!("IO_ERROR: {e}"))?;
                    println!("wrote {p}");
                }
                None => println!("{s}"),
            }
            Ok(0)
        }
        "vex" | "both" => {
            // needs osv.json alerts
            let check_args = crate::osv::CheckArgs {
                e1: args.e1,
                e2: false,
                remote: false,
                allow_stale_osv: true,
                allow_missing_osv: true,
                now: args.now.clone(),
                max_age_days: 7,
            };
            let (alerts, _w) = crate::osv::check(root, &check_args, ".own/osv.json")?;
            let doc = openvex(root, args, &alerts)?;
            let s = serde_json::to_string_pretty(&doc).map_err(|e| format!("IO_ERROR: {e}"))?;
            let out_path = if args.format == "both" {
                Some(
                    args.vex_output
                        .clone()
                        .ok_or("USAGE_ERROR: --format both requires --vex-output")?,
                )
            } else {
                // §8.3: stdout when --output is absent (same rule as cyclonedx)
                args.output.clone()
            };
            match &out_path {
                Some(p) => {
                    std::fs::write(root.join(p), format!("{s}\n"))
                        .map_err(|e| format!("IO_ERROR: {e}"))?;
                    println!("wrote {p} ({} statements)", alerts.len());
                }
                None => println!("{s}"),
            }
            if args.format == "both" {
                let cdx = cyclonedx(root, args)?;
                let s2 =
                    serde_json::to_string_pretty(&cdx).map_err(|e| format!("IO_ERROR: {e}"))?;
                let out = args
                    .output
                    .clone()
                    .ok_or("USAGE_ERROR: --output required with both")?;
                std::fs::write(root.join(out), format!("{s2}\n"))
                    .map_err(|e| format!("IO_ERROR: {e}"))?;
            }
            Ok(0)
        }
        _ => Err("USAGE_ERROR: --format must be cyclonedx|vex|both".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_scoped_encodes_at() {
        assert_eq!(purl("@scope/name", "1.0.0"), "pkg:npm/%40scope/name@1.0.0");
        assert_eq!(purl("zod", "3.22.4"), "pkg:npm/zod@3.22.4");
    }

    #[test]
    fn epoch_conversion() {
        assert_eq!(epoch_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_rfc3339(1_762_819_200), "2025-11-11T00:00:00Z");
    }
}
