//! `own osv fetch` + `own check` (SPEC §8.2): download the OSV npm dump into
//! `.own/osv.json` (deterministic compact JSON), then evaluate E0 alerts
//! offline against the vendored packages.

use own_core::lock::parse_lock;
use own_net::{build_client, fetch_osv_dump, NetConfig};
use own_policy::semver;
use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;

pub const DEFAULT_OSV_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

/// Reduce one OSV advisory to the fields `check` needs (§8.2).
fn reduce_advisory(a: &Value) -> Option<Value> {
    let id = a.get("id")?.as_str()?.to_string();
    if a.get("withdrawn").and_then(|w| w.as_str()).is_some() {
        return None;
    }
    let aliases: Vec<String> = a
        .get("aliases")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let mut affected_out = Vec::new();
    if let Some(affected) = a.get("affected").and_then(|x| x.as_array()) {
        for aff in affected {
            let pkg = aff
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())?
                .to_string();
            let ecosystem = aff
                .get("package")
                .and_then(|p| p.get("ecosystem"))
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .to_string();
            if ecosystem != "npm" {
                continue;
            }
            let mut ranges_out = Vec::new();
            if let Some(ranges) = aff.get("ranges").and_then(|r| r.as_array()) {
                for r in ranges {
                    let ty = r
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string();
                    if ty == "GIT" {
                        continue; // ignored per §8.2
                    }
                    let events: Vec<Value> = r
                        .get("events")
                        .and_then(|e| e.as_array())
                        .cloned()
                        .unwrap_or_default();
                    ranges_out.push(json!({ "type": ty, "events": events }));
                }
            }
            let versions: Vec<String> = aff
                .get("versions")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            affected_out
                .push(json!({ "package": pkg, "ranges": ranges_out, "versions": versions }));
        }
    }
    let severity = a.get("severity").cloned();
    // Phase 2 (Annexe G): keep file-level hints for E1 evidence evaluation
    let mut obj = json!({
        "id": id,
        "aliases": aliases,
        "affected": affected_out,
        "severity": severity,
    });
    // F-01 (deepseek review): match by INDEX — source package is an object,
    // reduced package is a string, so value comparison never matched.
    if let (Some(src_aff), Some(out_aff)) = (
        a.get("affected").and_then(|x| x.as_array()),
        obj["affected"].as_array_mut(),
    ) {
        for (i, aff_in) in src_aff.iter().enumerate() {
            if let Some(aout) = out_aff.get_mut(i) {
                for key in ["database_specific", "ecosystem_specific"] {
                    if let Some(v) = aff_in.get(key) {
                        aout[key] = v.clone();
                    }
                }
            }
        }
    }
    Some(obj)
}

/// `own osv fetch`: download dump, filter to lock packages, write .own/osv.json.
pub fn osv_fetch(
    root: &Path,
    osv_url: &str,
    max_download_mb: u64,
    now: Option<&str>,
) -> Result<u8, String> {
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let covered: Vec<String> = lock.packages.iter().map(|p| p.name.clone()).collect();
    let client = build_client(&NetConfig::default())?;
    let zip_bytes = fetch_osv_dump(&client, osv_url, max_download_mb)?;
    let cursor = std::io::Cursor::new(&zip_bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| format!("PARSE_ERROR: osv zip: {e}"))?;
    let mut advisories: Vec<Value> = Vec::new();
    let covered_set: std::collections::HashSet<&String> = covered.iter().collect();
    let max_entries = 2_000_000usize; // OSV npm dump has ~100k+ entries
    for (entries, i) in (0..archive.len()).enumerate() {
        if entries > max_entries {
            return Err("NETWORK_ERROR: osv dump exceeds entry cap".to_string());
        }
        let mut f = archive
            .by_index(i)
            .map_err(|e| format!("IO_ERROR: osv zip entry: {e}"))?;
        if f.size() > 5 * 1_048_576 {
            // individual advisory files are small
            continue;
        }
        let mut s = String::new();
        f.read_to_string(&mut s)
            .map_err(|e| format!("IO_ERROR: osv entry: {e}"))?;
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            // OSV dump zip: one advisory per file; filter by affected package name
            let touches = v
                .get("affected")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter().any(|aff| {
                        aff.get("package")
                            .and_then(|p| p.get("name"))
                            .and_then(|n| n.as_str())
                            .map(|n| covered_set.contains(&n.to_string()))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            if touches {
                if let Some(red) = reduce_advisory(&v) {
                    advisories.push(red);
                }
            }
        }
    }
    advisories.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let generated_at = now.unwrap_or("").to_string();
    let doc = json!({
        "schema_version": 1,
        "generated_at": generated_at,
        "source": osv_url,
        "source_last_modified": Value::Null,
        "covered_packages": covered,
        "advisories": advisories,
    });
    // compact deterministic JSON (keys sorted via JCS)
    let canon = own_core::jcs::canonicalize(&doc).map_err(|e| format!("IO_ERROR: jcs: {e}"))?;
    let own_dir = root.join(".own");
    std::fs::create_dir_all(&own_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
    // atomic write
    let tmp = own_dir.join("osv.json.tmp");
    std::fs::write(&tmp, canon.as_bytes()).map_err(|e| format!("IO_ERROR: {e}"))?;
    std::fs::rename(&tmp, own_dir.join("osv.json")).map_err(|e| format!("IO_ERROR: {e}"))?;
    println!(
        "wrote .own/osv.json ({} advisories for {} packages)",
        advisories.len(),
        covered.len()
    );
    Ok(0)
}

pub struct CheckArgs {
    #[allow(dead_code)] // --remote handled in CLI before calling check()
    pub remote: bool,
    pub allow_stale_osv: bool,
    pub allow_missing_osv: bool,
    pub now: Option<String>,
    pub max_age_days: u32,
    /// Phase 2: compute E1 reachability evidence per alert (SPEC §9.4)
    pub e1: bool,
    /// Phase 2: compute E2 executed-reachability evidence (requires node)
    pub e2: bool,
}

pub struct Alert {
    pub advisory_id: String,
    pub aliases: Vec<String>,
    pub package: String,
    pub current_version: String,
    pub affected_ranges: Vec<String>,
    pub fixed_versions: Vec<String>,
    pub evidence_level: String,
    /// Phase 2: sha256 (JCS) of the sorted reachable file set when E1 was computed
    pub reachable_sha256: Option<String>,
}

/// `own check` (offline, E0): evaluate .own/osv.json against the lock (§8.2).
pub fn check(
    root: &Path,
    args: &CheckArgs,
    osv_local_path: &str,
) -> Result<(Vec<Alert>, Vec<String>), String> {
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let path = root.join(osv_local_path);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => {
            if args.allow_missing_osv {
                return Ok((vec![], vec!["W_OSV_MISSING".to_string()]));
            }
            return Err("OSV_MISSING".to_string());
        }
    };
    let doc: Value =
        serde_json::from_str(&text).map_err(|e| format!("PARSE_ERROR: osv.json: {e}"))?;
    // freshness
    let generated_at = doc
        .get("generated_at")
        .and_then(|g| g.as_str())
        .unwrap_or("");
    if !generated_at.is_empty() {
        if let Some(now) = &args.now {
            let age_days = days_between(generated_at, now);
            if age_days > args.max_age_days as i64 {
                if args.allow_stale_osv {
                    // warning only
                } else {
                    return Err("OSV_STALE".to_string());
                }
            }
        }
    }
    // completeness: every lock package must be covered
    let covered: Vec<String> = doc
        .get("covered_packages")
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    for p in &lock.packages {
        if !covered.contains(&p.name) {
            return Err("OSV_INCOMPLETE".to_string());
        }
    }
    let ignores: Vec<(String, String)> = vec![]; // [osv].ignore parsed from own.toml — wired in CLI
    let _ = ignores;
    let mut alerts = Vec::new();
    let warnings: Vec<String> = Vec::new();
    for p in &lock.packages {
        let advisories = doc
            .get("advisories")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
        for adv in &advisories {
            let id = adv
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let aliases: Vec<String> = adv
                .get("aliases")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            for aff in adv
                .get("affected")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let pkg = aff.get("package").and_then(|p| p.as_str()).unwrap_or("");
                if pkg != p.name {
                    continue;
                }
                let mut hit = false;
                let mut range_desc = Vec::new();
                let mut fixed = Vec::new();
                for r in aff
                    .get("ranges")
                    .and_then(|r| r.as_array())
                    .cloned()
                    .unwrap_or_default()
                {
                    let evs: Vec<(String, String)> = r
                        .get("events")
                        .and_then(|e| e.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|e| {
                                    let obj = e.as_object()?;
                                    let (k, val) = obj.iter().next()?;
                                    Some((k.clone(), val.as_str()?.to_string()))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    for (k, v) in &evs {
                        if k == "fixed" {
                            fixed.push(v.clone());
                        }
                    }
                    if semver::in_osv_range(&p.version, &evs) {
                        hit = true;
                        range_desc.push(format!("{:?}", evs));
                    }
                }
                let versions: Vec<String> = aff
                    .get("versions")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                if versions.iter().any(|v| v == &p.version) {
                    hit = true;
                }
                if hit {
                    let mut level = "E0".to_string();
                    let mut reach_hash: Option<String> = None;
                    if args.e2 {
                        // E2 needs an entry file: use main from package.json
                        let dir = root.join(&p.dir);
                        let entry = std::fs::read_to_string(dir.join("package.json"))
                            .ok()
                            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                            .and_then(|v| {
                                v.get("main")
                                    .and_then(|m| m.as_str())
                                    .map(|s| s.to_string())
                            })
                            .map(|m| dir.join(m))
                            .unwrap_or_else(|| dir.join("index.js"));
                        let (lvl, loaded) = own_slice::e2::evidence_level_e2(&dir, adv, &entry);
                        if lvl == "E2" {
                            level = "E2".to_string();
                        } else if args.e1 {
                            // fall back to E1
                        }
                        if let Some(r) = loaded {
                            let mut v: Vec<&String> = r.iter().collect();
                            v.sort();
                            let j = serde_json::to_string(&v).unwrap_or_default();
                            reach_hash = Some(own_core::sha256_hex(j.as_bytes()));
                        }
                    }
                    if args.e1 && level == "E0" {
                        let dir = root.join(&p.dir);
                        let (lvl, reach) =
                            own_slice::e1::evidence_level(&dir, adv, own_slice::ConsumerModel::Esm);
                        level = lvl.to_string();
                        if let Some(r) = reach {
                            let mut v: Vec<&String> = r.iter().collect();
                            v.sort();
                            let j = serde_json::to_string(&v).unwrap_or_default();
                            reach_hash = Some(own_core::sha256_hex(j.as_bytes()));
                        }
                    }
                    alerts.push(Alert {
                        advisory_id: id.clone(),
                        aliases: aliases.clone(),
                        package: p.name.clone(),
                        current_version: p.version.clone(),
                        affected_ranges: range_desc,
                        fixed_versions: fixed,
                        evidence_level: level,
                        reachable_sha256: reach_hash,
                    });
                }
            }
        }
    }
    let _ = warnings;
    Ok((alerts, warnings))
}

fn days_between(a: &str, b: &str) -> i64 {
    // RFC 3339 dates only; compare by parsing YYYY-MM-DD prefix
    let pa: Vec<i64> = a[..10].split('-').filter_map(|x| x.parse().ok()).collect();
    let pb: Vec<i64> = b[..10].split('-').filter_map(|x| x.parse().ok()).collect();
    if pa.len() != 3 || pb.len() != 3 {
        return 0;
    }
    let da = pa[0] * 365 + pa[1] * 30 + pa[2];
    let db = pb[0] * 365 + pb[1] * 30 + pb[2];
    db - da
}
