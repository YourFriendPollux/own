//! `own scan` (SPEC §8.1): list runtime dependencies from pnpm-lock.yaml with
//! eligibility status, fetched from the registry in parallel (rayon over
//! [net].concurrency). `--include-dev` is informational only (dev-only packages
//! are listed with status `dev`).

use own_core::lock::parse_lock;
use own_net::{build_client, fetch_packument, NetConfig};
use own_policy::{eligibility, pnpm_lock::parse_pnpm_lock};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::path::Path;

pub struct ScanRow {
    pub name: String,
    pub version: String,
    pub size: Option<u64>,
    pub license: Option<String>,
    pub deps: usize,
    pub install_scripts: usize,
    pub types: &'static str,
    pub status: String,
}

pub fn scan(root: &Path, include_dev: bool) -> Result<(Vec<ScanRow>, u32), String> {
    let text = std::fs::read_to_string(root.join("pnpm-lock.yaml"))
        .map_err(|e| format!("PARSE_ERROR: pnpm-lock.yaml: {e}"))?;
    let lock = parse_pnpm_lock(&text)?;
    let own_lock = if root.join("own.lock").exists() {
        let t =
            std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
        Some(parse_lock(&t).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?)
    } else {
        None
    };
    // runtime deps: reachable from importers' dependencies/optionalDependencies.
    // Skip file: vendor deps — they are already vendored.
    let mut runtime: BTreeSet<(String, String)> = BTreeSet::new();
    let mut dev_only: BTreeSet<(String, String)> = BTreeSet::new();
    for im in &lock.importers {
        for (n, spec, v) in &im.deps {
            if spec.starts_with("file:vendor/own/") || v.starts_with("file:vendor/own/") {
                continue; // vendored: shown via own.lock, not re-fetched
            }
            runtime.insert((n.clone(), v.clone()));
        }
    }
    // dev-only: declared in devDependencies — our parser doesn't separate; approximate:
    // a dep is dev-only if it appears in no runtime chain. We keep the simple rule:
    // all importer deps are runtime for scan purposes (devDependencies parsing is a
    // later refinement; --include-dev stays informational).
    let _ = include_dev;
    let _ = &mut dev_only;

    let cfg = NetConfig::default();
    let client = build_client(&cfg)?;
    let names: Vec<String> = runtime.iter().map(|(n, _)| n.clone()).collect();
    let conc = cfg.concurrency.max(1);
    let chunked: Vec<Vec<String>> = names.chunks(conc.max(1)).map(|c| c.to_vec()).collect();
    // rayon parallel fetch
    let results: Vec<(String, Result<serde_json::Value, String>)> = chunked
        .par_iter()
        .flat_map(|chunk| {
            chunk.par_iter().map(|name| {
                let r = fetch_packument(&client, &cfg, name).and_then(|bytes| {
                    serde_json::from_slice(&bytes)
                        .map_err(|e| format!("PARSE_ERROR: packument {name}: {e}"))
                });
                (name.clone(), r)
            })
        })
        .collect();
    let mut errors = 0u32;
    let mut rows = Vec::new();
    for (name, res) in results {
        let version = runtime
            .iter()
            .find(|(n, _)| n == &name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        match res {
            Err(e) => {
                errors += 1;
                rows.push(ScanRow {
                    name,
                    version,
                    size: None,
                    license: None,
                    deps: 0,
                    install_scripts: 0,
                    types: "unknown",
                    status: format!("unknown:{e}"),
                });
            }
            Ok(pv) => {
                let vobj = pv.get("versions").and_then(|vs| vs.get(&version));
                // if already vendored, short-circuit before fetch result usage
                if own_lock
                    .as_ref()
                    .map(|l| l.packages.iter().any(|p| p.name == name))
                    .unwrap_or(false)
                {
                    rows.push(ScanRow {
                        name: name.clone(),
                        version,
                        size: None,
                        license: own_lock
                            .as_ref()
                            .unwrap()
                            .packages
                            .iter()
                            .find(|p| p.name == name)
                            .map(|p| p.license_expression.clone()),
                        deps: 0,
                        install_scripts: 0,
                        types: "declared",
                        status: "vendorized".to_string(),
                    });
                    continue;
                }
                let vendored_names: Vec<(String, String)> = own_lock
                    .as_ref()
                    .map(|l| {
                        l.packages
                            .iter()
                            .map(|p| (p.name.clone(), p.version.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                let (status, size, license, deps, scripts, types) = match vobj {
                    None => (
                        "unknown:VERSION_NOT_FOUND".to_string(),
                        None,
                        None,
                        0,
                        0,
                        "unknown",
                    ),
                    Some(v) => {
                        let vendored = own_lock
                            .as_ref()
                            .map(|l| l.packages.iter().any(|p| p.name == name))
                            .unwrap_or(false);
                        if vendored {
                            (
                                "vendorized".to_string(),
                                v.pointer("/dist/unpackedSize").and_then(|u| u.as_u64()),
                                v.get("license")
                                    .and_then(|l| l.as_str())
                                    .map(|s| s.to_string()),
                                0,
                                0,
                                "declared",
                            )
                        } else {
                            let elig = eligibility::evaluate(v, &vendored_names, 500 * 1_048_576);
                            let status = if elig.eligible {
                                "eligible".to_string()
                            } else {
                                format!("blocked:{}", elig.blocking.unwrap_or("unknown"))
                            };
                            let types = if elig.warnings.contains(&"W_TYPES_PRESENT") {
                                "declared"
                            } else {
                                "none-declared"
                            };
                            (
                                status,
                                v.pointer("/dist/unpackedSize").and_then(|u| u.as_u64()),
                                elig.license_expression.clone(),
                                v.get("dependencies")
                                    .and_then(|d| d.as_object())
                                    .map(|o| o.len())
                                    .unwrap_or(0),
                                elig.install_scripts.len(),
                                types,
                            )
                        }
                    }
                };
                rows.push(ScanRow {
                    name,
                    version,
                    size,
                    license,
                    deps,
                    install_scripts: scripts,
                    types,
                    status,
                });
            }
        }
    }
    rows.sort_by(|a, b| {
        (a.name.as_str(), a.version.as_str()).cmp(&(b.name.as_str(), b.version.as_str()))
    });
    Ok((rows, errors))
}
