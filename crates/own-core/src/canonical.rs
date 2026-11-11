//! Canonical serialization of `own.lock` (SPEC §7.1) and digest computation
//! (SPEC §7.3): `vendor_files_sha256`, `license_policy_sha256`, `lock_digest`.
//!
//! Key order for `[[package]]` (normative, §7.1):
//! name, ecosystem, version, dir, registry, integrity, tarball_sha256,
//! version_manifest_sha256, provenance_level, provenance_source, mode, roots,
//! dependents, license_expression, license_selected, license_policy,
//! license_files, package_files_sha256, file_count, total_size,
//! diamond_resolution, unified_ranges.

use crate::jcs::canonicalize;
use crate::lock::{Decision, Lock, Metadata, Package};
use crate::sha256_hex;
use crate::toml_write::{basic_string, TomlWriter};
use crate::vendor_files_sha256;
use serde_json::json;

pub const SCHEMA_VERSION: u32 = 1;

/// Default license policy (§7.4) as a JSON value, used for `license_policy_sha256`.
pub fn default_license_policy() -> serde_json::Value {
    json!({
        "allow": ["MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC"],
        "review": ["LGPL-2.1-only", "LGPL-3.0-only", "MPL-2.0"],
        "deny": ["GPL-*", "AGPL-*", "BSL-*", "PolyForm-*", "SSPL-*", "Elastic-2.0"],
        "unknown": "deny"
    })
}

/// `license_policy_sha256` of §7.3: JCS of the normalized policy object
/// (arrays sorted byte-wise and deduped, missing keys defaulted).
pub fn license_policy_sha256(policy: &serde_json::Value) -> String {
    let norm = normalize_policy(policy);
    let canon = canonicalize(&norm).expect("policy is JCS-safe");
    sha256_hex(canon.as_bytes())
}

fn normalize_policy(p: &serde_json::Value) -> serde_json::Value {
    let get_arr = |k: &str| -> Vec<String> {
        let mut v: Vec<String> = p
            .get(k)
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v.dedup();
        v
    };
    json!({
        "allow": get_arr("allow"),
        "review": get_arr("review"),
        "deny": get_arr("deny"),
        "unknown": p.get("unknown").and_then(|u| u.as_str()).unwrap_or("deny"),
    })
}

/// Compute `vendor_files_sha256` from the lock's packages (§7.3).
pub fn compute_vendor_files_sha256(packages: &[Package]) -> String {
    let entries: Vec<(String, String)> = packages
        .iter()
        .map(|p| {
            (
                p.package_files_sha256
                    .strip_prefix("sha256:")
                    .unwrap_or(&p.package_files_sha256)
                    .to_string(),
                p.dir.clone(),
            )
        })
        .collect();
    vendor_files_sha256(&entries)
}

/// `lock_digest` of §7.3: JCS of { schema_version, packages, decisions,
/// vendor_files_sha256, licenses_md_sha256?, license_policy_sha256, overrides }.
/// `overrides` = map of pnpm.overrides entries whose value starts with `file:vendor/own/`.
pub fn compute_lock_digest(
    lock: &Lock,
    overrides: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let packages: Vec<serde_json::Value> = {
        let mut v: Vec<_> = lock.packages.iter().map(package_to_json).collect();
        v.sort_by(|a, b| {
            let ka = (a["name"].as_str().unwrap(), a["version"].as_str().unwrap());
            let kb = (b["name"].as_str().unwrap(), b["version"].as_str().unwrap());
            ka.cmp(&kb)
        });
        v
    };
    let decisions: Vec<serde_json::Value> = {
        let mut v: Vec<_> = lock.decisions.iter().map(decision_to_json).collect();
        v.sort_by(|a, b| {
            let ka = (a["name"].as_str().unwrap(), a["version"].as_str().unwrap());
            let kb = (b["name"].as_str().unwrap(), b["version"].as_str().unwrap());
            ka.cmp(&kb)
        });
        v
    };
    let mut obj = json!({
        "schema_version": lock.metadata.schema_version,
        "packages": packages,
        "decisions": decisions,
        "vendor_files_sha256": lock.metadata.vendor_files_sha256,
        "license_policy_sha256": lock.metadata.license_policy_sha256,
        "overrides": serde_json::Value::Object(overrides.clone()),
    });
    if let Some(lm) = &lock.metadata.licenses_md_sha256 {
        obj["licenses_md_sha256"] = json!(lm);
    }
    let canon = canonicalize(&obj).expect("lock digest input is JCS-safe");
    sha256_hex(canon.as_bytes())
}

fn package_to_json(p: &Package) -> serde_json::Value {
    // TOML->JSON 1:1 mapping, optional fields omitted when absent.
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(p.name));
    m.insert("ecosystem".into(), json!(p.ecosystem));
    m.insert("version".into(), json!(p.version));
    m.insert("dir".into(), json!(p.dir));
    m.insert("registry".into(), json!(p.registry));
    m.insert("integrity".into(), json!(p.integrity));
    m.insert("tarball_sha256".into(), json!(p.tarball_sha256));
    m.insert(
        "version_manifest_sha256".into(),
        json!(p.version_manifest_sha256),
    );
    m.insert("provenance_level".into(), json!(p.provenance_level));
    if let Some(ps) = &p.provenance_source {
        m.insert("provenance_source".into(), json!(ps));
    }
    m.insert("mode".into(), json!(p.mode));
    m.insert("roots".into(), json!(p.roots));
    m.insert("dependents".into(), json!(p.dependents));
    m.insert("license_expression".into(), json!(p.license_expression));
    if let Some(ls) = &p.license_selected {
        m.insert("license_selected".into(), json!(ls));
    }
    m.insert("license_policy".into(), json!(p.license_policy));
    m.insert(
        "license_files".into(),
        json!(p
            .license_files
            .iter()
            .map(|f| json!({"path": f.path, "sha256": f.sha256}))
            .collect::<Vec<_>>()),
    );
    m.insert("package_files_sha256".into(), json!(p.package_files_sha256));
    m.insert("file_count".into(), json!(p.file_count));
    m.insert("total_size".into(), json!(p.total_size));
    if let Some(dr) = &p.diamond_resolution {
        m.insert("diamond_resolution".into(), json!(dr));
    }
    if let Some(ur) = &p.unified_ranges {
        m.insert(
            "unified_ranges".into(),
            json!(ur
                .iter()
                .map(|r| json!({"dependent": r.dependent, "range": r.range}))
                .collect::<Vec<_>>()),
        );
    }
    serde_json::Value::Object(m)
}

fn decision_to_json(d: &Decision) -> serde_json::Value {
    json!({
        "name": d.name,
        "version": d.version,
        "strategy": d.strategy,
        "dependents": d.dependents,
    })
}

/// Serialize a lock canonically (§7.1): `[metadata]`, blank line, `[[package]]*`,
/// blank line, `[[decision]]*`. Packages/decisions sorted by (name, version) bytes.
pub fn write_lock_canonical(lock: &Lock) -> String {
    let mut w = TomlWriter::new();
    let md = &lock.metadata;
    w.section("[metadata]")
        .key_int("schema_version", md.schema_version as u64);
    if let Some(v) = &md.own_version {
        w.key_string("own_version", v);
    }
    if let Some(v) = &md.extractor_version {
        w.key_string("extractor_version", v);
    }
    w.key_string("license_policy_sha256", &md.license_policy_sha256)
        .key_string("vendor_files_sha256", &md.vendor_files_sha256);
    if let Some(v) = &md.licenses_md_sha256 {
        w.key_string("licenses_md_sha256", v);
    }
    w.key_string("lock_digest", &md.lock_digest);

    let mut packages: Vec<&Package> = lock.packages.iter().collect();
    packages.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    for p in packages {
        w.section("[[package]]")
            .key_string("name", &p.name)
            .key_string("ecosystem", &p.ecosystem)
            .key_string("version", &p.version)
            .key_string("dir", &p.dir)
            .key_string("registry", &p.registry)
            .key_string("integrity", &p.integrity)
            .key_string("tarball_sha256", &p.tarball_sha256)
            .key_string("version_manifest_sha256", &p.version_manifest_sha256)
            .key_string("provenance_level", &p.provenance_level);
        if let Some(ps) = &p.provenance_source {
            w.key_string("provenance_source", ps);
        }
        w.key_string("mode", &p.mode)
            .key_str_array("roots", &p.roots)
            .key_str_array("dependents", &p.dependents)
            .key_string("license_expression", &p.license_expression);
        if let Some(ls) = &p.license_selected {
            w.key_string("license_selected", ls);
        }
        w.key_string("license_policy", &p.license_policy);
        let lf = p
            .license_files
            .iter()
            .map(|f| {
                format!(
                    "{{ path = {}, sha256 = {} }}",
                    basic_string(&f.path),
                    basic_string(&f.sha256)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        w.key_value("license_files", &format!("[{}]", lf))
            .key_string("package_files_sha256", &p.package_files_sha256)
            .key_int("file_count", p.file_count)
            .key_int("total_size", p.total_size);
        if let Some(dr) = &p.diamond_resolution {
            w.key_string("diamond_resolution", dr);
        }
        if let Some(ur) = &p.unified_ranges {
            let s = ur
                .iter()
                .map(|r| {
                    format!(
                        "{{ dependent = {}, range = {} }}",
                        basic_string(&r.dependent),
                        basic_string(&r.range)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            w.key_value("unified_ranges", &format!("[{}]", s));
        }
    }

    let mut decisions: Vec<&Decision> = lock.decisions.iter().collect();
    decisions.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    for d in decisions {
        w.section("[[decision]]")
            .key_string("name", &d.name)
            .key_string("version", &d.version)
            .key_string("strategy", &d.strategy)
            .key_str_array("dependents", &d.dependents);
    }
    w.finish()
}

/// Build a valid empty lock (§8.1 `init`): metadata with computed digests.
pub fn empty_lock(
    own_version: &str,
    extractor_version: &str,
    overrides: &serde_json::Map<String, serde_json::Value>,
) -> Lock {
    let policy_hash = license_policy_sha256(&default_license_policy());
    let vendor_hash = vendor_files_sha256(&[]);
    let mut lock = Lock {
        metadata: Metadata {
            schema_version: SCHEMA_VERSION,
            own_version: Some(own_version.to_string()),
            extractor_version: Some(extractor_version.to_string()),
            license_policy_sha256: policy_hash,
            vendor_files_sha256: vendor_hash,
            licenses_md_sha256: None,
            lock_digest: String::new(),
        },
        packages: vec![],
        decisions: vec![],
    };
    let digest = compute_lock_digest(&lock, overrides);
    lock.metadata.lock_digest = digest;
    lock
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector §7.3: empty lock digest.
    #[test]
    fn golden_empty_lock_canonical_inv10() {
        let lock = empty_lock("0.1.0", "1", &serde_json::Map::new());
        assert_eq!(
            lock.metadata.lock_digest,
            "sha256:cb21ba33540b37168a24bdaafd515c2c670908aed7867e35df97549b946f00af"
        );
        assert_eq!(
            lock.metadata.license_policy_sha256,
            "sha256:f23c02299b6304ae42886963d918e1a4b16cae83e70bc45efbd4102e50e5e2d1"
        );
        let text = write_lock_canonical(&lock);
        // reparse must succeed and re-serialize byte-identically (canonical round-trip)
        let back = crate::lock::parse_lock(&text).unwrap();
        assert_eq!(write_lock_canonical(&back), text);
    }

    #[test]
    fn lock_digest_changes_with_overrides_inv10() {
        let mut ov = serde_json::Map::new();
        ov.insert("zod".to_string(), json!("file:vendor/own/zod@3.22.4"));
        let l1 = empty_lock("0.1.0", "1", &serde_json::Map::new());
        let l2 = empty_lock("0.1.0", "1", &ov);
        assert_ne!(l1.metadata.lock_digest, l2.metadata.lock_digest);
    }
}
