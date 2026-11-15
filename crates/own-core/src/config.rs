//! Default `own.toml` (SPEC §7.4) and minimal config reading.

use crate::canonical::default_license_policy;

pub const DEFAULT_OWN_TOML: &str = r#"schema_version = 1

[registry]
url = "https://registry.npmjs.org"
# mirror = "https://npm.mirror.internal"

[license]
allow  = ["MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC"]
review = ["LGPL-2.1-only", "LGPL-3.0-only", "MPL-2.0"]
deny   = ["GPL-*", "AGPL-*", "BSL-*", "PolyForm-*", "SSPL-*", "Elastic-2.0"]
unknown = "deny"

[osv]
url = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
api_url = "https://api.osv.dev"
local_path = ".own/osv.json"
max_age_days = 7
max_download_mb = 500
ignore = []

[security]
max_tarball_size_mb = 100
max_unpacked_size_mb = 500
max_file_size_mb = 10
max_entries = 20000
max_compression_ratio = 100
max_path_bytes = 200

[net]
connect_timeout_s = 10
read_timeout_s = 30
max_retries = 3
max_packument_size_mb = 64
concurrency = 8
"#;

/// The `[license]` section of own.toml as a JSON value (for license_policy_sha256).
pub fn license_policy_json(toml_text: &str) -> Result<serde_json::Value, String> {
    let v: toml::Value =
        toml::from_str(toml_text).map_err(|e| format!("PARSE_ERROR: own.toml: {e}"))?;
    let table = v
        .as_table()
        .ok_or("PARSE_ERROR: own.toml root must be a table")?;
    if let Some(version) = table.get("schema_version") {
        if version.as_integer() != Some(crate::canonical::SCHEMA_VERSION as i64) {
            return Err("CONFIG_SCHEMA_UNSUPPORTED: own.toml schema_version".into());
        }
    }
    let Some(lic) = table.get("license") else {
        return Ok(default_license_policy());
    };
    let policy =
        serde_json::to_value(lic).map_err(|e| format!("PARSE_ERROR: own.toml license: {e}"))?;
    validate_license_policy(&policy)?;
    if policy.as_object().unwrap().is_empty() {
        return Ok(default_license_policy());
    }
    Ok(policy)
}

/// Refuse malformed policy values instead of normalizing them into a different
/// policy. Missing fields are permitted; malformed present fields never are.
pub fn validate_license_policy(policy: &serde_json::Value) -> Result<(), String> {
    let object = policy
        .as_object()
        .ok_or("PARSE_ERROR: license policy must be an object")?;
    for (key, value) in object {
        match key.as_str() {
            "allow" | "review" | "deny" => {
                let arr = value
                    .as_array()
                    .ok_or_else(|| format!("PARSE_ERROR: license.{key} must be an array"))?;
                if arr.iter().any(|v| v.as_str().is_none_or(|s| s.is_empty())) {
                    return Err(format!(
                        "PARSE_ERROR: license.{key} entries must be nonempty strings"
                    ));
                }
            }
            "unknown" if value.as_str() == Some("deny") => {}
            "unknown" => return Err("PARSE_ERROR: license.unknown must be 'deny'".into()),
            _ => return Err(format!("PARSE_ERROR: unknown license field: {key}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::license_policy_sha256;

    #[test]
    fn default_toml_policy_hash_matches_golden_inv10() {
        let pol = license_policy_json(DEFAULT_OWN_TOML).unwrap();
        assert_eq!(
            license_policy_sha256(&pol),
            "sha256:f23c02299b6304ae42886963d918e1a4b16cae83e70bc45efbd4102e50e5e2d1"
        );
    }
}
