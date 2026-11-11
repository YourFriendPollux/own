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
    let lic = v
        .get("license")
        .cloned()
        .unwrap_or_else(|| toml::Value::Table(Default::default()));
    let mut m = serde_json::Map::new();
    for key in ["allow", "review", "deny"] {
        if let Some(arr) = lic.get(key).and_then(|a| a.as_array()) {
            m.insert(
                key.to_string(),
                serde_json::Value::Array(
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| serde_json::json!(s)))
                        .collect(),
                ),
            );
        }
    }
    if let Some(u) = lic.get("unknown").and_then(|u| u.as_str()) {
        m.insert("unknown".to_string(), serde_json::json!(u));
    }
    if m.is_empty() {
        return Ok(default_license_policy());
    }
    Ok(serde_json::Value::Object(m))
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
