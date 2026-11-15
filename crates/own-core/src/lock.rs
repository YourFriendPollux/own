//! Data structures for `own.lock` (SPEC §7.1) and package manifests (§7.2),
//! plus their canonical serialization via `toml_write`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lock {
    pub metadata: Metadata,
    #[serde(default, rename = "package")]
    pub packages: Vec<Package>,
    #[serde(default, rename = "decision")]
    pub decisions: Vec<Decision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Metadata {
    #[serde(deserialize_with = "supported_lock_schema")]
    pub schema_version: u32,
    pub own_version: Option<String>,
    pub extractor_version: Option<String>,
    pub license_policy_sha256: String,
    pub vendor_files_sha256: String,
    pub licenses_md_sha256: Option<String>,
    pub lock_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Package {
    pub name: String,
    pub ecosystem: String,
    pub version: String,
    pub dir: String,
    pub registry: String,
    pub integrity: String,
    pub tarball_sha256: String,
    pub version_manifest_sha256: String,
    pub provenance_level: String,
    pub provenance_source: Option<String>,
    pub mode: String,
    pub roots: Vec<String>,
    pub dependents: Vec<String>,
    pub license_expression: String,
    pub license_selected: Option<String>,
    pub license_policy: String,
    pub license_files: Vec<LicenseFile>,
    pub package_files_sha256: String,
    pub file_count: u64,
    pub total_size: u64,
    pub diamond_resolution: Option<String>,
    pub unified_ranges: Option<Vec<UnifiedRange>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LicenseFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnifiedRange {
    pub dependent: String,
    pub range: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Decision {
    pub name: String,
    pub version: String,
    pub strategy: String,
    pub dependents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest: ManifestHeader,
    #[serde(default, rename = "file")]
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManifestHeader {
    #[serde(deserialize_with = "supported_manifest_schema")]
    pub schema_version: u32,
    pub package: String,
    pub package_files_sha256: String,
    pub file_count: u64,
    pub total_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub exec: bool,
}

/// Directory name for a package: `<name>@<version>`, scoped names use
/// `@scope+name@version` (never `/`) — SPEC §5.
pub fn dir_name(name: &str, version: &str) -> String {
    if let Some(scope_rest) = name.strip_prefix('@') {
        // @scope/name -> @scope+name
        let plus = scope_rest.replace('/', "+");
        format!("@{}@{}", plus, version)
    } else {
        format!("{}@{}", name, version)
    }
}

/// pnpm override key for one vendored package version.
///
/// A name vendored in several versions cannot use the bare `name` key: pnpm
/// applies `name@version` per resolved version, while a bare key would pin
/// every version to one directory. Unlike [`dir_name`], scoped names keep the
/// `/` here because this is a package spec, not a directory name.
pub fn versioned_override_key(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}

/// Parse a lock from TOML text (reading only; writing is canonical via toml_write).
pub fn parse_lock(text: &str) -> Result<Lock, toml::de::Error> {
    toml::from_str(text)
}

fn supported_lock_schema<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u32, D::Error> {
    let version = u32::deserialize(deserializer)?;
    if version != crate::canonical::SCHEMA_VERSION {
        return Err(<D::Error as serde::de::Error>::custom(format!(
            "LOCK_SCHEMA_UNSUPPORTED: {version}"
        )));
    }
    Ok(version)
}

pub fn parse_manifest(text: &str) -> Result<Manifest, toml::de::Error> {
    let manifest: Manifest = toml::from_str(text)?;
    let mut paths = std::collections::BTreeSet::new();
    for file in &manifest.files {
        crate::path_safety::validate_relative(&file.path)
            .map_err(<toml::de::Error as serde::de::Error>::custom)?;
        if !paths.insert(&file.path) {
            return Err(<toml::de::Error as serde::de::Error>::custom(
                "duplicate manifest path",
            ));
        }
    }
    Ok(manifest)
}

fn supported_manifest_schema<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u32, D::Error> {
    let version = u32::deserialize(deserializer)?;
    if version != crate::canonical::SCHEMA_VERSION {
        return Err(<D::Error as serde::de::Error>::custom(format!(
            "MANIFEST_SCHEMA_UNSUPPORTED: {version}"
        )));
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_name_scoped_inv1() {
        assert_eq!(dir_name("zod", "3.22.4"), "zod@3.22.4");
        assert_eq!(dir_name("@scope/name", "1.0.0"), "@scope+name@1.0.0");
    }

    #[test]
    fn lock_roundtrip_parse_inv10() {
        let text = r#"[metadata]
schema_version = 1
own_version = "0.1.0"
extractor_version = "1"
license_policy_sha256 = "sha256:f23c02299b6304ae42886963d918e1a4b16cae83e70bc45efbd4102e50e5e2d1"
vendor_files_sha256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
lock_digest = "sha256:cb21ba33540b37168a24bdaafd515c2c670908aed7867e35df97549b946f00af"
"#;
        let lock = parse_lock(text).unwrap();
        assert_eq!(lock.metadata.schema_version, 1);
        assert!(lock.packages.is_empty());
    }
}
