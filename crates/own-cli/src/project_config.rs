//! Validated project settings shared by registry/OSV/extraction callers.
use own_extract::SecurityLimits;
use own_net::NetConfig;
use std::path::Path;

#[allow(dead_code)]
pub struct ProjectConfig {
    pub net: NetConfig,
    pub security: SecurityLimits,
    pub osv_url: String,
    pub osv_max_download_mb: u64,
}

fn number(table: Option<&toml::Table>, key: &str, default: u64, zero: bool) -> Result<u64, String> {
    let Some(value) = table.and_then(|table| table.get(key)) else {
        return Ok(default);
    };
    let value = value
        .as_integer()
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| zero || *value > 0)
        .ok_or_else(|| {
            format!(
                "PARSE_ERROR: own.toml {key} must be a {}integer",
                if zero { "nonnegative " } else { "positive " }
            )
        })?;
    Ok(value)
}
fn megabytes(table: Option<&toml::Table>, key: &str, default: u64) -> Result<u64, String> {
    number(table, key, default / 1_048_576, false)?
        .checked_mul(1_048_576)
        .ok_or_else(|| format!("PARSE_ERROR: own.toml {key} overflows bytes"))
}
fn section<'a>(root: &'a toml::Table, name: &str) -> Result<Option<&'a toml::Table>, String> {
    root.get(name)
        .map(|value| {
            value
                .as_table()
                .ok_or_else(|| format!("PARSE_ERROR: own.toml [{name}] must be a table"))
        })
        .transpose()
}
fn endpoint(table: Option<&toml::Table>, key: &str, default: &str) -> Result<String, String> {
    match table.and_then(|table| table.get(key)) {
        None => Ok(default.to_string()),
        Some(value) => value
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("PARSE_ERROR: own.toml {key} must be a nonempty URL string")),
    }
}
fn size(value: u64, key: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("PARSE_ERROR: own.toml {key} exceeds platform size"))
}

pub fn load(root: &Path) -> Result<ProjectConfig, String> {
    let text = match std::fs::read_to_string(root.join("own.toml")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("IO_ERROR: own.toml: {error}")),
    };
    parse(&text)
}

pub fn parse(text: &str) -> Result<ProjectConfig, String> {
    let value: toml::Value =
        toml::from_str(text).map_err(|error| format!("PARSE_ERROR: own.toml: {error}"))?;
    let root = value
        .as_table()
        .ok_or("PARSE_ERROR: own.toml must be a table")?;
    own_core::config::license_policy_json(text)?;
    let registry = section(root, "registry")?;
    let network = section(root, "net")?;
    let security = section(root, "security")?;
    let osv = section(root, "osv")?;
    let mut net = NetConfig::default();
    net.registry_url = endpoint(registry, "url", &net.registry_url)?;
    net.mirror_url = registry
        .and_then(|table| table.get("mirror"))
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or("PARSE_ERROR: own.toml mirror must be a nonempty URL string".to_string())
        })
        .transpose()?;
    net.connect_timeout_s = number(network, "connect_timeout_s", net.connect_timeout_s, false)?;
    net.read_timeout_s = number(network, "read_timeout_s", net.read_timeout_s, false)?;
    net.max_retries = u32::try_from(number(
        network,
        "max_retries",
        u64::from(net.max_retries),
        true,
    )?)
    .map_err(|_| "PARSE_ERROR: own.toml max_retries exceeds u32".to_string())?;
    net.max_packument_size = megabytes(network, "max_packument_size_mb", net.max_packument_size)?;
    net.concurrency = size(
        number(network, "concurrency", net.concurrency as u64, false)?,
        "concurrency",
    )?;
    let mut limits = SecurityLimits::default();
    limits.max_tarball_size = megabytes(security, "max_tarball_size_mb", limits.max_tarball_size)?;
    limits.max_unpacked_size =
        megabytes(security, "max_unpacked_size_mb", limits.max_unpacked_size)?;
    limits.max_file_size = megabytes(security, "max_file_size_mb", limits.max_file_size)?;
    limits.max_entries = size(
        number(security, "max_entries", limits.max_entries as u64, false)?,
        "max_entries",
    )?;
    limits.max_compression_ratio = number(
        security,
        "max_compression_ratio",
        limits.max_compression_ratio,
        false,
    )?;
    limits.max_path_bytes = size(
        number(
            security,
            "max_path_bytes",
            limits.max_path_bytes as u64,
            false,
        )?,
        "max_path_bytes",
    )?;
    net.max_tarball_size = limits.max_tarball_size;
    own_net::validate_config(&net)
        .map_err(|error| format!("PARSE_ERROR: own.toml network: {error}"))?;
    let osv_url = endpoint(
        osv,
        "url",
        "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
    )?;
    own_net::validate_endpoint(&osv_url)
        .map_err(|error| format!("PARSE_ERROR: own.toml osv.url: {error}"))?;
    let osv_max_download_mb = number(osv, "max_download_mb", 500, false)?;
    osv_max_download_mb
        .checked_mul(1_048_576)
        .ok_or("PARSE_ERROR: own.toml max_download_mb overflows bytes")?;
    Ok(ProjectConfig {
        net,
        security: limits,
        osv_url,
        osv_max_download_mb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_match_runtime_and_generated_configuration() {
        let config = parse(own_core::config::DEFAULT_OWN_TOML).unwrap();
        assert_eq!(config.net.registry_url, "https://registry.npmjs.org");
        assert_eq!(config.security, SecurityLimits::default());
        assert_eq!(config.net.concurrency, 8);
    }
    #[test]
    fn custom_settings_are_retained_and_apply_to_both_caps() {
        let config = parse("[registry]\nurl='https://registry.example/npm'\nmirror='https://mirror.example/npm'\n[net]\nconcurrency=2\nconnect_timeout_s=1\nread_timeout_s=3\nmax_retries=0\nmax_packument_size_mb=2\n[security]\nmax_tarball_size_mb=4\nmax_unpacked_size_mb=5\nmax_file_size_mb=1\nmax_entries=100\nmax_path_bytes=80\nmax_compression_ratio=10\n[osv]\nurl='https://osv.example/npm.zip'\nmax_download_mb=6\n").unwrap();
        assert_eq!(
            config.net.mirror_url.as_deref(),
            Some("https://mirror.example/npm")
        );
        assert_eq!(config.net.registry_url, "https://registry.example/npm");
        assert_eq!(config.net.max_tarball_size, 4 * 1_048_576);
        assert_eq!(
            config.security.max_tarball_size,
            config.net.max_tarball_size
        );
        assert_eq!(config.security.max_unpacked_size, 5 * 1_048_576);
        assert_eq!(config.net.max_retries, 0);
        assert_eq!(config.osv_max_download_mb, 6);
    }
}
