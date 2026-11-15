//! npm registry client (SPEC §5, §10.2): packument fetch + tarball download with
//! streaming hashes and hard caps. HTTPS only; redirects followed only to the
//! same host as the configured registry/mirror; `dist.tarball` on another host
//! is `TARBALL_HOST_MISMATCH` (no SSRF).

use reqwest::blocking::Client;
use reqwest::Url;
use sha2::{Digest, Sha256, Sha512};
use std::io::Read;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct NetConfig {
    pub registry_url: String, // canonical, no trailing slash, no credentials
    pub mirror_url: Option<String>, // explicitly trusted registry mirror
    pub connect_timeout_s: u64,
    pub read_timeout_s: u64,
    pub max_retries: u32,
    pub max_packument_size: u64, // bytes
    pub max_tarball_size: u64,   // compressed bytes
    pub concurrency: usize,
    pub user_agent: String,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            registry_url: "https://registry.npmjs.org".to_string(),
            mirror_url: None,
            connect_timeout_s: 10,
            read_timeout_s: 30,
            max_retries: 3,
            max_packument_size: 64 * 1_048_576,
            max_tarball_size: 100 * 1_048_576,
            concurrency: 8,
            user_agent: format!("own/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

pub fn build_client(cfg: &NetConfig) -> Result<Client, String> {
    validate_config(cfg)?;
    let b = Client::builder()
        .user_agent(&cfg.user_agent)
        .connect_timeout(Duration::from_secs(cfg.connect_timeout_s))
        .timeout(Duration::from_secs(cfg.read_timeout_s))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                return attempt.error("redirect limit exceeded");
            }
            // Never downgrade HTTPS or cross ports/credentials on a redirect.
            if attempt
                .previous()
                .last()
                .is_some_and(|previous| safe_redirect(previous, attempt.url()))
            {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }));
    // proxies: HTTPS_PROXY/NO_PROXY respected via reqwest's system proxy detection
    b.build().map_err(|e| format!("NETWORK_ERROR: {e}"))
}

fn validated_registry_url(cfg: &NetConfig) -> Result<Url, String> {
    validate_endpoint(&cfg.registry_url)
}

pub fn validate_endpoint(endpoint: &str) -> Result<Url, String> {
    let url = Url::parse(endpoint).map_err(|_| "USAGE_ERROR: invalid registry url".to_string())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "USAGE_ERROR: registry url must be HTTPS without credentials, query or fragment".into(),
        );
    }
    Ok(url)
}

pub fn validate_config(cfg: &NetConfig) -> Result<(), String> {
    validated_registry_url(cfg)?;
    if let Some(mirror) = &cfg.mirror_url {
        validate_endpoint(mirror)?;
    }
    if cfg.connect_timeout_s == 0
        || cfg.read_timeout_s == 0
        || cfg.max_packument_size == 0
        || cfg.max_tarball_size == 0
        || cfg.concurrency == 0
    {
        return Err("USAGE_ERROR: network limits must be positive".into());
    }
    Ok(())
}

fn safe_redirect(previous: &Url, next: &Url) -> bool {
    next.scheme() == "https"
        && next.username().is_empty()
        && next.password().is_none()
        && previous.origin() == next.origin()
}

fn registry_endpoint(cfg: &NetConfig) -> Result<&str, String> {
    validate_config(cfg)?;
    Ok(cfg.mirror_url.as_deref().unwrap_or(&cfg.registry_url))
}

fn tarball_request_url(cfg: &NetConfig, input: &str) -> Result<Url, String> {
    validate_config(cfg)?;
    let registry = validated_registry_url(cfg)?;
    let original = Url::parse(input).map_err(|e| format!("USAGE_ERROR: tarball url: {e}"))?;
    if original.scheme() != "https"
        || !original.username().is_empty()
        || original.password().is_some()
        || original.fragment().is_some()
    {
        return Err("TARBALL_HOST_MISMATCH: non-https or credentialed tarball".into());
    }
    let mirror = cfg
        .mirror_url
        .as_deref()
        .map(validate_endpoint)
        .transpose()?;
    if mirror
        .as_ref()
        .is_some_and(|mirror| original.origin() == mirror.origin())
    {
        return Ok(original);
    }
    if original.origin() != registry.origin() {
        return Err("TARBALL_HOST_MISMATCH".into());
    }
    let Some(mut mirror) = mirror else {
        return Ok(original);
    };
    let prefix = format!("{}/", registry.path().trim_end_matches('/'));
    let relative = original
        .path()
        .strip_prefix(&prefix)
        .ok_or("TARBALL_HOST_MISMATCH: outside registry path")?;
    let path = format!("{}/{}", mirror.path().trim_end_matches('/'), relative);
    mirror.set_path(&path);
    mirror.set_query(original.query());
    Ok(mirror)
}

/// Fetch the full packument (`Accept: application/json`) for `name`.
/// Returns the raw JSON bytes (capped) — parsing is own-policy's job.
pub fn fetch_packument(client: &Client, cfg: &NetConfig, name: &str) -> Result<Vec<u8>, String> {
    let endpoint = registry_endpoint(cfg)?;
    let url = format!(
        "{}/{}",
        endpoint.trim_end_matches('/'),
        name.replace('/', "%2F")
    );
    let mut last_err = String::new();
    for attempt in 0..=cfg.max_retries {
        match client.get(&url).header("Accept", "application/json").send() {
            Ok(resp) => {
                let status = resp.status();
                if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
                    return Err("VERSION_NOT_FOUND".to_string());
                }
                if status.is_server_error() && attempt < cfg.max_retries {
                    last_err = format!("REGISTRY_UNAVAILABLE: HTTP {status}");
                    continue;
                }
                if !status.is_success() {
                    return Err(format!("REGISTRY_UNAVAILABLE: HTTP {status}"));
                }
                let mut buf = Vec::new();
                let mut resp = resp;
                let mut chunk = [0u8; 65536];
                loop {
                    let n = resp
                        .read(&mut chunk)
                        .map_err(|e| format!("NETWORK_ERROR: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    if buf.len() + n > cfg.max_packument_size as usize {
                        return Err(
                            "NETWORK_ERROR: packument exceeds max_packument_size_mb".to_string()
                        );
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                return Ok(buf);
            }
            Err(e) => {
                let retriable = e.is_timeout() || e.is_connect();
                if retriable && attempt < cfg.max_retries {
                    last_err = format!("NETWORK_ERROR: {e}");
                    continue;
                }
                return Err(format!("NETWORK_ERROR: {e}"));
            }
        }
    }
    Err(last_err)
}

#[derive(Debug)]
pub struct TarballDownload {
    pub bytes: Vec<u8>,
    pub sha512_hex: String,
    pub sha256: String, // "sha256:<hex>"
}

/// Download `tarball_url` enforcing: same host as registry (§10.2), compressed
/// cap, streaming sha512 + sha256. Returns the bytes + hashes.
pub fn fetch_tarball(
    client: &Client,
    cfg: &NetConfig,
    tarball_url: &str,
) -> Result<TarballDownload, String> {
    let url = tarball_request_url(cfg, tarball_url)?;
    let mut last_err = String::new();
    for attempt in 0..=cfg.max_retries {
        match client.get(url.clone()).send() {
            Ok(resp) => {
                let status = resp.status();
                if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
                    return Err("TARBALL_REMOVED".to_string());
                }
                if status.is_server_error() && attempt < cfg.max_retries {
                    last_err = format!("REGISTRY_UNAVAILABLE: HTTP {status}");
                    continue;
                }
                if !status.is_success() {
                    return Err(format!("REGISTRY_UNAVAILABLE: HTTP {status}"));
                }
                let mut resp = resp;
                let mut buf = Vec::new();
                let mut h512 = Sha512::new();
                let mut h256 = Sha256::new();
                let mut chunk = [0u8; 65536];
                loop {
                    let n = resp
                        .read(&mut chunk)
                        .map_err(|e| format!("NETWORK_ERROR: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    if buf.len() + n > cfg.max_tarball_size as usize {
                        return Err("EXTRACT_REFUSED:max_tarball_size".to_string());
                    }
                    h512.update(&chunk[..n]);
                    h256.update(&chunk[..n]);
                    buf.extend_from_slice(&chunk[..n]);
                }
                let sha512_hex: String =
                    h512.finalize().iter().map(|b| format!("{b:02x}")).collect();
                let sha256 = format!("sha256:{:x}", h256.finalize());
                return Ok(TarballDownload {
                    bytes: buf,
                    sha512_hex,
                    sha256,
                });
            }
            Err(e) => {
                let retriable = e.is_timeout() || e.is_connect();
                if retriable && attempt < cfg.max_retries {
                    last_err = format!("NETWORK_ERROR: {e}");
                    continue;
                }
                return Err(format!("NETWORK_ERROR: {e}"));
            }
        }
    }
    Err(last_err)
}

/// Verify npm SRI `sha512-<base64>` against the downloaded bytes.
pub fn verify_sri_integrity(sri: &str, bytes: &[u8]) -> Result<String, String> {
    let hex = sri
        .strip_prefix("sha512-")
        .ok_or_else(|| "NOT_ELIGIBLE:integrity_missing".to_string())?;
    let expected =
        base64_decode(hex).ok_or_else(|| "NOT_ELIGIBLE:integrity_missing".to_string())?;
    let mut h = Sha512::new();
    h.update(bytes);
    let got = h.finalize();
    if got.as_slice() != expected.as_slice() {
        return Err("INTEGRITY_MISMATCH".to_string());
    }
    let sha512_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    Ok(sha512_hex)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    // SHA-512 is 64 bytes: 86 symbols and two padding bytes. Never accept a prefix.
    if s.len() != 88 || !s.ends_with("==") {
        return None;
    }
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits = 0;
    for &c in &s.as_bytes()[..86] {
        let v = TABLE.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if out.len() != 64 || acc & 0x0f != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_routes_only_explicitly_trusted_registry_origins() {
        let config = NetConfig {
            registry_url: "https://registry.example/npm".into(),
            mirror_url: Some("https://mirror.example/packages".into()),
            ..NetConfig::default()
        };
        assert_eq!(
            registry_endpoint(&config).unwrap(),
            "https://mirror.example/packages"
        );
        let original = "https://registry.example/npm/pkg/-/pkg-1.0.0.tgz";
        assert_eq!(
            tarball_request_url(&config, original).unwrap().as_str(),
            "https://mirror.example/packages/pkg/-/pkg-1.0.0.tgz"
        );
        assert_eq!(config.registry_url, "https://registry.example/npm");
        for unsafe_url in [
            "https://elsewhere.example/pkg.tgz",
            "https://registry.example:444/npm/pkg.tgz",
            "https://registry.example/npm-other/pkg.tgz",
            "https://user:password@mirror.example/packages/pkg.tgz",
        ] {
            assert!(
                tarball_request_url(&config, unsafe_url).is_err(),
                "{unsafe_url}"
            );
        }
    }

    #[test]
    fn untrusted_mirror_configuration_is_rejected_without_network() {
        for endpoint in [
            "http://mirror.example",
            "https://user:password@mirror.example",
            "https://mirror.example?token=value",
        ] {
            let config = NetConfig {
                mirror_url: Some(endpoint.into()),
                ..NetConfig::default()
            };
            assert!(validate_config(&config).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn redirects_preserve_https_origin_without_credentials_inv4() {
        let previous = Url::parse("https://registry.npmjs.org/a").unwrap();
        assert!(safe_redirect(
            &previous,
            &Url::parse("https://registry.npmjs.org/b").unwrap()
        ));
        for next in [
            "http://registry.npmjs.org/b",
            "https://registry.npmjs.org:444/b",
            "https://other.invalid/b",
            "https://user:password@registry.npmjs.org/b",
        ] {
            assert!(!safe_redirect(&previous, &Url::parse(next).unwrap()));
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct OsvDump {
    pub bytes: Vec<u8>,
    /// Original HTTP source date, converted to UTC by the snapshot writer.
    pub last_modified: Option<String>,
}

/// Fetch capped OSV zip bytes and retain the source's Last-Modified header.
/// No archive entry is extracted to disk by this transport function.
pub fn fetch_osv_dump(
    client: &Client,
    osv_url: &str,
    max_download_mb: u64,
) -> Result<OsvDump, String> {
    fetch_osv_with_retries(client, osv_url, max_download_mb, 3)
}

pub fn fetch_osv_dump_configured(
    client: &Client,
    config: &NetConfig,
    osv_url: &str,
    max_download_mb: u64,
) -> Result<OsvDump, String> {
    validate_config(config)?;
    fetch_osv_with_retries(client, osv_url, max_download_mb, config.max_retries)
}

fn fetch_osv_with_retries(
    client: &Client,
    osv_url: &str,
    max_download_mb: u64,
    retries: u32,
) -> Result<OsvDump, String> {
    let url = Url::parse(osv_url).map_err(|e| format!("USAGE_ERROR: osv url: {e}"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("NETWORK_ERROR: osv url must be https without credentials".to_string());
    }
    if max_download_mb == 0 {
        return Err("USAGE_ERROR: max_download_mb must be positive".into());
    }
    let cap = max_download_mb
        .checked_mul(1_048_576)
        .ok_or("USAGE_ERROR: max_download_mb overflow")?;
    let mut last_err = String::new();
    for attempt in 0..=retries {
        match client.get(osv_url).send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() && attempt < retries {
                    last_err = format!("NETWORK_ERROR: HTTP {status}");
                    continue;
                }
                if !status.is_success() {
                    return Err(format!("NETWORK_ERROR: HTTP {status}"));
                }
                let last_modified =
                    resp.headers()
                        .get(reqwest::header::LAST_MODIFIED)
                        .map(|value| {
                            value.to_str().map(str::to_owned).map_err(|_| {
                                "NETWORK_ERROR: invalid Last-Modified header".to_string()
                            })
                        })
                        .transpose()?;
                let mut resp = resp;
                let mut buf = Vec::new();
                let mut chunk = [0u8; 65536];
                loop {
                    let n = resp
                        .read(&mut chunk)
                        .map_err(|e| format!("NETWORK_ERROR: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    if buf.len() + n > cap as usize {
                        return Err("NETWORK_ERROR: osv dump exceeds max_download_mb".to_string());
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                return Ok(OsvDump {
                    bytes: buf,
                    last_modified,
                });
            }
            Err(e) if (e.is_timeout() || e.is_connect()) && attempt < retries => {
                last_err = format!("NETWORK_ERROR: {e}");
            }
            Err(e) => return Err(format!("NETWORK_ERROR: {e}")),
        }
    }
    Err(last_err)
}
