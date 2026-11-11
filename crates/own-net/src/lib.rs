//! npm registry client (SPEC §5, §10.2): packument fetch + tarball download with
//! streaming hashes and hard caps. HTTPS only; redirects followed only to the
//! same host as the configured registry/mirror; `dist.tarball` on another host
//! is `TARBALL_HOST_MISMATCH` (no SSRF).

use reqwest::blocking::Client;
use reqwest::Url;
use sha2::{Digest, Sha256, Sha512};
use std::io::Read;
use std::time::Duration;

pub struct NetConfig {
    pub registry_url: String, // canonical, no trailing slash, no credentials
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
    let b = Client::builder()
        .user_agent(&cfg.user_agent)
        .connect_timeout(Duration::from_secs(cfg.connect_timeout_s))
        .timeout(Duration::from_secs(cfg.read_timeout_s))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            // follow only same-host redirects
            if attempt.previous().last().and_then(|u| u.host_str()) == attempt.url().host_str() {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }));
    // proxies: HTTPS_PROXY/NO_PROXY respected via reqwest's system proxy detection
    b.build().map_err(|e| format!("NETWORK_ERROR: {e}"))
}

fn registry_host(cfg: &NetConfig) -> Result<String, String> {
    Url::parse(&cfg.registry_url)
        .map_err(|e| format!("USAGE_ERROR: registry url: {e}"))?
        .host_str()
        .map(|h| h.to_string())
        .ok_or_else(|| "USAGE_ERROR: registry url has no host".to_string())
}

/// Fetch the full packument (`Accept: application/json`) for `name`.
/// Returns the raw JSON bytes (capped) — parsing is own-policy's job.
pub fn fetch_packument(client: &Client, cfg: &NetConfig, name: &str) -> Result<Vec<u8>, String> {
    let host = registry_host(cfg)?;
    let url = format!("{}/{}", cfg.registry_url, name.replace('/', "%2F"));
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
                let _ = host;
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
    let host = registry_host(cfg)?;
    let url = Url::parse(tarball_url).map_err(|e| format!("USAGE_ERROR: tarball url: {e}"))?;
    if url.scheme() != "https" {
        return Err("TARBALL_HOST_MISMATCH: non-https tarball".to_string());
    }
    match url.host_str() {
        Some(h) if h == host => {}
        _ => return Err("TARBALL_HOST_MISMATCH".to_string()),
    }
    let mut last_err = String::new();
    for attempt in 0..=cfg.max_retries {
        match client.get(tarball_url).send() {
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
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits = 0;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = TABLE.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// Fetch the OSV npm dump zip (SPEC §8.2), capped by max_download_mb, and
/// return the raw zip bytes (never extracted to disk here; the caller reads
/// entries in memory with the same size/ratio guards as §11.2).
pub fn fetch_osv_dump(
    client: &Client,
    osv_url: &str,
    max_download_mb: u64,
) -> Result<Vec<u8>, String> {
    let url = Url::parse(osv_url).map_err(|e| format!("USAGE_ERROR: osv url: {e}"))?;
    if url.scheme() != "https" {
        return Err("NETWORK_ERROR: osv url must be https".to_string());
    }
    let cap = max_download_mb * 1_048_576;
    let mut last_err = String::new();
    for attempt in 0..=3u32 {
        match client.get(osv_url).send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() && attempt < 3 {
                    last_err = format!("NETWORK_ERROR: HTTP {status}");
                    continue;
                }
                if !status.is_success() {
                    return Err(format!("NETWORK_ERROR: HTTP {status}"));
                }
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
                return Ok(buf);
            }
            Err(e) if (e.is_timeout() || e.is_connect()) && attempt < 3 => {
                last_err = format!("NETWORK_ERROR: {e}");
            }
            Err(e) => return Err(format!("NETWORK_ERROR: {e}")),
        }
    }
    Err(last_err)
}
