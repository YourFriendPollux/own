//! Hardened tarball extraction (SPEC §11.2).
//!
//! The tarball is read **once**: the caller passes an already-verified cache
//! file path whose name is its sha512 hex and mode 0444; we re-hash while
//! copying to a private temp file (0600) and extract from that single open
//! descriptor (INV-3, no TOCTOU).
//!
//! Every refusal is an error `EXTRACT_REFUSED:<rule>`, never a warning.

use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha512};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityLimits {
    pub max_tarball_size: u64,  // compressed stream bytes
    pub max_unpacked_size: u64, // sum of extracted file sizes
    pub max_file_size: u64,     // single file
    pub max_entries: usize,
    pub max_compression_ratio: u64, // decompressed / compressed + 1 MiB slack
    pub max_path_bytes: usize,
}

impl Default for SecurityLimits {
    fn default() -> Self {
        // §7.4 defaults: 1 MB = 1 048 576 octets
        Self {
            max_tarball_size: 100 * 1_048_576,
            max_unpacked_size: 500 * 1_048_576,
            max_file_size: 10 * 1_048_576,
            max_entries: 20_000,
            max_compression_ratio: 100,
            max_path_bytes: 200,
        }
    }
}

pub type ExtractResult<T> = Result<T, String>;

fn refused(rule: &str) -> String {
    format!("EXTRACT_REFUSED:{rule}")
}

/// Verify the cache file: name must be `<sha512 hex>.tgz`, mode 0444, and the
/// re-computed sha512 must match the name (review M5-astra).
pub fn verify_cache_file(path: &Path) -> ExtractResult<()> {
    let md = fs::metadata(path).map_err(|e| format!("IO_ERROR: {e}"))?;
    #[cfg(unix)]
    {
        let mode = md.permissions().mode() & 0o777;
        if mode != 0o444 {
            return Err(format!("IO_ERROR: cache file mode {mode:o} != 0444"));
        }
    }
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| refused("cache_name"))?;
    if name.len() != 128
        || !name
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(refused("cache_name"));
    }
    let mut h = Sha512::new();
    let mut f = File::open(path).map_err(|e| format!("IO_ERROR: {e}"))?;
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("IO_ERROR: {e}"))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if hex != name {
        return Err(refused("cache_hash_mismatch"));
    }
    Ok(())
}

/// Extract a verified gzipped tarball from `cache_path` into `dest_dir`,
/// enforcing every §11.2 rule. `cache_path` must already pass `verify_cache_file`.
/// The archive's single top-level prefix (typically `package/`) is stripped.
pub fn extract(
    cache_path: &Path,
    dest_dir: &Path,
    limits: &SecurityLimits,
) -> ExtractResult<ExtractStats> {
    verify_cache_file(cache_path)?;
    // copy to private temp (0600) re-hashing sha512, then extract from that fd
    let tmp = dest_dir.join(".own-extract-tmp");
    {
        let mut src = File::open(cache_path).map_err(|e| format!("IO_ERROR: {e}"))?;
        #[cfg(unix)]
        let mut dst = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true) // never reopen an existing path (TOCTOU)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("IO_ERROR: {e}"))?
        };
        #[cfg(not(unix))]
        let mut dst = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("IO_ERROR: {e}"))?;
        let mut h = Sha512::new();
        let mut buf = [0u8; 65536];
        let mut total = 0u64;
        loop {
            let n = src.read(&mut buf).map_err(|e| format!("IO_ERROR: {e}"))?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > limits.max_tarball_size {
                let _ = fs::remove_file(&tmp);
                return Err(refused("max_tarball_size"));
            }
            h.update(&buf[..n]);
            std::io::Write::write_all(&mut dst, &buf[..n]).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        let expected = cache_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if hex != expected {
            let _ = fs::remove_file(&tmp);
            return Err(refused("cache_hash_mismatch"));
        }
    }
    let res = extract_from_file(&tmp, dest_dir, limits);
    let _ = fs::remove_file(&tmp);
    res
}

#[derive(Debug)]
pub struct ExtractStats {
    pub entries: usize,
    pub files: usize,
    pub total_unpacked: u64,
}

fn extract_from_file(
    tar_gz: &Path,
    dest_dir: &Path,
    limits: &SecurityLimits,
) -> ExtractResult<ExtractStats> {
    let f = File::open(tar_gz).map_err(|e| format!("IO_ERROR: {e}"))?;
    // count COMPRESSED bytes on the raw stream (before GzDecoder), so the
    // compression-ratio check compares decompressed vs compressed as intended.
    let compressed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counted = CompressedCounter {
        inner: f,
        counter: compressed.clone(),
    };
    let gz = GzDecoder::new(std::io::BufReader::new(counted));
    // Bound the entire decompressed stream, including extension headers and
    // padding after tar EOF, not only the file payloads counted in stats.
    let decompressed_cap = limits
        .max_unpacked_size
        .saturating_add((limits.max_entries as u64).saturating_mul(1536))
        .saturating_add(1024);
    let gz = CountingReader::new(
        gz,
        decompressed_cap,
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let mut archive = tar::Archive::new(gz);
    fs::create_dir_all(dest_dir).map_err(|e| format!("IO_ERROR: {e}"))?;

    let mut stats = ExtractStats {
        entries: 0,
        files: 0,
        total_unpacked: 0,
    };
    let mut prefix: Option<String> = None;
    let mut seen_paths: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_casefold: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in archive
        .entries()
        .map_err(|e| format!("PARSE_ERROR: tar: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("PARSE_ERROR: tar: {e}"))?;
        stats.entries += 1;
        if stats.entries > limits.max_entries {
            return Err(refused("max_entries"));
        }
        let header = entry.header();
        let entry_type = header.entry_type();
        // allowed: regular, dir, PAX headers (x/g), GNU longname (L/K)
        let is_meta =
            entry_type == tar::EntryType::GNULongName || entry_type == tar::EntryType::GNULongLink;
        let is_pax =
            entry_type == tar::EntryType::XHeader || entry_type == tar::EntryType::XGlobalHeader;
        if !(entry_type.is_file() || entry_type.is_dir() || is_pax || is_meta) {
            match entry_type {
                tar::EntryType::Symlink | tar::EntryType::Link => return Err(refused("symlink")),
                _ => return Err(refused("entry_type")),
            }
        }
        if is_pax || is_meta {
            // consume as metadata
            let mut sink = Vec::new();
            entry
                .read_to_end(&mut sink)
                .map_err(|e| format!("IO_ERROR: {e}"))?;
            continue;
        }
        let raw_path = entry.path().map_err(|e| format!("PARSE_ERROR: {e}"))?;
        // reject non-UTF-8 names instead of lossy-converting them (a lossy
        // name can collide with a different real name on disk)
        let raw = raw_path
            .to_str()
            .ok_or_else(|| refused("non_utf8_path"))?
            .to_string();
        if raw.contains('\\') {
            return Err(refused("backslash"));
        }
        let path_str = raw
            .strip_prefix("./")
            .unwrap_or(&raw)
            .trim_end_matches('/')
            .to_string();
        check_path(&path_str, limits)?;
        // prefix check
        let first = path_str.split('/').next().unwrap_or("");
        if first.is_empty() {
            return Err(refused("prefix_mismatch"));
        }
        match &prefix {
            None => prefix = Some(first.to_string()),
            Some(p) => {
                if *p != first {
                    return Err(refused("prefix_mismatch"));
                }
            }
        }
        let rel = path_str
            .strip_prefix(&format!("{}/", prefix.as_ref().unwrap()))
            .or_else(|| path_str.strip_prefix(prefix.as_ref().unwrap()))
            .unwrap_or("")
            .to_string();
        if rel.is_empty() {
            continue; // the prefix dir itself
        }
        // duplicates / case collisions
        if !seen_paths.insert(rel.clone()) {
            return Err(refused("duplicate_path"));
        }
        let folded: String = rel.nfc().flat_map(|c| c.to_lowercase()).collect();
        if !seen_casefold.insert(folded) {
            return Err(refused("case_collision"));
        }
        // git metadata / node_modules
        for comp in rel.split('/') {
            if comp == ".git"
                || comp == ".gitignore"
                || comp == ".gitattributes"
                || comp == ".gitmodules"
            {
                return Err(refused("git_metadata"));
            }
            if comp == "node_modules" {
                return Err(refused("node_modules"));
            }
        }
        if entry_type.is_dir() {
            continue; // dirs not materialized (§11.2)
        }
        // regular file
        let size = header.size().map_err(|e| format!("PARSE_ERROR: {e}"))?;
        if size > limits.max_file_size {
            return Err(refused("max_file_size"));
        }
        stats.total_unpacked += size;
        if stats.total_unpacked > limits.max_unpacked_size {
            return Err(refused("max_unpacked_size"));
        }
        // compression ratio: decompressed bytes so far vs COMPRESSED bytes read
        // so far (counter sits on the raw stream, before GzDecoder)
        let compressed = compressed.load(std::sync::atomic::Ordering::Relaxed).max(1);
        if stats.total_unpacked / compressed > limits.max_compression_ratio {
            return Err(refused("compression_ratio"));
        }
        let dest = dest_dir.join(&rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        let exec = header.mode().map_err(|e| format!("PARSE_ERROR: {e}"))? & 0o100 != 0;
        #[cfg(unix)]
        let mut out = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(if exec { 0o755 } else { 0o644 })
                .open(&dest)
                .map_err(|e| format!("IO_ERROR: {e}"))?
        };
        #[cfg(not(unix))]
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)
            .map_err(|e| format!("IO_ERROR: {e}"))?;
        let mut limited = entry.take(limits.max_file_size + 1);
        let written =
            std::io::copy(&mut limited, &mut out).map_err(|e| format!("IO_ERROR: {e}"))?;
        if written > limits.max_file_size {
            return Err(refused("max_file_size"));
        }
        stats.files += 1;
    }
    // drain the decompressed stream to EOF so the GzDecoder consumes the whole
    // member, then compare the compressed counter with the raw file size: any
    // unread compressed bytes mean trailing/multi-member data.
    {
        let mut remaining = archive.into_inner();
        let mut sink = [0u8; 65536];
        loop {
            match std::io::Read::read(&mut remaining, &mut sink) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(e) => return Err(format!("PARSE_ERROR: gzip: {e}")),
            }
        }
        let raw_size = fs::metadata(tar_gz)
            .map_err(|e| format!("IO_ERROR: {e}"))?
            .len();
        // Bufread GzDecoder leaves bytes after the member in its input buffer.
        // Counting raw read-ahead as consumed used to miss short trailing data.
        let buffered = remaining.inner.get_ref().buffer().len() as u64;
        let read = compressed
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_sub(buffered);
        if read < raw_size {
            return Err(refused("trailing_data"));
        }
    }
    Ok(stats)
}

/// Validate one archive path against §11.2 path rules.
fn check_path(p: &str, limits: &SecurityLimits) -> ExtractResult<()> {
    if p.starts_with('/') {
        return Err(refused("absolute_path"));
    }
    if p.len() > limits.max_path_bytes {
        return Err(refused("path_too_long"));
    }
    if !unicode_normalization::is_nfc(p) {
        return Err(refused("not_nfc"));
    }
    for comp in p.split('/') {
        if comp.is_empty() || comp == "." {
            return Err(refused("dot_component"));
        }
        if comp == ".." {
            return Err(refused("parent_component"));
        }
        if comp.len() > 255 {
            return Err(refused("path_too_long"));
        }
        // windows reserved
        let upper = comp.to_uppercase();
        let stem = upper.split('.').next().unwrap_or("");
        if matches!(stem, "CON" | "PRN" | "AUX" | "NUL")
            || (stem.starts_with("COM")
                && stem.len() == 4
                && stem[3..].chars().all(|c| c.is_ascii_digit()))
            || (stem.starts_with("LPT")
                && stem.len() == 4
                && stem[3..].chars().all(|c| c.is_ascii_digit()))
        {
            return Err(refused("windows_reserved"));
        }
        if comp.ends_with('.') || comp.ends_with(' ') {
            return Err(refused("windows_reserved"));
        }
        if comp
            .chars()
            .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        {
            return Err(refused("windows_reserved"));
        }
        for c in comp.chars() {
            let cp = c as u32;
            if cp <= 0x1f || cp == 0x7f {
                return Err(refused("control_char"));
            }
            if matches!(cp, 0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069) {
                return Err(refused("bidi_char"));
            }
            if matches!(cp, 0x200b..=0x200d | 0x2060 | 0xfeff) {
                return Err(refused("invisible_char"));
            }
        }
    }
    Ok(())
}

/// Reader wrapper that counts bytes read from `inner` and enforces a cap.
/// Kept for callers that need a hard byte cap on a decompressed stream.
struct CountingReader<R> {
    inner: R,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    cap: u64,
}

impl<R: Read> CountingReader<R> {
    fn new(inner: R, cap: u64, counter: std::sync::Arc<std::sync::atomic::AtomicU64>) -> Self {
        Self {
            inner,
            counter,
            cap,
        }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        let prev = self
            .counter
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        if prev.saturating_add(n as u64) > self.cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "max_decompressed_size exceeded",
            ));
        }
        Ok(n)
    }
}

/// Counting wrapper over a raw (still-compressed) reader: used between the
/// cache file and the GzDecoder so the counter measures compressed bytes.
struct CompressedCounter<R> {
    inner: R,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl<R: Read> Read for CompressedCounter<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.counter
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }
}
