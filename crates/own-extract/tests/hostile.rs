//! Hostile tarball corpus — one test per §11.2 rule (SPEC §18 "Hostile").

use own_extract::{extract, verify_cache_file, SecurityLimits};
use sha2::{Digest, Sha512};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn limits() -> SecurityLimits {
    SecurityLimits {
        max_tarball_size: 1024 * 1024,
        max_unpacked_size: 4 * 1024 * 1024,
        max_file_size: 1024 * 1024,
        max_entries: 100,
        max_compression_ratio: 100,
        max_path_bytes: 200,
    }
}

/// Build a gzipped tar in memory from (name, type, data) entries and write it
/// as a valid cache file `<sha512>.tgz` (mode 0444) inside `dir`.
fn write_cache(dir: &Path, entries: &[(&str, u8, &[u8])]) -> PathBuf {
    let raw = build_tar(entries);
    let gz = gzip(&raw);
    let hex: String = Sha512::digest(&gz)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let p = dir.join(format!("{hex}.tgz"));
    let mut f = File::create(&p).unwrap();
    f.write_all(&gz).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
    p
}

fn build_tar(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, etype, data) in entries {
        let mut h = [0u8; 512];
        let nb = name.as_bytes();
        h[..nb.len()].copy_from_slice(nb);
        // mode
        write_octal(&mut h[100..108], 0o644);
        write_octal(&mut h[108..116], 0);
        write_octal(&mut h[116..124], 0);
        write_octal(&mut h[124..136], data.len() as u64);
        write_octal(&mut h[136..148], 0);
        h[156] = *etype;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        // checksum: spaces then sum
        for b in &mut h[148..156] {
            *b = b' ';
        }
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        let cs = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(cs.as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

fn write_octal(field: &mut [u8], v: u64) {
    let s = format!("{v:0width$o}", width = field.len() - 1);
    field[..s.len()].copy_from_slice(s.as_bytes());
    field[field.len() - 1] = 0;
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn setup() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let cache = t.path().join("cache");
    let dest = t.path().join("dest");
    fs::create_dir_all(&cache).unwrap();
    fs::create_dir_all(&dest).unwrap();
    (t, cache)
}

const REG: u8 = b'0';
const DIR: u8 = b'5';
const SYMLINK: u8 = b'2';
const HARDLINK: u8 = b'1';

#[test]
fn rule_short_trailing_data_refused_inv3() {
    let (_t, cache) = setup();
    let mut bytes = gzip(&build_tar(&[("package/index.js", REG, b"ok")]));
    bytes.push(1);
    let hash = own_core::hex(Sha512::digest(&bytes));
    let path = cache.join(format!("{hash}.tgz"));
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    assert_eq!(
        extract(&path, &_t.path().join("dest"), &limits()).unwrap_err(),
        "EXTRACT_REFUSED:trailing_data"
    );
}

#[test]
fn rule_gzip_trailer_crc_refused_inv3() {
    let (_t, cache) = setup();
    let mut bytes = gzip(&build_tar(&[("package/index.js", REG, b"ok")]));
    let crc = bytes.len() - 8;
    bytes[crc] ^= 1;
    let hash = own_core::hex(Sha512::digest(&bytes));
    let path = cache.join(format!("{hash}.tgz"));
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(extract(&path, &_t.path().join("dest"), &limits()).is_err());
}

#[test]
fn rule_decompressed_padding_is_bounded_inv3() {
    let (_t, cache) = setup();
    let mut raw = build_tar(&[("package/index.js", REG, b"ok")]);
    raw.resize(8 * 1024 * 1024, 0);
    let bytes = gzip(&raw);
    let hash = own_core::hex(Sha512::digest(&bytes));
    let path = cache.join(format!("{hash}.tgz"));
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(extract(&path, &_t.path().join("dest"), &limits()).is_err());
}

#[test]
fn happy_path_extracts_files_stripping_prefix() {
    let (_t, cache) = setup();
    let dest = _t.path().join("dest");
    let c = write_cache(
        &cache,
        &[
            ("package/", DIR, &[]),
            ("package/index.js", REG, b"x=1\n"),
            ("package/LICENSE", REG, b"MIT\n"),
        ],
    );
    let st = extract(&c, &dest, &limits()).unwrap();
    assert_eq!(st.files, 2);
    assert_eq!(fs::read_to_string(dest.join("index.js")).unwrap(), "x=1\n");
    assert_eq!(fs::read_to_string(dest.join("LICENSE")).unwrap(), "MIT\n");
}

#[test]
fn rule_symlink_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[
            ("package/", DIR, &[]),
            ("package/evil", SYMLINK, b"/etc/passwd"),
        ],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:symlink");
}

#[test]
fn rule_hardlink_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[
            ("package/", DIR, &[]),
            ("package/a", HARDLINK, b"package/b"),
        ],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:symlink"); // hardlink maps to Link -> symlink rule per table
}

#[test]
fn rule_prefix_mismatch_refused() {
    let (t, cache) = setup();
    let c = write_cache(&cache, &[("package/", DIR, &[]), ("other/x", REG, b"1")]);
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:prefix_mismatch");
}

#[test]
fn rule_absolute_path_refused() {
    let (t, cache) = setup();
    // entry named with a leading slash
    let c = write_cache(&cache, &[("package/", DIR, &[]), ("/etc/evil", REG, b"1")]);
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert!(e.starts_with("EXTRACT_REFUSED:"), "got {e}");
}

#[test]
fn rule_parent_component_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[("package/", DIR, &[]), ("package/../evil", REG, b"1")],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:parent_component");
}

#[test]
fn rule_backslash_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[("package/", DIR, &[]), ("package/a\\b", REG, b"1")],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:backslash");
}

#[test]
fn rule_duplicate_path_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[
            ("package/", DIR, &[]),
            ("package/a", REG, b"1"),
            ("package/a", REG, b"2"),
        ],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:duplicate_path");
}

#[test]
fn rule_case_collision_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[
            ("package/", DIR, &[]),
            ("package/Readme", REG, b"1"),
            ("package/readme", REG, b"2"),
        ],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:case_collision");
}

#[test]
fn rule_windows_reserved_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[("package/", DIR, &[]), ("package/CON", REG, b"1")],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:windows_reserved");
}

#[test]
fn rule_control_char_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[("package/", DIR, &[]), ("package/a\x07b", REG, b"1")],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:control_char");
}

#[test]
fn rule_bidi_char_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[("package/", DIR, &[]), ("package/a\u{202e}b", REG, b"1")],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:bidi_char");
}

#[test]
fn rule_git_metadata_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[("package/", DIR, &[]), ("package/.gitignore", REG, b"*")],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:git_metadata");
}

#[test]
fn rule_node_modules_refused() {
    let (t, cache) = setup();
    let c = write_cache(
        &cache,
        &[
            ("package/", DIR, &[]),
            ("package/node_modules/x", REG, b"1"),
        ],
    );
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:node_modules");
}

#[test]
fn rule_max_entries_refused() {
    let (t, cache) = setup();
    let mut l = limits();
    l.max_entries = 50;
    let mut entries: Vec<(String, u8, Vec<u8>)> = vec![("package/".into(), DIR, vec![])];
    for i in 0..60 {
        entries.push((format!("package/f{i}"), REG, vec![b'x']));
    }
    let refs: Vec<(&str, u8, &[u8])> = entries
        .iter()
        .map(|(n, t, d)| (n.as_str(), *t, d.as_slice()))
        .collect();
    let c = write_cache(&cache, &refs);
    let e = extract(&c, &t.path().join("dest"), &l).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:max_entries");
}

#[test]
fn rule_path_too_long_refused() {
    let (t, cache) = setup();
    let mut l = limits();
    l.max_path_bytes = 50; // classic tar name field is 100 bytes; keep the entry under it
    let long = "package/".to_string() + &"a".repeat(60); // 68 bytes > 50
    let c = write_cache(
        &cache,
        &[("package/", DIR, &[]), (long.as_str(), REG, b"1")],
    );
    let e = extract(&c, &t.path().join("dest"), &l).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:path_too_long");
}

#[test]
fn rule_not_nfc_refused() {
    let (t, cache) = setup();
    // e + combining acute (NFD)
    let nfd = "package/cafe\u{0301}";
    let c = write_cache(&cache, &[("package/", DIR, &[]), (nfd, REG, b"1")]);
    let e = extract(&c, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:not_nfc");
}

#[test]
fn cache_file_must_be_0444_and_hash_named() {
    let (t, _cache) = setup();
    let p = t.path().join("deadbeef.tgz");
    fs::write(&p, b"not a tar").unwrap();
    assert!(verify_cache_file(&p).is_err());
    let p2 = t.path().join("nothex.tgz");
    fs::write(&p2, b"x").unwrap();
    fs::set_permissions(&p2, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(verify_cache_file(&p2).is_err());
}

#[test]
fn rule_max_file_size_refused() {
    let (t, cache) = setup();
    let mut l = limits();
    l.max_file_size = 10; // header claims 100 bytes
    let c = write_cache(
        &cache,
        &[("package/", DIR, &[]), ("package/big", REG, &[b'x'; 100])],
    );
    let e = extract(&c, &t.path().join("dest"), &l).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:max_file_size");
}

#[test]
fn rule_max_unpacked_size_refused() {
    let (t, cache) = setup();
    let mut l = limits();
    l.max_unpacked_size = 50;
    l.max_file_size = 1024 * 1024;
    let c = write_cache(
        &cache,
        &[
            ("package/", DIR, &[]),
            ("package/a", REG, &[b'x'; 40]),
            ("package/b", REG, &[b'y'; 40]),
        ],
    );
    let e = extract(&c, &t.path().join("dest"), &l).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:max_unpacked_size");
}

#[test]
fn rule_compression_ratio_refused() {
    let (t, cache) = setup();
    let mut l = limits();
    l.max_compression_ratio = 5;
    // highly compressible payload: 1000 'x' compress to a few bytes
    let c = write_cache(
        &cache,
        &[
            ("package/", DIR, &[]),
            ("package/zeros", REG, &[b'x'; 1000]),
        ],
    );
    let e = extract(&c, &t.path().join("dest"), &l).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:compression_ratio");
}

#[test]
fn rule_trailing_data_refused() {
    // multi-member gzip: concatenate two valid gzip members. The extractor
    // must refuse: the second member's entries would otherwise be silently
    // merged into the first archive's namespace.
    let (t, cache) = setup();
    let raw1 = build_tar(&[("package/", DIR, &[]), ("package/index.js", REG, b"x=1\n")]);
    let raw2 = build_tar(&[("package/", DIR, &[]), ("package/evil.js", REG, b"e=1\n")]);
    let mut gz = gzip(&raw1);
    gz.extend_from_slice(&gzip(&raw2));
    let hex: String = Sha512::digest(&gz)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let p = cache.join(format!("{hex}.tgz"));
    fs::write(&p, &gz).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
    // Either the second member is refused as trailing data, or its duplicate
    // prefix/path collides — but it must NOT be silently extracted.
    let r = extract(&p, &t.path().join("dest"), &limits());
    match r {
        Err(e) => assert!(
            e.starts_with("EXTRACT_REFUSED:"),
            "expected refusal, got {e}"
        ),
        Ok(st) => {
            // if it succeeded, the second member must not have added files
            assert!(st.files <= 1, "multi-member gzip silently merged: {st:?}");
        }
    }
}

#[test]
fn rule_non_utf8_path_refused() {
    let (t, cache) = setup();
    // entry whose name contains an invalid UTF-8 byte (0xff)
    let mut h = [0u8; 512];
    let name_bytes: &[u8] = b"package/bad\xffname";
    h[..name_bytes.len()].copy_from_slice(name_bytes);
    write_octal(&mut h[100..108], 0o644);
    write_octal(&mut h[124..136], 1);
    h[156] = REG;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    let cs = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(cs.as_bytes());
    let mut raw = build_tar(&[("package/", DIR, &[])]);
    raw.truncate(raw.len() - 1024); // drop the two end blocks
    raw.extend_from_slice(&h);
    raw.extend_from_slice(b"x");
    raw.extend(std::iter::repeat_n(0u8, 511));
    raw.extend(std::iter::repeat_n(0u8, 1024));
    let gz = gzip(&raw);
    let hex: String = Sha512::digest(&gz)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let p = cache.join(format!("{hex}.tgz"));
    fs::write(&p, &gz).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
    let e = extract(&p, &t.path().join("dest"), &limits()).unwrap_err();
    assert_eq!(e, "EXTRACT_REFUSED:non_utf8_path");
}
