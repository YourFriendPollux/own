pub mod canonical;
pub mod config;
pub mod jcs;
pub mod lock;
pub mod path_safety;
pub mod toml_write;
pub mod txn;
pub mod verify;

use sha2::{Digest, Sha256};

/// Compute the `package_files_sha256` of §7.3: for each file sorted by UTF-8 path,
/// hash the line `"<sha256hex> <size> <x|-> <path>\n"`.
pub fn package_files_sha256(files: &[(String, String, u64, bool)]) -> String {
    let mut h = Sha256::new();
    let mut sorted: Vec<_> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, sha256hex, size, exec) in sorted {
        let flag = if *exec { "x" } else { "-" };
        h.update(format!("{} {} {} {}\n", sha256hex, size, flag, path));
    }
    format!("sha256:{}", hex(h.finalize()))
}

/// Compute the `vendor_files_sha256` of §7.3: hash lines
/// `"<package_files_sha256 hex> <dir>\n"` sorted by dir. Empty lock = sha256 of empty input.
pub fn vendor_files_sha256(entries: &[(String, String)]) -> String {
    let mut h = Sha256::new();
    let mut sorted: Vec<_> = entries.iter().collect();
    sorted.sort_by(|a, b| a.1.cmp(&b.1));
    for (pkg_hash_hex, dir) in sorted {
        h.update(format!("{} {}\n", pkg_hash_hex, dir));
    }
    format!("sha256:{}", hex(h.finalize()))
}

pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    format!("sha256:{}", hex(Sha256::digest(data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector from SPEC §7.3.
    #[test]
    fn golden_package_files_sha256_inv10() {
        // LICENSE = "MIT License\n" (12 bytes), dist/index.js = "module.exports=1\n" (17 bytes, exec),
        // package.json = "{\"name\":\"a\",\"version\":\"1.0.0\"}\n" (31 bytes)
        let files = vec![
            (
                "LICENSE".to_string(),
                sha256_hex(b"MIT License\n")
                    .trim_start_matches("sha256:")
                    .to_string(),
                12,
                false,
            ),
            (
                "dist/index.js".to_string(),
                sha256_hex(b"module.exports=1\n")
                    .trim_start_matches("sha256:")
                    .to_string(),
                17,
                true,
            ),
            (
                "package.json".to_string(),
                sha256_hex(b"{\"name\":\"a\",\"version\":\"1.0.0\"}\n")
                    .trim_start_matches("sha256:")
                    .to_string(),
                31,
                false,
            ),
        ];
        assert_eq!(
            package_files_sha256(&files),
            "sha256:c547a7b9f354991f74a7d6c98e3c425b6ec9dc93f354f5d1d0c2d0880cc2ee64"
        );
    }

    #[test]
    fn golden_vendor_files_sha256_inv10() {
        let pkg = "c547a7b9f354991f74a7d6c98e3c425b6ec9dc93f354f5d1d0c2d0880cc2ee64";
        assert_eq!(
            vendor_files_sha256(&[(pkg.to_string(), "vendor/own/a@1.0.0".to_string())]),
            "sha256:3cc749fc6e40aafd505af5215487649de5b5a513bed835c5e104e0bce48d428d"
        );
        // Empty lock
        assert_eq!(
            vendor_files_sha256(&[]),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
