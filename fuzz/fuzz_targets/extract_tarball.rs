#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    // write to a temp cache-named file (sha512 of data), then extract
    let dir = std::env::temp_dir().join(format!("own-fuzz-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    use sha2::{Digest, Sha512};
    let hex: String = Sha512::digest(data).iter().map(|b| format!("{b:02x}")).collect();
    let cache = dir.join(format!("{hex}.tgz"));
    {
        let mut f = std::fs::File::create(&cache).unwrap();
        f.write_all(data).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o444)).unwrap();
    }
    let dest = dir.join("dest");
    let _ = std::fs::create_dir_all(&dest);
    let limits = own_extract::SecurityLimits {
        max_tarball_size: 1024 * 1024,
        max_unpacked_size: 4 * 1024 * 1024,
        max_file_size: 1024 * 1024,
        max_entries: 500,
        max_compression_ratio: 1000,
        max_path_bytes: 200,
    };
    // must never panic; refusals are Ok(Err)
    let _ = own_extract::extract(&cache, &dest, &limits);
    let _ = std::fs::remove_dir_all(&dest);
    let _ = std::fs::remove_file(&cache);
});
