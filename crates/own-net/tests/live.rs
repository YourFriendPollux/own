//! Live integration tests against registry.npmjs.org (SPEC §18 "Intégration").
//! Run with: cargo test -p own-net -- --ignored  (network required)

use own_net::{build_client, fetch_packument, fetch_tarball, verify_sri_integrity, NetConfig};

#[test]
#[ignore]
fn live_packument_zod_has_integrity() {
    let cfg = NetConfig::default();
    let client = build_client(&cfg).unwrap();
    let bytes = fetch_packument(&client, &cfg, "zod").unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let ver = v["dist-tags"]["latest"].as_str().unwrap().to_string();
    let integrity = v["versions"][&ver]["dist"]["integrity"]
        .as_str()
        .unwrap()
        .to_string();
    let tarball = v["versions"][&ver]["dist"]["tarball"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(integrity.starts_with("sha512-"));
    let dl = fetch_tarball(&client, &cfg, &tarball).unwrap();
    let sha512_hex = verify_sri_integrity(&integrity, &dl.bytes).unwrap();
    assert_eq!(sha512_hex, dl.sha512_hex);
}

#[test]
#[ignore]
fn live_404_is_version_not_found() {
    let cfg = NetConfig::default();
    let client = build_client(&cfg).unwrap();
    let e = fetch_packument(&client, &cfg, "own-definitely-not-a-real-pkg-zzz-12345").unwrap_err();
    assert_eq!(e, "VERSION_NOT_FOUND");
}

#[test]
#[ignore]
fn tarball_host_mismatch_rejected() {
    let cfg = NetConfig::default();
    let client = build_client(&cfg).unwrap();
    let e = fetch_tarball(&client, &cfg, "https://evil.example.com/x.tgz").unwrap_err();
    assert_eq!(e, "TARBALL_HOST_MISMATCH");
}
