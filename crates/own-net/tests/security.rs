//! Network policy and literal SRI validation must fail before a request.
use own_net::{build_client, verify_sri_integrity, NetConfig};

#[test]
fn tarball_cannot_cross_the_registry_port_before_network_inv4() {
    let config = NetConfig {
        connect_timeout_s: 1,
        read_timeout_s: 1,
        max_retries: 0,
        ..NetConfig::default()
    };
    let client = build_client(&config).unwrap();
    let error = own_net::fetch_tarball(
        &client,
        &config,
        "https://registry.npmjs.org:4444/package.tgz",
    )
    .unwrap_err();
    assert!(error.starts_with("TARBALL_HOST_MISMATCH"), "{error}");
}

#[test]
fn registry_requires_https_and_no_credentials_inv4() {
    for registry in [
        "http://registry.npmjs.org",
        "https://user:password@registry.npmjs.org",
        "https://registry.npmjs.org/#fragment",
    ] {
        let config = NetConfig {
            registry_url: registry.into(),
            ..NetConfig::default()
        };
        assert!(
            build_client(&config).is_err(),
            "accepted registry: {registry}"
        );
    }
}

#[test]
fn sri_does_not_ignore_trailing_data_inv2() {
    // SHA-512 of the empty byte string, independently fixed test vector.
    let sri = "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==";
    assert!(verify_sri_integrity(sri, b"").is_ok());
    for invalid in [
        format!("{sri}garbage"),
        sri.replace("==", "="),
        sri.replace("==", "==="),
    ] {
        assert!(
            verify_sri_integrity(&invalid, b"").is_err(),
            "accepted {invalid}"
        );
    }
}
