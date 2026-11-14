//! HTTPS OSV transport regression, opt-in like the registry integration tests.
use own_net::fetch_osv_dump;
use reqwest::blocking::Client;
use std::time::Duration;

#[test]
#[ignore = "requires the public HTTPS OSV mirror; downloads only four range bytes"]
fn real_osv_transport_preserves_last_modified_header_inv10() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::RANGE, "bytes=0-3".parse().unwrap());
    let client = Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let response = fetch_osv_dump(
        &client,
        "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
        1,
    )
    .unwrap();
    let response = serde_json::to_value(response).unwrap();
    let modified = response
        .get("last_modified")
        .and_then(serde_json::Value::as_str);
    assert!(
        modified.is_some(),
        "OSV response lost its Last-Modified metadata: {response}"
    );
    assert!(modified.unwrap().ends_with(" GMT"));
    assert_eq!(response["bytes"], serde_json::json!(b"PK\x03\x04"));
}
