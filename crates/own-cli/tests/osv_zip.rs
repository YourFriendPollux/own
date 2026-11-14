//! Exercise the ZIP reader used by OSV after dependency upgrades, offline.
use std::io::{Cursor, Read, Write};

#[test]
fn inv11_osv_zip_entries_are_read_in_memory_for_stored_and_deflate() {
    let advisory = br#"{"id":"SYNTHETIC-1","affected":[{"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]}]}"#;
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "SYNTHETIC-1.json",
                zip::write::SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
        writer.write_all(advisory).unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
        assert_eq!(archive.len(), 1);
        let mut entry = archive.by_index(0).unwrap();
        assert!(entry.size() < 5 * 1_048_576);
        let mut text = String::new();
        entry.read_to_string(&mut text).unwrap();
        assert_eq!(text.as_bytes(), advisory);
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["id"], "SYNTHETIC-1");
        assert_eq!(doc["affected"][0]["package"]["ecosystem"], "npm");
    }
}
