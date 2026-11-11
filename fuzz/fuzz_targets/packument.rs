#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            if let Some(ver) = v.get("versions").and_then(|vs| vs.as_object()).and_then(|m| m.values().next()) {
                let _ = own_policy::eligibility::evaluate(ver, &[], 500 * 1_048_576);
            }
        }
    }
});
