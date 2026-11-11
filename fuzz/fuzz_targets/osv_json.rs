#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            if let Some(affected) = v.get("affected").and_then(|a| a.as_array()) {
                for a in affected {
                    if let Some(ranges) = a.get("ranges").and_then(|r| r.as_array()) {
                        for r in ranges {
                            if let Some(events) = r.get("events").and_then(|e| e.as_array()) {
                                let evs: Vec<(String, String)> = events
                                    .iter()
                                    .filter_map(|e| {
                                        let obj = e.as_object()?;
                                        let (k, val) = obj.iter().next()?;
                                        Some((k.clone(), val.as_str()?.to_string()))
                                    })
                                    .collect();
                                if let Some(ver) = a.pointer("/package/version").and_then(|x| x.as_str()) {
                                    let _ = own_policy::semver::in_osv_range(ver, &evs);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
});
