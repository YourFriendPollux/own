#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let pol = own_policy::license::LicensePolicy::default();
        let _ = own_policy::license::evaluate_expression(s, &pol);
    }
});
