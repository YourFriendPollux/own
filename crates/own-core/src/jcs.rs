//! JCS (RFC 8785) canonicalization, implemented internally per SPEC §12 / ADR 0003.
//!
//! Own digests use strings and integers, but this canonicalizer also supports
//! finite f64 values with ECMAScript notation for the RFC 8785 vectors.

use serde_json::Value;

/// Canonicalize a JSON value per RFC 8785.
/// Property names are sorted by UTF-16 code units (ascending, unsigned).
/// Strings are escaped per §3.2.2.2. Finite floats use ECMAScript notation;
/// non-finite numbers return an error.
pub fn canonicalize(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // RFC 8785 uses ECMAScript binary64 semantics for every number,
            // including integer JSON representations. Never emit an unchecked
            // arbitrary-precision literal that bypasses the finite-number rule.
            let number = n
                .as_f64()
                .ok_or("JCS: number is not representable as binary64")?;
            out.push_str(&es6_format_f64(number)?);
        }
        Value::String(s) => write_string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(&map[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Sort comparison per RFC 8785 §3.2.3: property names compared as arrays of
/// UTF-16 code units, unsigned, lexicographic; shorter precedes longer on prefix.
fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// ECMAScript Number::toString (ECMA-262 §7.1.12.1) for f64, as required by
/// RFC 8785 §3.2.2.3. Digits come from ryu (shortest round-trip, same reference
/// as the RFC); notation follows the ECMAScript rules (plain when -6 < n <= 21).
fn es6_format_f64(f: f64) -> Result<String, String> {
    if !f.is_finite() {
        return Err("JCS: NaN/Infinity not permitted".to_string());
    }
    if f == 0.0 {
        return Ok("0".to_string());
    }
    // ryu's Buffer::format gives the shortest round-trip decimal, in plain or
    // scientific style ("56.0", "333333333.3333333", "1e30", "0.002").
    let mut buf = ryu::Buffer::new();
    let sign = if f.is_sign_negative() { "-" } else { "" };
    let s = buf.format(f.abs());
    let (digits_raw, n) = match s.split_once(['e', 'E']) {
        Some((m, e)) => {
            let exp: i32 = e.parse().map_err(|_| "bad exponent")?;
            let d: String = m.chars().filter(|c| c.is_ascii_digit()).collect();
            (d, exp + 1)
        }
        None => {
            let frac = s.split_once('.').map(|(_, fr)| fr.len()).unwrap_or(0) as i32;
            let d: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
            let n = d.len() as i32 - frac;
            (d, n)
        }
    };
    // strip trailing zeros (n is unchanged)
    let mut digits = digits_raw;
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    let k = digits.len() as i32;
    if n <= -6 || n > 21 {
        let mantissa = if k == 1 {
            digits.clone()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        let e = n - 1;
        Ok(format!(
            "{}{}e{}{}",
            sign,
            mantissa,
            if e >= 0 { "+" } else { "-" },
            e.abs()
        ))
    } else if n > k {
        // integral value with trailing zeros: digits + (n-k) zeros, no decimal point
        Ok(format!(
            "{}{}{}",
            sign,
            digits,
            "0".repeat((n - k) as usize)
        ))
    } else if n == k {
        // integral value, exactly k digits
        Ok(format!("{sign}{digits}"))
    } else if n > 0 {
        Ok(format!(
            "{}{}.{}",
            sign,
            &digits[..n as usize],
            &digits[n as usize..]
        ))
    } else {
        Ok(format!("{}0.{}{}", sign, "0".repeat((-n) as usize), digits))
    }
}

/// String serialization per RFC 8785 §3.2.2.2.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) <= 0x1f => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn jcs_integers_follow_ecmascript_binary64_inv10() {
        for (input, expected) in [
            ("9007199254740993", "9007199254740992"),
            ("-9007199254740993", "-9007199254740992"),
            ("18446744073709551615", "18446744073709552000"),
        ] {
            let value: Value = serde_json::from_str(input).unwrap();
            assert_eq!(canonicalize(&value).unwrap(), expected);
        }
        if let Ok(value) = serde_json::from_str::<Value>("1e999") {
            assert!(canonicalize(&value).is_err());
        }
    }

    #[test]
    fn jcs_negative_floats_keep_sign_inv10() {
        for (input, expected) in [
            ("-1.5", "-1.5"),
            ("-0.002", "-0.002"),
            ("-1e-7", "-1e-7"),
            ("-1e-6", "-0.000001"),
            ("-1e21", "-1e+21"),
            ("-333333333.3333333", "-333333333.3333333"),
            ("-0.0", "0"),
            ("0.002", "0.002"),
        ] {
            let value: Value = serde_json::from_str(input).unwrap();
            assert_eq!(canonicalize(&value).unwrap(), expected, "{input}");
        }
        let negative = canonicalize(&serde_json::json!({"value": -1.5})).unwrap();
        let positive = canonicalize(&serde_json::json!({"value": 1.5})).unwrap();
        assert_ne!(
            crate::sha256_hex(negative.as_bytes()),
            crate::sha256_hex(positive.as_bytes())
        );
    }

    /// Official RFC 8785 reference vectors (cyberphone/json-canonicalization testdata).
    #[test]
    fn rfc8785_official_vectors_inv10() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors");
        for name in [
            "arrays",
            "french",
            "structures",
            "unicode",
            "values",
            "weird",
        ] {
            let input = fs::read_to_string(format!("{}/input/{}.json", dir, name)).unwrap();
            let expected = fs::read_to_string(format!("{}/output/{}.json", dir, name)).unwrap();
            let v: Value = serde_json::from_str(&input).unwrap();
            let got = canonicalize(&v).unwrap();
            assert_eq!(got, expected.trim_end(), "vector {}", name);
        }
    }

    /// Golden vector from SPEC §7.3: default license policy JCS.
    #[test]
    fn golden_license_policy_sha256_inv10() {
        use crate::sha256_hex;
        let policy = serde_json::json!({
            "allow": ["Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT"],
            "deny": ["AGPL-*", "BSL-*", "Elastic-2.0", "GPL-*", "PolyForm-*", "SSPL-*"],
            "review": ["LGPL-2.1-only", "LGPL-3.0-only", "MPL-2.0"],
            "unknown": "deny"
        });
        let canon = canonicalize(&policy).unwrap();
        assert_eq!(
            canon,
            "{\"allow\":[\"Apache-2.0\",\"BSD-2-Clause\",\"BSD-3-Clause\",\"ISC\",\"MIT\"],\"deny\":[\"AGPL-*\",\"BSL-*\",\"Elastic-2.0\",\"GPL-*\",\"PolyForm-*\",\"SSPL-*\"],\"review\":[\"LGPL-2.1-only\",\"LGPL-3.0-only\",\"MPL-2.0\"],\"unknown\":\"deny\"}"
        );
        assert_eq!(
            sha256_hex(canon.as_bytes()),
            "sha256:f23c02299b6304ae42886963d918e1a4b16cae83e70bc45efbd4102e50e5e2d1"
        );
    }

    /// Golden vector from SPEC §7.3: lock_digest of the empty lock.
    #[test]
    fn golden_empty_lock_digest_inv10() {
        use crate::sha256_hex;
        let obj = serde_json::json!({
            "decisions": [],
            "license_policy_sha256": "sha256:f23c02299b6304ae42886963d918e1a4b16cae83e70bc45efbd4102e50e5e2d1",
            "overrides": {},
            "packages": [],
            "schema_version": 1,
            "vendor_files_sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        });
        let canon = canonicalize(&obj).unwrap();
        assert_eq!(
            canon,
            "{\"decisions\":[],\"license_policy_sha256\":\"sha256:f23c02299b6304ae42886963d918e1a4b16cae83e70bc45efbd4102e50e5e2d1\",\"overrides\":{},\"packages\":[],\"schema_version\":1,\"vendor_files_sha256\":\"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}"
        );
        assert_eq!(
            sha256_hex(canon.as_bytes()),
            "sha256:cb21ba33540b37168a24bdaafd515c2c670908aed7867e35df97549b946f00af"
        );
    }
}
