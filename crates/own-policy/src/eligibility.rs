//! Eligibility (SPEC §9.1) evaluated from a packument `versions[<ver>]` object.
//!
//! Each criterion maps to its `NOT_ELIGIBLE:<code>`.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Eligibility {
    pub eligible: bool,
    pub blocking: Option<&'static str>, // criterion code from §9.1
    pub warnings: Vec<&'static str>, // W_DEPRECATED, W_TYPES_PRESENT, W_WASM (wasm is extract-time)
    pub license_expression: Option<String>,
    pub unpacked_size: Option<u64>,
    pub has_bin: bool,
    pub install_scripts: Vec<String>,
}

const INSTALL_SCRIPTS: [&str; 4] = ["preinstall", "install", "postinstall", "prepare"];

pub fn evaluate(
    version_obj: &Value,
    vendored: &[(String, String)],
    max_unpacked: u64,
) -> Eligibility {
    let mut w = Vec::new();
    // A present but unreadable constraint is not an absent constraint. Keep
    // the existing refusal codes so callers do not need a new error contract.
    let invalid = |code| Eligibility {
        eligible: false,
        blocking: Some(code),
        warnings: vec![],
        license_expression: None,
        unpacked_size: None,
        has_bin: false,
        install_scripts: vec![],
    };
    for (field, code) in [
        ("dependencies", "dependencies"),
        ("peerDependencies", "peer_dependencies"),
        ("optionalDependencies", "optional_dependencies"),
        ("scripts", "install_scripts"),
    ] {
        if let Some(value) = version_obj.get(field) {
            if !value
                .as_object()
                .is_some_and(|map| map.values().all(Value::is_string))
            {
                return invalid(code);
            }
        }
    }
    if version_obj.get("gypfile").is_some_and(|v| !v.is_boolean()) {
        return invalid("binding_gyp");
    }
    if version_obj
        .get("directories")
        .is_some_and(|v| !v.is_object())
    {
        return invalid("bin");
    }
    // dependencies: empty or only vendored packages whose version satisfies the range
    if let Some(deps) = version_obj.get("dependencies").and_then(|d| d.as_object()) {
        for (name, range) in deps {
            let range = range.as_str().unwrap_or("");
            let ok = vendored
                .iter()
                .any(|(n, v)| n == name && crate::semver::satisfies(v, range));
            if !ok {
                return Eligibility {
                    eligible: false,
                    blocking: Some("dependencies"),
                    warnings: w,
                    license_expression: None,
                    unpacked_size: None,
                    has_bin: false,
                    install_scripts: vec![],
                };
            }
        }
    }
    if let Some(peers) = version_obj
        .get("peerDependencies")
        .and_then(|d| d.as_object())
    {
        for (name, range) in peers {
            let range = range.as_str().unwrap_or("");
            let ok = vendored
                .iter()
                .any(|(n, v)| n == name && crate::semver::satisfies(v, range));
            if !ok {
                return Eligibility {
                    eligible: false,
                    blocking: Some("peer_dependencies"),
                    warnings: w,
                    license_expression: None,
                    unpacked_size: None,
                    has_bin: false,
                    install_scripts: vec![],
                };
            }
        }
    }
    if version_obj
        .get("optionalDependencies")
        .and_then(|d| d.as_object())
        .map(|o| !o.is_empty())
        .unwrap_or(false)
    {
        return Eligibility {
            eligible: false,
            blocking: Some("optional_dependencies"),
            warnings: w,
            license_expression: None,
            unpacked_size: None,
            has_bin: false,
            install_scripts: vec![],
        };
    }
    for b in ["bundledDependencies", "bundleDependencies"]
        .iter()
        .filter_map(|field| version_obj.get(*field))
    {
        let empty = b.as_array().map(|a| a.is_empty()).unwrap_or(false);
        if !empty {
            return Eligibility {
                eligible: false,
                blocking: Some("bundled_dependencies"),
                warnings: w,
                license_expression: None,
                unpacked_size: None,
                has_bin: false,
                install_scripts: vec![],
            };
        }
    }
    let mut install_scripts = Vec::new();
    if let Some(scripts) = version_obj.get("scripts").and_then(|s| s.as_object()) {
        for k in scripts.keys() {
            if INSTALL_SCRIPTS.contains(&k.as_str()) {
                install_scripts.push(k.clone());
            }
        }
    }
    // §9.1: only preinstall/install/postinstall/prepare are install scripts.
    // A `prepare` script present in the *packument* of a published package is a
    // development-time script (it ran at publish time, not at install time for
    // consumers); the real danger is binding.gyp / native builds, checked below,
    // and the tarball content (binding.gyp anywhere) checked at extraction.
    let dangerous_scripts: Vec<&String> = install_scripts
        .iter()
        .filter(|s| !(*s == "prepare"))
        .collect();
    let has_dangerous = !dangerous_scripts.is_empty();
    if has_dangerous
        || version_obj
            .get("gypfile")
            .and_then(|g| g.as_bool())
            .unwrap_or(false)
    {
        return Eligibility {
            eligible: false,
            blocking: Some(
                if version_obj
                    .get("gypfile")
                    .and_then(|g| g.as_bool())
                    .unwrap_or(false)
                {
                    "binding_gyp"
                } else {
                    "install_scripts"
                },
            ),
            warnings: w,
            license_expression: None,
            unpacked_size: None,
            has_bin: false,
            install_scripts,
        };
    }
    let has_bin = version_obj.get("bin").is_some()
        || version_obj
            .get("directories")
            .and_then(|d| d.get("bin"))
            .is_some();
    if has_bin {
        return Eligibility {
            eligible: false,
            blocking: Some("bin"),
            warnings: w,
            license_expression: None,
            unpacked_size: None,
            has_bin,
            install_scripts,
        };
    }
    if version_obj.get("os").is_some()
        || version_obj.get("cpu").is_some()
        || version_obj.get("libc").is_some()
    {
        return Eligibility {
            eligible: false,
            blocking: Some("os_cpu"),
            warnings: w,
            license_expression: None,
            unpacked_size: None,
            has_bin,
            install_scripts,
        };
    }
    let integrity = version_obj
        .pointer("/dist/integrity")
        .and_then(|i| i.as_str())
        .unwrap_or("");
    if !integrity.contains("sha512-") {
        return Eligibility {
            eligible: false,
            blocking: Some("integrity_missing"),
            warnings: w,
            license_expression: None,
            unpacked_size: None,
            has_bin,
            install_scripts,
        };
    }
    let ver = version_obj
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !crate::semver::is_valid_version(ver) || ver.contains('+') {
        return Eligibility {
            eligible: false,
            blocking: Some("version_format"),
            warnings: w,
            license_expression: None,
            unpacked_size: None,
            has_bin,
            install_scripts,
        };
    }
    let unpacked_size = version_obj
        .pointer("/dist/unpackedSize")
        .and_then(|u| u.as_u64());
    if let Some(sz) = unpacked_size {
        if sz > max_unpacked {
            return Eligibility {
                eligible: false,
                blocking: Some("size"),
                warnings: w,
                license_expression: None,
                unpacked_size,
                has_bin,
                install_scripts,
            };
        }
    }
    if version_obj
        .get("deprecated")
        .and_then(|d| d.as_str())
        .is_some()
    {
        w.push("W_DEPRECATED");
    }
    // types warning
    let has_types = version_obj.get("types").is_some()
        || version_obj.get("typings").is_some()
        || version_obj
            .get("exports")
            .map(|e| e.to_string().contains("types"))
            .unwrap_or(false);
    if has_types {
        w.push("W_TYPES_PRESENT");
    }
    let license_expression = version_obj
        .get("license")
        .and_then(|l| l.as_str())
        .map(|s| s.to_string())
        .or_else(|| normalize_legacy_licenses(version_obj.get("licenses")));
    Eligibility {
        eligible: true,
        blocking: None,
        warnings: w,
        license_expression,
        unpacked_size,
        has_bin,
        install_scripts,
    }
}

fn normalize_legacy_licenses(v: Option<&Value>) -> Option<String> {
    let arr = v?.as_array()?;
    let parts: Vec<String> = arr
        .iter()
        .filter_map(|e| {
            if let Some(t) = e.get("type").and_then(|t| t.as_str()) {
                Some(t.to_string())
            } else {
                e.as_str().map(|s| s.to_string())
            }
        })
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" OR "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn package() -> Value {
        json!({"version": "1.0.0", "license": "MIT", "dist": {"integrity": "sha512-AAAA"}})
    }

    #[test]
    fn eligibility_rejects_unreadable_constraint_types() {
        let vendored = vec![("runtime".into(), "1.2.5".into())];
        for (field, code, bad) in [
            ("dependencies", "dependencies", json!(["runtime"])),
            ("dependencies", "dependencies", json!({"runtime": 123})),
            ("dependencies", "dependencies", Value::Null),
            ("peerDependencies", "peer_dependencies", json!(["runtime"])),
            (
                "peerDependencies",
                "peer_dependencies",
                json!({"runtime": false}),
            ),
            ("optionalDependencies", "optional_dependencies", json!([])),
            ("scripts", "install_scripts", json!(["postinstall"])),
            ("scripts", "install_scripts", json!({"prepare": []})),
            ("scripts", "install_scripts", Value::Null),
            ("gypfile", "binding_gyp", json!("false")),
            ("directories", "bin", json!(["bin"])),
        ] {
            let mut value = package();
            value[field] = bad;
            let result = evaluate(&value, &vendored, u64::MAX);
            assert!(!result.eligible, "{field}: {value}");
            assert_eq!(result.blocking, Some(code), "{field}: {value}");
        }
        let mut value = package();
        value["bundledDependencies"] = json!([]);
        value["bundleDependencies"] = json!(["runtime"]);
        assert_eq!(
            evaluate(&value, &vendored, u64::MAX).blocking,
            Some("bundled_dependencies")
        );
    }

    #[test]
    fn eligibility_keeps_valid_absent_and_empty_constraints() {
        assert!(evaluate(&package(), &[], u64::MAX).eligible);
        let mut value = package();
        for field in [
            "dependencies",
            "peerDependencies",
            "optionalDependencies",
            "scripts",
            "directories",
        ] {
            value[field] = json!({});
        }
        value["bundledDependencies"] = json!([]);
        value["bundleDependencies"] = json!([]);
        value["gypfile"] = json!(false);
        assert!(evaluate(&value, &[], u64::MAX).eligible);
        value["dependencies"] = json!({"runtime": "^1.0.0"});
        value["peerDependencies"] = json!({"runtime": ">=1.0.0 <2.0.0"});
        value["scripts"] = json!({"prepare": "build", "test": "test"});
        let result = evaluate(&value, &[("runtime".into(), "1.2.5".into())], u64::MAX);
        assert!(result.eligible);
        assert_eq!(result.install_scripts, ["prepare"]);
        value["scripts"]["postinstall"] = json!("build");
        assert_eq!(
            evaluate(&value, &[("runtime".into(), "1.2.5".into())], u64::MAX).blocking,
            Some("install_scripts")
        );
    }
}
