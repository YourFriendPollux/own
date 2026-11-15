use own_policy::pnpm_lock::parse_pnpm_lock;

const LOCK: &str = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      zod:\n        specifier: ^3.22.0\n        version: 3.22.4\npackages: {}\n";

#[test]
fn unsupported_graph_spacing_or_depth_is_refused_not_silently_lost() {
    for text in [
        LOCK.replace("importers:", "importers :"),
        LOCK.replace("dependencies:", "dependencies :"),
        LOCK.replace("    dependencies:", "      dependencies:")
            .replace("      zod:", "        zod:")
            .replace("        specifier:", "          specifier:")
            .replace("        version:", "          version:"),
    ] {
        let error = parse_pnpm_lock(&text).expect_err("unreadable graph must not be empty success");
        assert!(error.starts_with("PNPM_UNSUPPORTED:"), "{error}");
    }
    assert_eq!(
        parse_pnpm_lock(LOCK).unwrap().resolved_versions("zod"),
        ["3.22.4"]
    );
}

#[test]
fn inline_comments_do_not_change_dependency_identity() {
    let text = LOCK
        .replace("specifier: ^3.22.0", "specifier: ^3.22.0 # note: upstream")
        .replace("version: 3.22.4", "version: 3.22.4 # note");
    let lock = parse_pnpm_lock(&text).unwrap();
    assert_eq!(
        lock.importers[0].deps[0],
        ("zod".into(), "^3.22.0".into(), "3.22.4".into())
    );
    assert_eq!(lock.registry_dependents("zod", "3.22.4"), ["importer:."]);
}

#[test]
fn quoted_yaml_scalars_preserve_decoded_graph_identities() {
    let text = LOCK
        .replace("  .:", "  'packages/it''s':")
        .replace("      zod:", r#"      "zo\u0064":"#)
        .replace("specifier: ^3.22.0", r#"specifier: "\u005e3.22.0""#)
        .replace("version: 3.22.4", r#"version: "3.22.\u0034""#)
        + r#"snapshots:
  "zo\u0064@3.22.4":
    dependencies:
      "foo\u0064": "1.0.\u0030"
overrides:
  'npm:zod@^3.22.0': 'file:vendor/own/zod@3.22.4'
"#;
    let lock = parse_pnpm_lock(&text).unwrap();
    assert_eq!(
        lock.registry_dependents("zod", "3.22.4"),
        ["importer:packages/it's"]
    );
    assert_eq!(
        lock.importers[0].deps[0],
        ("zod".into(), "^3.22.0".into(), "3.22.4".into())
    );
    assert_eq!(lock.packages[0].key, "zod@3.22.4");
    assert_eq!(lock.packages[0].deps[0], ("food".into(), "1.0.0".into()));
    assert_eq!(
        lock.overrides[0],
        (
            "npm:zod@^3.22.0".into(),
            "file:vendor/own/zod@3.22.4".into()
        )
    );
}

#[test]
fn duplicate_graph_mapping_keys_are_refused_in_each_scope() {
    let edge = "      zod:\n        specifier: ^3.22.0\n        version: 3.22.4\n";
    for text in [
        LOCK.replace(edge, &format!("{edge}{edge}")),
        LOCK.replace(
            edge,
            &format!("{edge}{}", edge.replace("zod:", r#""zo\u0064":"#)),
        ),
        LOCK.replace("packages: {}", "  .: {}\npackages: {}"),
        LOCK.replace("packages: {}", "packages: {}\npackages: {}"),
        LOCK.replace(
            "lockfileVersion: '9.0'",
            "lockfileVersion: '9.0'\nlockfileVersion: '9.0'",
        ),
        LOCK.replace(
            "packages: {}",
            &format!("    dependencies:\n{edge}packages: {{}}"),
        ),
        LOCK.to_owned() + "snapshots:\n  zod@3.22.4: {}\n  zod@3.22.4: {}\n",
        LOCK.to_owned()
            + "snapshots:\n  zod@3.22.4:\n    dependencies:\n      a: 1.0.0\n      a: 2.0.0\n",
        LOCK.to_owned() + "overrides:\n  zod: ^3\n  zod: ^4\n",
    ] {
        assert!(
            parse_pnpm_lock(&text).is_err(),
            "ambiguous mapping accepted:\n{text}"
        );
    }
    let valid = LOCK.to_owned() + "snapshots:\n  zod@3.22.4:\n    dependencies:\n      a: 1.0.0\n    optionalDependencies:\n      a: 1.0.0\n";
    assert_eq!(parse_pnpm_lock(&valid).unwrap().packages[0].deps.len(), 2);
}

#[test]
fn graph_before_schema_header_is_not_discarded() {
    let reordered = LOCK.replace("lockfileVersion: '9.0'\n", "") + "lockfileVersion: '9.0'\n";
    assert_eq!(
        parse_pnpm_lock(&reordered).unwrap(),
        parse_pnpm_lock(LOCK).unwrap()
    );
}

#[test]
fn unreadable_nested_mappings_do_not_disappear() {
    for text in [
        LOCK.to_owned() + "snapshots:\n  zod@3.22.4:\n    dependencies:\n      \"a: 1.0.0\n",
        LOCK.to_owned() + "overrides:\n  \"npm:zod: ^3\n",
        LOCK.replace("packages: {}", "        version:3.22.4\npackages: {}"),
        LOCK.replace(
            "packages: {}",
            "    optionalDependencies:\n        specifier: ^1\npackages: {}",
        ),
    ] {
        assert!(
            parse_pnpm_lock(&text).is_err(),
            "unconsumed graph line accepted:\n{text}"
        );
    }
    let valid = LOCK.replace("  .:", "  packages/it's: # importer")
        + "overrides:\n  zod: 'file:vendor/# test' # comment\n";
    let lock = parse_pnpm_lock(&valid).unwrap();
    assert_eq!(lock.importers[0].path, "packages/it's");
    assert_eq!(lock.overrides[0].1, "file:vendor/# test");
}
