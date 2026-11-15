//! Minimal shapes witnessed in real GitHub locks, without upstream source copies.
use own_policy::pnpm_lock::parse_pnpm_lock;

#[test]
fn quoted_npm_ranges_are_not_yaml_block_or_alias_indicators() {
    // pnpm/pnpm v10.0.0, deps/status -> @pnpm/logger.
    for specifier in [
        "'>=5.1.0 <1001.0.0'",
        "'>5.0.0'",
        "'*'",
        ">=5.1.0 <1001.0.0",
    ] {
        let text = format!("lockfileVersion: '9.0'\nimporters:\n  deps/status:\n    dependencies:\n      '@pnpm/logger':\n        specifier: {specifier}\n        version: 5.1.0\npackages: {{}}\n");
        let lock = parse_pnpm_lock(&text).unwrap();
        assert_eq!(lock.resolved_versions("@pnpm/logger"), ["5.1.0"]);
    }
    for specifier in [">", ">-", "|", "*missing", "&constraint ^5.0.0"] {
        let text = format!("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: {specifier}\n        version: 5.1.0\npackages: {{}}\n");
        assert!(
            parse_pnpm_lock(&text).is_err(),
            "accepted ambiguous YAML {specifier}"
        );
    }
}

#[test]
fn catalog_dependencies_participate_in_the_registry_graph() {
    // pnpm/pnpm v10.0.0 resolves catalog specifiers to ordinary npm versions.
    // Do not rely on the packages section: importer-only edges must count too.
    for specifier in ["catalog:", "catalog:default", "catalog:frontend"] {
        let text = format!("lockfileVersion: '9.0'\nimporters:\n  packages/a:\n    dependencies:\n      zod:\n        specifier: '{specifier}'\n        version: 3.22.4\npackages: {{}}\n");
        let lock = parse_pnpm_lock(&text).unwrap();
        assert_eq!(lock.resolved_versions("zod"), ["3.22.4"]);
        assert_eq!(
            lock.registry_dependents("zod", "3.22.4"),
            ["importer:packages/a"]
        );
    }
    assert!(
        own_policy::pnpm_lock::registry_dependency("local", Some("catalog:"), "link:../local")
            .is_none()
    );
}

#[test]
fn pnpm_current_directory_links_remain_local_edges() {
    // pnpm/pnpm v10.0.0: the private updater links to its own importer root.
    let text = "lockfileVersion: '9.0'\nimporters:\n  .meta-updater:\n    devDependencies:\n      '@pnpm-private/updater':\n        specifier: workspace:*\n        version: 'link:'\npackages: {}\n";
    let lock = parse_pnpm_lock(text).unwrap();
    assert_eq!(lock.importers[0].dev_deps[0].2, "link:");
    assert!(lock.resolved_versions("@pnpm-private/updater").is_empty());
    assert!(parse_pnpm_lock(&text.replace("'link:'", "'https://'")).is_err());
}

#[test]
fn url_aliases_are_visible_but_not_registry_versions() {
    // vitejs/vite v7.1.7, packages/plugin-legacy's preview tarball alias.
    let resolution = "@vitejs/plugin-legacy@https://pkg.pr.new/vitejs/rolldown-vite/@vitejs/plugin-legacy@a2594ec(terser@5.44.0)";
    let text = format!("lockfileVersion: '9.0'\nimporters:\n  packages/plugin-legacy:\n    devDependencies:\n      '@vitejs/plugin-legacy-for-rolldown-vite':\n        specifier: https://pkg.pr.new/vitejs/rolldown-vite/@vitejs/plugin-legacy@a2594ec\n        version: '{resolution}'\npackages: {{}}\nsnapshots:\n  '{resolution}': {{}}\n");
    let lock = parse_pnpm_lock(&text).unwrap();
    assert_eq!(lock.importers[0].dev_deps[0].2, resolution);
    assert_eq!(lock.packages[0].key, resolution);
    assert!(lock.resolved_versions("@vitejs/plugin-legacy").is_empty());
    assert!(lock
        .registry_dependents("@vitejs/plugin-legacy", "1.0.0")
        .is_empty());
    let bad = text.replace(
        "https://pkg.pr.new/vitejs/rolldown-vite/@vitejs/plugin-legacy@a2594ec",
        "https://",
    );
    assert!(parse_pnpm_lock(&bad).is_err());
}

#[test]
fn multidocument_locks_never_merge_or_silently_discard_graphs() {
    // pnpm/pnpm e0e583ce: YAML package-manager lock + JSON project lock v13.
    // vitejs/vite f8988882: two separate v9 YAML documents.
    let first = "---\nlockfileVersion: '9.0'\nimporters:\n  .: {}\npackages: {}\n";
    for second in [
        "---\n{\n\t\"lockfileVersion\": \"13.0\"\n}\n",
        "---\nlockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      zod:\n        specifier: ^4.0.0\n        version: 4.0.0\n",
        "--- # project dependencies\nlockfileVersion: '6.0'\nimporters: {}\n",
    ] {
        let error = parse_pnpm_lock(&format!("{first}{second}")).unwrap_err();
        assert!(error.starts_with("PNPM_UNSUPPORTED: multiple documents"), "{error}");
    }
    // A document start/end around one supported lock remains ordinary YAML.
    assert!(parse_pnpm_lock(&format!("{first}...\n")).is_ok());
}
