//! Minimal, strict-enough parser for `pnpm-lock.yaml` v9 (`lockfileVersion: '9.0'`).
//!
//! We do NOT use a general YAML crate (SPEC §12: serde_yaml archived): the pnpm
//! lockfile has a stable, line-oriented shape and we only need:
//! - `importers:` map: each importer's `dependencies:` / `optionalDependencies:` entries
//!   with `specifier` and `version`
//! - `packages:` map (snapshots): keys `name@version` (or `name@version(...)`) with
//!   `dependencies:` / `optionalDependencies:` name->version
//! - top-level `overrides:` map (informational)
//!
//! Indentation-based parsing of these three sections; anything else is ignored.

#[derive(Debug, Clone, PartialEq)]
pub struct PnpmLock {
    pub lockfile_version: String,
    pub importers: Vec<Importer>,
    pub packages: Vec<PkgEntry>,
    pub overrides: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Importer {
    pub path: String,                        // "." or "packages/a"
    pub deps: Vec<(String, String, String)>, // (name, specifier, resolved version)
}

#[derive(Debug, Clone, PartialEq)]
pub struct PkgEntry {
    pub key: String, // "zod@3.22.4" possibly with suffix
    pub name: String,
    pub version: String,
    pub deps: Vec<(String, String)>, // (name, resolved version)
}

pub fn parse_pnpm_lock(text: &str) -> Result<PnpmLock, String> {
    let mut lock = PnpmLock {
        lockfile_version: String::new(),
        importers: Vec::new(),
        packages: Vec::new(),
        overrides: Vec::new(),
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    // lockfileVersion
    while i < lines.len() {
        let l = lines[i].trim_end();
        if let Some(v) = l.strip_prefix("lockfileVersion:") {
            lock.lockfile_version = v.trim().trim_matches('\'').trim_matches('"').to_string();
            break;
        }
        i += 1;
    }
    if lock.lockfile_version != "9.0" {
        return Err(format!(
            "PNPM_UNSUPPORTED: lockfileVersion {:?} (only '9.0')",
            lock.lockfile_version
        ));
    }
    enum Section {
        None,
        Importers,
        Packages,
        Snapshots,
        Overrides,
    }
    let mut section = Section::None;
    let mut cur_importer: Option<Importer> = None;
    #[allow(unused_assignments)]
    let mut cur_dep_section: Option<String> = None; // tracks current dep block (informational)
    let mut cur_pkg: Option<PkgEntry> = None;
    let mut cur_pkg_dep_section: Option<String> = None;

    fn indent(l: &str) -> usize {
        l.len() - l.trim_start().len()
    }

    while i < lines.len() {
        let raw = lines[i];
        let l = raw.trim_end();
        if l.trim().is_empty() || l.trim_start().starts_with('#') {
            i += 1;
            continue;
        }
        let ind = indent(l);
        let t = l.trim();
        match &section {
            Section::None => {
                if t == "importers:" && ind == 0 {
                    section = Section::Importers;
                } else if t == "packages:" && ind == 0 {
                    section = Section::Packages;
                } else if t == "snapshots:" && ind == 0 {
                    section = Section::Snapshots;
                } else if t == "overrides:" && ind == 0 {
                    section = Section::Overrides;
                }
            }
            Section::Importers => {
                if ind == 0 && t.ends_with(':') && t != "importers:" {
                    // leaving importers
                    if let Some(im) = cur_importer.take() {
                        lock.importers.push(im);
                    }
                    if t == "packages:" {
                        section = Section::Packages;
                    } else if t == "overrides:" {
                        section = Section::Overrides;
                    }
                    i += 1;
                    continue;
                }
                if ind == 2 && t.ends_with(':') {
                    if let Some(im) = cur_importer.take() {
                        lock.importers.push(im);
                    }
                    cur_importer = Some(Importer {
                        path: t.trim_end_matches(':').to_string(),
                        deps: Vec::new(),
                    });
                    let _ = cur_dep_section.take();
                } else if ind == 4 && (t == "dependencies:" || t == "optionalDependencies:") {
                    cur_dep_section = Some(t.trim_end_matches(':').to_string());
                    let _ = &cur_dep_section;
                } else if ind == 6 && t.ends_with(':') {
                    // dep name at ind 6; specifier/version nested at ind 8
                    if let Some(im) = &mut cur_importer {
                        let name = t
                            .trim_end_matches(':')
                            .trim_matches('\'')
                            .trim_matches('"')
                            .to_string();
                        im.deps.push((name, String::new(), String::new()));
                    }
                } else if ind == 8 && t.contains(':') {
                    if let Some(im) = &mut cur_importer {
                        if let Some(last) = im.deps.last_mut() {
                            if let Some((k, v)) = t.split_once(':') {
                                let v = v.trim().trim_matches('\'').trim_matches('"').to_string();
                                match k.trim() {
                                    "specifier" => last.1 = v,
                                    "version" => last.2 = v,
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            Section::Packages => {
                if ind == 0 && t.ends_with(':') && t != "packages:" {
                    if let Some(p) = cur_pkg.take() {
                        lock.packages.push(p);
                    }
                    if t == "overrides:" {
                        section = Section::Overrides;
                    } else if t == "snapshots:" {
                        section = Section::Snapshots;
                    }
                    i += 1;
                    continue;
                }
                if ind == 2 && t.ends_with(':') {
                    if let Some(p) = cur_pkg.take() {
                        lock.packages.push(p);
                    }
                    let key = t
                        .trim_end_matches(':')
                        .trim_matches('\'')
                        .trim_matches('"')
                        .to_string();
                    let (name, version) = split_pkg_key(&key);
                    cur_pkg = Some(PkgEntry {
                        key,
                        name,
                        version,
                        deps: Vec::new(),
                    });
                    cur_pkg_dep_section = None;
                } else if ind == 4 && (t == "dependencies:" || t == "optionalDependencies:") {
                    cur_pkg_dep_section = Some(t.trim_end_matches(':').to_string());
                } else if ind == 6 && t.contains(':') {
                    if let (Some(p), Some(_sec)) = (&mut cur_pkg, &cur_pkg_dep_section) {
                        if let Some((name, ver)) = t.split_once(':') {
                            p.deps.push((
                                name.trim().trim_matches('\'').trim_matches('"').to_string(),
                                ver.trim().trim_matches('\'').trim_matches('"').to_string(),
                            ));
                        }
                    }
                }
            }
            Section::Snapshots => {
                if ind == 0 && t.ends_with(':') && t != "snapshots:" {
                    if let Some(p) = cur_pkg.take() {
                        lock.packages.push(p);
                    }
                    if t == "overrides:" {
                        section = Section::Overrides;
                    }
                    i += 1;
                    continue;
                }
                if ind == 2 && t.ends_with(':') {
                    if let Some(p) = cur_pkg.take() {
                        lock.packages.push(p);
                    }
                    let key = t
                        .trim_end_matches(':')
                        .trim_matches('\'')
                        .trim_matches('"')
                        .to_string();
                    let (name, version) = split_pkg_key(&key);
                    cur_pkg = Some(PkgEntry {
                        key,
                        name,
                        version,
                        deps: Vec::new(),
                    });
                    cur_pkg_dep_section = None;
                } else if ind == 4 && (t == "dependencies:" || t == "optionalDependencies:") {
                    cur_pkg_dep_section = Some(t.trim_end_matches(':').to_string());
                } else if ind == 6 && t.contains(':') {
                    if let (Some(p), Some(_sec)) = (&mut cur_pkg, &cur_pkg_dep_section) {
                        if let Some((name, ver)) = t.split_once(':') {
                            p.deps.push((
                                name.trim().trim_matches('\'').trim_matches('"').to_string(),
                                ver.trim().trim_matches('\'').trim_matches('"').to_string(),
                            ));
                        }
                    }
                }
            }
            Section::Overrides => {
                if ind == 0 && t.ends_with(':') && t != "overrides:" {
                    section = Section::None;
                    continue; // re-process this line in Section::None
                }
                if ind == 2 && t.contains(':') {
                    if let Some((k, v)) = t.split_once(':') {
                        lock.overrides.push((
                            k.trim().trim_matches('\'').trim_matches('"').to_string(),
                            v.trim().trim_matches('\'').trim_matches('"').to_string(),
                        ));
                    }
                }
            }
        }
        i += 1;
    }
    if let Some(im) = cur_importer.take() {
        lock.importers.push(im);
    }
    if let Some(p) = cur_pkg.take() {
        lock.packages.push(p);
    }
    Ok(lock)
}

/// Split a snapshots key like `zod@3.22.4` or `@scope/name@1.0.0(peer@2.0)` into (name, version).
pub fn split_pkg_key(key: &str) -> (String, String) {
    // strip peer suffix "(...)"
    let key = key.split('(').next().unwrap_or(key);
    // pnpm lockfile v9 writes scoped keys as @scope+name@version
    let key = if key.starts_with('@') && key.contains('+') {
        key.replacen('+', "/", 1)
    } else {
        key.to_string()
    };
    let key = key.as_str();
    if let Some(rest) = key.strip_prefix('@') {
        // scoped: @scope/name@version
        if let Some(idx) = rest.find('/') {
            let after = &rest[idx + 1..];
            if let Some(at) = after.rfind('@') {
                return (
                    format!("@{}/{}", &rest[..idx], &after[..at]),
                    after[at + 1..].to_string(),
                );
            }
        }
        (format!("@{rest}"), String::new())
    } else if let Some(at) = key.rfind('@') {
        (key[..at].to_string(), key[at + 1..].to_string())
    } else {
        (key.to_string(), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      zod:
        specifier: ^3.22.0
        version: 3.22.4

  packages/a:
    dependencies:
      zod:
        specifier: ^3.22.0
        version: 3.22.4

packages:

  zod@3.22.4:
    resolution: {integrity: sha512-x}

  '@scope+thing@1.0.0':
    dependencies:
      zod: 3.22.4
"#;

    #[test]
    fn parses_importers_and_packages() {
        let lock = parse_pnpm_lock(SAMPLE).unwrap();
        assert_eq!(lock.lockfile_version, "9.0");
        assert_eq!(lock.importers.len(), 2);
        assert_eq!(
            lock.importers[0].deps[0],
            ("zod".into(), "^3.22.0".into(), "3.22.4".into())
        );
        assert_eq!(lock.packages[1].name, "@scope/thing");
        assert_eq!(lock.packages[1].version, "1.0.0");
        assert_eq!(
            lock.packages[1].deps,
            vec![("zod".to_string(), "3.22.4".to_string())]
        );
    }

    #[test]
    fn rejects_other_lockfile_versions() {
        let bad = SAMPLE.replace("'9.0'", "'6.0'");
        assert!(parse_pnpm_lock(&bad)
            .unwrap_err()
            .contains("PNPM_UNSUPPORTED"));
    }

    #[test]
    fn split_pkg_key_handles_scope_and_peers() {
        assert_eq!(split_pkg_key("zod@3.22.4"), ("zod".into(), "3.22.4".into()));
        assert_eq!(
            split_pkg_key("@scope/name@1.0.0"),
            ("@scope/name".into(), "1.0.0".into())
        );
        assert_eq!(
            split_pkg_key("zod@3.22.4(peer@2.0)"),
            ("zod".into(), "3.22.4".into())
        );
    }
}
