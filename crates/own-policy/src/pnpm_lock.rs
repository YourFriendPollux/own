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
//! Indentation-based parsing of these sections. Nonempty flow maps and other
//! unsupported graph syntax are refused, never interpreted as an empty graph.

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
    pub dev_deps: Vec<(String, String, String)>,
}

impl Importer {
    pub fn all_deps(&self) -> impl Iterator<Item = &(String, String, String)> {
        self.deps.iter().chain(&self.dev_deps)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PkgEntry {
    pub key: String, // "zod@3.22.4" possibly with suffix
    pub name: String,
    pub version: String,
    pub deps: Vec<(String, String)>, // (name, resolved version)
}

/// Registry identity of an edge, without changing its declared dependency name.
/// pnpm aliases resolve as `name@version` (optionally prefixed with `npm:`),
/// while ordinary edges carry only a version. Local/URL edges are not registry
/// versions, even when an importer's file specifier accompanies a bare version.
pub fn registry_dependency(
    declared_name: &str,
    specifier: Option<&str>,
    resolution: &str,
) -> Option<(String, String)> {
    // A catalog specifier is an indirection to a registry constraint, not a
    // local dependency protocol. Its locked resolution supplies the identity.
    if specifier
        .is_some_and(|s| s.contains(':') && !s.starts_with("npm:") && !s.starts_with("catalog:"))
    {
        return None;
    }
    let resolution = resolution.strip_prefix("npm:").unwrap_or(resolution);
    // A peer's file protocol does not change this edge's registry identity.
    let resolution = resolution.split('(').next().unwrap_or(resolution);
    if resolution.contains(':') {
        return None;
    }
    let (name, version) = if resolution.contains('@') {
        split_pkg_key(resolution)
    } else {
        let name = specifier
            .and_then(|s| s.strip_prefix("npm:"))
            .map(|s| split_pkg_key(s).0)
            .unwrap_or_else(|| declared_name.to_string());
        (name, resolution.to_string())
    };
    if name.is_empty() || !crate::semver::is_valid_version(&version) {
        return None;
    }
    Some((name, version))
}

/// Exact local file target, including alias-qualified snapshot resolutions.
pub fn file_dependency_path(resolution: &str) -> Option<&str> {
    let resolution = resolution.split('(').next().unwrap_or(resolution);
    let target = resolution
        .strip_prefix("file:")
        .or_else(|| resolution.split_once("@file:").map(|(_, path)| path))?;
    Some(target)
}

impl PnpmLock {
    /// Every real registry version in the catalogue or dependency graph.
    pub fn resolved_versions(&self, name: &str) -> Vec<String> {
        let mut versions: Vec<String> = self
            .importers
            .iter()
            .flat_map(|im| im.all_deps())
            .filter_map(|(n, spec, v)| registry_dependency(n, Some(spec), v))
            .chain(
                self.packages
                    .iter()
                    .filter_map(|p| registry_dependency(&p.name, None, &p.key)),
            )
            .chain(self.packages.iter().flat_map(|p| {
                p.deps
                    .iter()
                    .filter_map(|(n, v)| registry_dependency(n, None, v))
            }))
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v)
            .collect();
        versions.sort();
        versions.dedup();
        versions
    }

    pub fn registry_dependents(&self, name: &str, version: &str) -> Vec<String> {
        self.dependents_matching(|n, spec, v| {
            registry_dependency(n, spec, v).is_some_and(|(n, v)| n == name && v == version)
        })
    }

    pub fn file_dependents(&self, dir: &str) -> Vec<String> {
        self.dependents_matching(|_, spec, v| {
            file_dependency_path(v) == Some(dir)
                || spec.is_some_and(|s| file_dependency_path(s) == Some(dir))
        })
    }

    fn dependents_matching(
        &self,
        matches: impl Fn(&str, Option<&str>, &str) -> bool,
    ) -> Vec<String> {
        let mut dependents: Vec<String> = self
            .importers
            .iter()
            .filter(|im| im.all_deps().any(|(n, spec, v)| matches(n, Some(spec), v)))
            .map(|im| format!("importer:{}", im.path))
            .collect();
        for p in &self.packages {
            if p.deps.iter().any(|(n, v)| matches(n, None, v)) {
                dependents.push(format!("{}@{}", p.name, p.version));
            }
        }
        dependents.sort();
        dependents.dedup();
        dependents
    }
}

pub fn parse_pnpm_lock(text: &str) -> Result<PnpmLock, String> {
    // Newer pnpm releases can put a package-manager lock before the project
    // lock (even a different schema). Never merge them or return the first
    // document's empty runtime graph as if it described the whole project.
    let mut started = false;
    let mut content = false;
    let mut ended = false;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let token = line.split_whitespace().next();
        if line.starts_with("---") && token == Some("---") {
            if started || content || ended {
                return Err(format!(
                    "PNPM_UNSUPPORTED: multiple documents at line {}",
                    index + 1
                ));
            }
            started = true;
        } else if line.starts_with("...") && token == Some("...") {
            ended = true;
        } else {
            if ended {
                return Err(format!(
                    "PNPM_UNSUPPORTED: multiple documents at line {}",
                    index + 1
                ));
            }
            content = true;
        }
    }
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
        let l = without_yaml_comment(lines[i]).trim_end();
        if let Some(v) = l.strip_prefix("lockfileVersion:") {
            lock.lockfile_version = dependency_scalar(v)?;
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
    // YAML mapping order is not semantic: consume sections before the header
    // too, rather than silently losing that prefix of the graph.
    i = 0;
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

    let mut top_keys = std::collections::BTreeSet::new();
    let mut importer_keys = std::collections::BTreeSet::new();
    let mut importer_sections = std::collections::BTreeSet::new();
    let mut importer_deps = std::collections::BTreeSet::new();
    let mut package_keys = std::collections::BTreeSet::new();
    let mut package_sections = std::collections::BTreeSet::new();
    let mut package_deps = std::collections::BTreeSet::new();
    let mut override_keys = std::collections::BTreeSet::new();

    fn indent(l: &str) -> usize {
        l.len() - l.trim_start().len()
    }

    fn block_or_empty_map(t: &str) -> bool {
        t.ends_with(':') || t.ends_with(": {}")
    }

    while i < lines.len() {
        let raw = lines[i];
        let l = without_yaml_comment(raw).trim_end();
        if l.trim().is_empty() || l.trim_start().starts_with('#') {
            i += 1;
            continue;
        }
        let ind = indent(l);
        let t = l.trim();
        let raw_key = t.split_once(':').map(|(key, _)| key).unwrap_or(t);
        let key = raw_key.trim().trim_matches('\'').trim_matches('"');
        if (ind == 0 && matches!(key, "importers" | "packages" | "snapshots" | "overrides")
            || ind == 4
                && matches!(
                    key,
                    "dependencies" | "optionalDependencies" | "devDependencies"
                ))
            && raw_key != key
        {
            return Err(format!(
                "PNPM_UNSUPPORTED: noncanonical graph field at line {}",
                i + 1
            ));
        }
        // An empty map is still a section boundary, e.g. `packages: {}`
        // followed by snapshots. Keep the parser line-oriented and limited to
        // the four pnpm sections we consume.
        if ind == 0 {
            if matches!(
                key,
                "lockfileVersion" | "importers" | "packages" | "snapshots" | "overrides"
            ) {
                unique_graph_key(&mut top_keys, key, i + 1)?;
            }
            package_keys.clear();
            if let Some(im) = cur_importer.take() {
                lock.importers.push(im);
            }
            if let Some(p) = cur_pkg.take() {
                lock.packages.push(p);
            }
            section = match t.split_once(':').map(|(key, _)| key) {
                Some("importers") => Section::Importers,
                Some("packages") => Section::Packages,
                Some("snapshots") => Section::Snapshots,
                Some("overrides") => Section::Overrides,
                _ => Section::None,
            };
            if !matches!(section, Section::None) && !block_or_empty_map(t) {
                return Err(format!(
                    "PNPM_UNSUPPORTED: graph map at line {}: {t}",
                    i + 1
                ));
            }
            cur_dep_section = None;
            cur_pkg_dep_section = None;
            i += 1;
            continue;
        }
        let orphan = match section {
            Section::Importers => cur_importer.is_none() && ind != 2,
            Section::Packages | Section::Snapshots => cur_pkg.is_none() && ind != 2,
            _ => false,
        };
        let dependency_field = matches!(
            key,
            "dependencies" | "optionalDependencies" | "devDependencies"
        );
        let bad_depth = match section {
            Section::Importers => {
                (dependency_field && ind > 4 && (ind != 6 || cur_dep_section.is_none()))
                    || (cur_dep_section.is_some() && ind > 8)
            }
            Section::Packages | Section::Snapshots => {
                (dependency_field && ind > 4 && (ind != 6 || cur_pkg_dep_section.is_none()))
                    || (cur_pkg_dep_section.is_some() && ind > 6)
            }
            _ => false,
        };
        if !matches!(section, Section::None)
            && (orphan
                || bad_depth
                || !ind.is_multiple_of(2)
                || l[..ind].contains('\t')
                || key == "<<")
        {
            return Err(format!(
                "PNPM_UNSUPPORTED: graph structure at line {}",
                i + 1
            ));
        }
        let graph_map = match section {
            Section::Importers => {
                ind == 2
                    || (ind == 4
                        && ["dependencies:", "optionalDependencies:", "devDependencies:"]
                            .iter()
                            .any(|key| t.starts_with(key)))
                    || (ind == 6 && cur_dep_section.is_some())
            }
            Section::Packages | Section::Snapshots => {
                ind == 2
                    || (ind == 4
                        && ["dependencies:", "optionalDependencies:"]
                            .iter()
                            .any(|key| t.starts_with(key)))
            }
            _ => false,
        };
        if graph_map && !block_or_empty_map(t) {
            return Err(format!(
                "PNPM_UNSUPPORTED: graph map at line {}: {t}",
                i + 1
            ));
        }
        match &section {
            Section::None => {}
            Section::Importers => {
                if ind == 2 && block_or_empty_map(t) {
                    let path = dependency_scalar(yaml_mapping(t).map(|(k, _)| k).unwrap_or(t))?;
                    unique_graph_key(&mut importer_keys, &path, i + 1)?;
                    importer_sections.clear();
                    importer_deps.clear();
                    if let Some(im) = cur_importer.take() {
                        lock.importers.push(im);
                    }
                    cur_importer = Some(Importer {
                        path,
                        deps: Vec::new(),
                        dev_deps: Vec::new(),
                    });
                    let _ = cur_dep_section.take();
                } else if ind == 4 {
                    let key = t.split_once(':').map(|(key, _)| key);
                    cur_dep_section = key
                        .filter(|key| {
                            matches!(
                                *key,
                                "dependencies" | "optionalDependencies" | "devDependencies"
                            )
                        })
                        .map(str::to_string);
                    if let Some(key) = &cur_dep_section {
                        unique_graph_key(&mut importer_sections, key, i + 1)?;
                    }
                    importer_deps.clear();
                    let _ = &cur_dep_section;
                } else if ind == 6 && cur_dep_section.is_some() {
                    if !t.ends_with(':') {
                        return Err(format!(
                            "PNPM_UNSUPPORTED: dependency fields required at line {}",
                            i + 1
                        ));
                    }
                    // dep name at ind 6; specifier/version nested at ind 8
                    if let Some(im) = &mut cur_importer {
                        let name = dependency_scalar(yaml_mapping(t).map(|(k, _)| k).unwrap_or(t))?;
                        unique_graph_key(&mut importer_deps, &name, i + 1)?;
                        let deps = if cur_dep_section.as_deref() == Some("devDependencies") {
                            &mut im.dev_deps
                        } else {
                            &mut im.deps
                        };
                        deps.push((name, String::new(), String::new()));
                    }
                } else if ind == 8 && cur_dep_section.is_some() {
                    let (k, v) = yaml_mapping(t).ok_or_else(|| {
                        format!("PNPM_UNSUPPORTED: dependency mapping at line {}", i + 1)
                    })?;
                    if importer_deps.is_empty() {
                        return Err(format!(
                            "PNPM_UNSUPPORTED: orphan dependency field at line {}",
                            i + 1
                        ));
                    }
                    if let Some(im) = &mut cur_importer {
                        let deps = if cur_dep_section.as_deref() == Some("devDependencies") {
                            &mut im.dev_deps
                        } else {
                            &mut im.deps
                        };
                        if let Some(last) = deps.last_mut() {
                            let v = dependency_scalar(v)?;
                            match k.trim() {
                                "specifier" if last.1.is_empty() => last.1 = v,
                                "version" if last.2.is_empty() => last.2 = v,
                                "specifier" | "version" => {
                                    return Err(format!(
                                        "PNPM_UNSUPPORTED: duplicate dependency field at line {}",
                                        i + 1
                                    ));
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            Section::Packages | Section::Snapshots => {
                if ind == 2 && (t.ends_with(':') || t.ends_with(": {}")) {
                    if let Some(p) = cur_pkg.take() {
                        lock.packages.push(p);
                    }
                    let key = dependency_scalar(yaml_mapping(t).map(|(k, _)| k).unwrap_or(t))?;
                    unique_graph_key(&mut package_keys, &key, i + 1)?;
                    package_sections.clear();
                    package_deps.clear();
                    let (name, version) = split_pkg_key(&key);
                    cur_pkg = Some(PkgEntry {
                        key,
                        name,
                        version,
                        deps: Vec::new(),
                    });
                    cur_pkg_dep_section = None;
                } else if ind == 4 {
                    cur_pkg_dep_section = t
                        .split_once(':')
                        .map(|(key, _)| key)
                        .filter(|key| matches!(*key, "dependencies" | "optionalDependencies"))
                        .map(str::to_string);
                    if let Some(key) = &cur_pkg_dep_section {
                        unique_graph_key(&mut package_sections, key, i + 1)?;
                    }
                    package_deps.clear();
                } else if ind == 6 && cur_pkg_dep_section.is_some() {
                    let (name, ver) = yaml_mapping(t).ok_or_else(|| {
                        format!("PNPM_UNSUPPORTED: dependency mapping at line {}", i + 1)
                    })?;
                    if let (Some(p), Some(_sec)) = (&mut cur_pkg, &cur_pkg_dep_section) {
                        let name = dependency_scalar(name)?;
                        unique_graph_key(&mut package_deps, &name, i + 1)?;
                        p.deps.push((name, dependency_scalar(ver)?));
                    }
                }
            }
            Section::Overrides => {
                if ind != 2 {
                    return Err(format!(
                        "PNPM_UNSUPPORTED: override structure at line {}",
                        i + 1
                    ));
                }
                let (k, v) = yaml_mapping(t).ok_or_else(|| {
                    format!("PNPM_UNSUPPORTED: override mapping at line {}", i + 1)
                })?;
                let key = dependency_scalar(k)?;
                unique_graph_key(&mut override_keys, &key, i + 1)?;
                lock.overrides.push((key, dependency_scalar(v)?));
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
    // Validate the graph we consumed before exposing it to diamond/coherence
    // checks. Incomplete or uninterpretable edges must not disappear from them.
    for importer in &lock.importers {
        for (name, specifier, resolution) in importer.all_deps() {
            if name.is_empty() || !supported_scalar(specifier) || !supported_resolution(resolution)
            {
                return Err(format!(
                    "PNPM_UNSUPPORTED: unreadable dependency {name:?} in importer {:?}",
                    importer.path
                ));
            }
        }
    }
    for package in &lock.packages {
        if package.name.is_empty() || !supported_resolution(&package.version) {
            return Err(format!(
                "PNPM_UNSUPPORTED: unreadable package key {:?}",
                package.key
            ));
        }
        for (name, resolution) in &package.deps {
            if name.is_empty() || !supported_resolution(resolution) {
                return Err(format!(
                    "PNPM_UNSUPPORTED: unreadable dependency {name:?} in {:?}",
                    package.key
                ));
            }
        }
    }
    Ok(lock)
}

fn unique_graph_key(
    keys: &mut std::collections::BTreeSet<String>,
    key: &str,
    line: usize,
) -> Result<(), String> {
    if !keys.insert(key.to_string()) {
        return Err(format!(
            "PNPM_UNSUPPORTED: duplicate graph key {key:?} at line {line}"
        ));
    }
    Ok(())
}

// A comment marker is significant only outside a quoted scalar and after
// whitespace. Apostrophes inside plain paths/URLs are literal, not delimiters.
fn without_yaml_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut scalar_start = true;
    for (i, &byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(delimiter) = quote {
            if delimiter == b'"' && byte == b'\\'
                || delimiter == b'\'' && byte == b'\'' && bytes.get(i + 1) == Some(&b'\'')
            {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
        } else if byte == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        } else if byte.is_ascii_whitespace() {
            continue;
        } else if scalar_start && matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
            scalar_start = false;
        } else {
            scalar_start = matches!(byte, b'{' | b'[' | b',')
                || byte == b':' && bytes.get(i + 1).is_none_or(u8::is_ascii_whitespace);
        }
    }
    line
}

// Find the mapping delimiter, not a colon inside a quoted selector or URL.
fn yaml_mapping(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    if let Some(&quote @ (b'\'' | b'"')) = bytes.first() {
        i = 1;
        while i < bytes.len() {
            if quote == b'"' && bytes[i] == b'\\'
                || quote == b'\'' && bytes[i] == b'\'' && bytes.get(i + 1) == Some(&b'\'')
            {
                i += 2;
            } else if bytes[i] == quote {
                i += 1;
                break;
            } else {
                i += 1;
            }
        }
    }
    while i < bytes.len() {
        if bytes[i] == b':' && bytes.get(i + 1).is_none_or(u8::is_ascii_whitespace) {
            return Some((&line[..i], &line[i + 1..]));
        }
        i += 1;
    }
    None
}

fn supported_scalar(value: &str) -> bool {
    !value.is_empty() && !value.starts_with(['{', '[', '&', '!', '|'])
}

fn dependency_scalar(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    let quoted = value.len() >= 2
        && ((value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('"') && value.ends_with('"')));
    // Check YAML syntax before removing quotes. A quoted '*' is an npm
    // wildcard, not an alias; '>=5' and '>5' are ranges, not folded blocks.
    let folded = value.starts_with('>')
        && !value
            .as_bytes()
            .get(1)
            .is_some_and(|ch| ch.is_ascii_digit() || *ch == b'=');
    if !quoted && (!supported_scalar(value) || value.starts_with('*') || folded) {
        return Err("PNPM_UNSUPPORTED: unreadable dependency scalar".to_string());
    }
    if value.starts_with('"') {
        return serde_json::from_str::<String>(value)
            .map_err(|_| "PNPM_UNSUPPORTED: invalid or unsupported quoted scalar".to_string());
    }
    if value.starts_with('\'') {
        let inside = value
            .strip_prefix('\'')
            .and_then(|v| v.strip_suffix('\''))
            .ok_or("PNPM_UNSUPPORTED: unclosed quoted scalar")?;
        if inside.replace("''", "").contains('\'') {
            return Err("PNPM_UNSUPPORTED: invalid quoted scalar".to_string());
        }
        return Ok(inside.replace("''", "'"));
    }
    Ok(value.to_string())
}

fn supported_resolution(value: &str) -> bool {
    if !supported_scalar(value) {
        return false;
    }
    registry_dependency("dependency", None, value).is_some()
        || file_dependency_path(value).is_some_and(|path| !path.is_empty())
        || [
            value.split('(').next().unwrap_or(value),
            &split_pkg_key(value).1,
        ]
        .iter()
        .any(|resolution| {
            [
                "link:",
                "workspace:",
                "https://",
                "http://",
                "git+https://",
                "git+ssh://",
                "git://",
            ]
            .iter()
            .any(|prefix| {
                resolution
                    .strip_prefix(prefix)
                    // pnpm writes `link:` for an importer linking to
                    // itself. It is local, not a missing registry version.
                    .is_some_and(|target| !target.is_empty() || *prefix == "link:")
            })
        })
}

/// Split a snapshots key like `zod@3.22.4` or `@scope/name@1.0.0(peer@2.0)` into (name, version).
pub fn split_pkg_key(key: &str) -> (String, String) {
    // strip peer suffix "(...)"
    let key = key.split('(').next().unwrap_or(key);
    // pnpm lockfile v9 writes scoped keys as @scope+name@version
    let key =
        if key.starts_with('@') && key.split('@').nth(1).is_some_and(|name| name.contains('+')) {
            key.replacen('+', "/", 1)
        } else {
            key.to_string()
        };
    let key = key.as_str();
    if let Some(rest) = key.strip_prefix('@') {
        // scoped: @scope/name@version
        if let Some(idx) = rest.find('/') {
            let after = &rest[idx + 1..];
            if let Some(at) = after.find('@') {
                return (
                    format!("@{}/{}", &rest[..idx], &after[..at]),
                    after[at + 1..].to_string(),
                );
            }
        }
        (format!("@{rest}"), String::new())
    } else if let Some(at) = key.find('@') {
        (key[..at].to_string(), key[at + 1..].to_string())
    } else {
        (key.to_string(), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from pnpm 10.33 after vendoring picomatch in tinyglobby 0.2.16.
    const REAL_FILE_PEER: &str = "6.5.0(picomatch@file:vendor/own/picomatch@4.0.4)";

    #[test]
    fn real_registry_resolution_with_file_peer() {
        assert_eq!(
            registry_dependency("fdir", Some("^6.5.0"), REAL_FILE_PEER),
            Some(("fdir".to_string(), "6.5.0".to_string()))
        );
    }

    #[test]
    fn real_registry_file_peer_is_not_the_dependency_target() {
        assert_eq!(file_dependency_path(REAL_FILE_PEER), None);
    }

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
    fn runtime_dependencies_exclude_dev_but_diamond_graph_keeps_them_inv6() {
        let lock = parse_pnpm_lock("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      runtime:\n        specifier: 1.0.0\n        version: 1.0.0\n    devDependencies:\n      development:\n        specifier: 2.0.0\n        version: 2.0.0\npackages: {}\n").unwrap();
        assert_eq!(
            lock.importers[0].deps,
            [("runtime".into(), "1.0.0".into(), "1.0.0".into())]
        );
        assert_eq!(
            lock.registry_dependents("development", "2.0.0"),
            ["importer:."]
        );
        assert_eq!(lock.resolved_versions("development"), ["2.0.0"]);
    }

    #[test]
    fn snapshots_after_empty_packages_keep_alias_edges_inv6() {
        let lock = parse_pnpm_lock(
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      consumer:\n        specifier: 2.0.0\n        version: 2.0.0\npackages: {}\nsnapshots:\n  consumer@2.0.0:\n    dependencies:\n      alias-a: a@1.0.0\n  a@1.0.0: {}\n",
        )
        .unwrap();
        assert_eq!(
            lock.packages.len(),
            2,
            "INV-6: snapshots must not be skipped"
        );
        assert_eq!(lock.packages[0].name, "consumer");
        assert_eq!(
            lock.packages[0].deps,
            vec![("alias-a".into(), "a@1.0.0".into())]
        );
        assert_eq!(lock.packages[1].name, "a");
        assert_eq!(lock.packages[1].version, "1.0.0");
    }

    #[test]
    fn registry_alias_identity_handles_scopes_and_peers_inv6() {
        for (declared, spec, resolved, name, version) in [
            (
                "zod-old",
                "npm:zod@^3.22.0",
                "zod@3.22.4(peer@2.0.0)",
                "zod",
                "3.22.4",
            ),
            (
                "zod-old",
                "npm:zod@3.22.4",
                "npm:zod@3.22.4",
                "zod",
                "3.22.4",
            ),
            (
                "alias",
                "npm:@scope/thing@^1.0.0",
                "@scope/thing@1.0.0(peer@2.0.0)",
                "@scope/thing",
                "1.0.0",
            ),
            (
                "alias",
                "npm:@scope/thing@1.0.0",
                "@scope+thing@1.0.0",
                "@scope/thing",
                "1.0.0",
            ),
            (
                "alias",
                "npm:@scope/thing@^1.0.0",
                "1.0.0",
                "@scope/thing",
                "1.0.0",
            ),
            ("zod", "^3.22.0", "3.22.4(peer@2.0.0)", "zod", "3.22.4"),
        ] {
            assert_eq!(
                registry_dependency(declared, Some(spec), resolved),
                Some((name.into(), version.into())),
                "{declared}: {resolved}"
            );
        }
    }

    #[test]
    fn local_resolutions_are_not_registry_versions_inv6() {
        for local in [
            "file:vendor/own/a@1.0.0",
            "a@file:vendor/own/a@1.0.0(peer@2.0.0)",
            "link:../a",
            "workspace:*",
            "https://example.invalid/a@1.0.0.tgz",
            "git+https://example.invalid/a.git",
        ] {
            assert_eq!(registry_dependency("a", None, local), None, "{local}");
            assert_eq!(
                registry_dependency("a", Some(local), "1.0.0"),
                None,
                "{local}"
            );
        }
        assert_eq!(
            split_pkg_key("@scope/thing@file:vendor/own/@scope+thing@1.0.0(peer@2.0.0)"),
            (
                "@scope/thing".into(),
                "file:vendor/own/@scope+thing@1.0.0".into()
            )
        );
        assert_eq!(
            file_dependency_path("alias@file:vendor/own/a@1.0.0(peer@2.0.0)"),
            Some("vendor/own/a@1.0.0")
        );
    }

    #[test]
    fn inverse_alias_graph_preserves_declared_names_inv6() {
        let lock = parse_pnpm_lock(
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      alias-a:\n        specifier: npm:a@^1.0.0\n        version: a@1.0.0(peer@3.0.0)\npackages: {}\nsnapshots:\n  consumer@2.0.0:\n    dependencies:\n      alias-a: a@1.0.0\n  a@1.0.0: {}\n",
        )
        .unwrap();
        assert_eq!(lock.importers[0].deps[0].0, "alias-a");
        assert_eq!(lock.packages[0].deps[0].0, "alias-a");
        assert_eq!(lock.resolved_versions("a"), ["1.0.0"]);
        assert_eq!(
            lock.registry_dependents("a", "1.0.0"),
            ["consumer@2.0.0", "importer:."]
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
    fn pnpm_unsupported_graph_flow_maps_fail_closed() {
        for graph in [
            "packages: {'a@2.0.0': {resolution: {integrity: sha512-x}}}\nsnapshots: {'a@2.0.0': {}}\n",
            "packages: {}\nsnapshots: {'a@2.0.0': {}}\n",
            "importers: {'.': {dependencies: {a: {specifier: 2.0.0, version: 2.0.0}}}}\n",
            "importers:\n  .: {dependencies: {a: {specifier: 2.0.0, version: 2.0.0}}}\n",
            "importers:\n  .:\n    dependencies: {a: {specifier: 2.0.0, version: 2.0.0}}\n",
            "packages:\n  a@2.0.0: {dependencies: {b: 3.0.0}}\n",
            "snapshots:\n  a@2.0.0:\n    dependencies: {b: 3.0.0}\n",
            "packages: &catalogue\n  a@2.0.0: {}\nsnapshots: *catalogue\n",
        ] {
            let text = format!("lockfileVersion: '9.0'\n{graph}");
            assert!(parse_pnpm_lock(&text).is_err(), "silently accepted: {graph}");
        }
        let empty = parse_pnpm_lock(
            "lockfileVersion: '9.0'\nimporters: {}\npackages: {}\nsnapshots: {}\noverrides: {}\n",
        )
        .unwrap();
        assert!(empty.importers.is_empty() && empty.packages.is_empty());
    }

    #[test]
    fn pnpm_truncated_or_unreadable_dependencies_fail_closed() {
        let prefix = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n";
        for fields in [
            "        specifier: ^1.0.0\n",
            "        version: 1.0.0\n",
            "        specifier: ^1.0.0\n        version:\n",
            "        specifier: ^1.0.0\n        version: *missing\n",
            "        specifier: ^1.0.0\n        version: {bad: 1.0.0}\n",
            "        specifier: ^1.0.0\n        version: not-a-version\n",
        ] {
            assert!(
                parse_pnpm_lock(&format!("{prefix}{fields}")).is_err(),
                "silently accepted: {fields}"
            );
        }
        for graph in [
            "snapshots:\n  a@1.0.0:\n    dependencies:\n      b:\n",
            "snapshots:\n  a@1.0.0:\n    dependencies:\n      b: [2.0.0]\n",
            "snapshots:\n  a@1.0.0:\n    dependencies:\n      b: *missing\n",
            "snapshots:\n  a@1.0.0:\n    dependencies:\n      b: not-a-version\n",
            "packages:\n  not-a-package-version: {}\n",
            "importers:\n  .:\n    dependencies:\n      a: {}\n",
        ] {
            assert!(
                parse_pnpm_lock(&format!("lockfileVersion: '9.0'\n{graph}")).is_err(),
                "silently accepted: {graph}"
            );
        }
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

    #[test]
    fn pnpm_ambiguous_graph_shapes_fail_closed() {
        for graph in [
            "packages:\n    a@1.0.0: {}\n",
            "snapshots:\n a@1.0.0: {}\n",
            "importers:\n    dependencies:\n      a:\n        specifier: ^1.0.0\n        version: 1.0.0\n",
            "importers:\n  .:\n    <<: {dependencies: {a: {specifier: 1.0.0, version: 1.0.0}}}\n",
            "'packages': {'a@2.0.0': {}}\n",
            "snapshots:\n  a@1.0.0:\n    'dependencies': {b: 2.0.0}\n",
            "importers:\n  .:\n    dependencies:\n      a:\n        specifier: ^1.0.0\n        version: 1.0.0\n        version: 2.0.0\n",
        ] {
            assert!(parse_pnpm_lock(&format!("lockfileVersion: '9.0'\n{graph}")).is_err(), "silently accepted: {graph}");
        }
    }

    #[test]
    fn pnpm_valid_local_and_quoted_alias_edges_remain_visible() {
        let lock = parse_pnpm_lock("lockfileVersion: '9.0'\nimporters:\n  '.':\n    dependencies:\n      alias:\n        specifier: npm:@scope/thing@^1.0.0\n        version: '@scope/thing@1.0.0(peer@2.0.0)'\n      local:\n        specifier: file:vendor/own/local@1.0.0\n        version: file:vendor/own/local@1.0.0\npackages: {}\nsnapshots:\n  '@scope/thing@1.0.0(peer@2.0.0)': {}\n  'local@file:vendor/own/local@1.0.0': {}\n").unwrap();
        assert_eq!(lock.resolved_versions("@scope/thing"), ["1.0.0"]);
        assert_eq!(
            lock.file_dependents("vendor/own/local@1.0.0"),
            ["importer:."]
        );
    }
}
