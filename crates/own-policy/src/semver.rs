//! npm semver: versions, ranges (npm grammar — NOT Cargo semver), and
//! OSV SEMVER/ECOSYSTEM range evaluation (SPEC §8.2, §9.1).
//!
//! Supports: exact versions, comparison operators (< <= > >= =), hyphen ranges
//! `1.2.3 - 2.3.4`, space-separated AND comparators, `||` OR, `*`, `x`, prereleases
//! with npm comparison rules. `workspace:`, `npm:`, tags, URLs are NOT semver
//! ranges (caller treats them as refusals per §9.2).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Vec<PrePart>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrePart {
    Num(u64),
    Str(String),
}

pub fn is_valid_version(s: &str) -> bool {
    let core = s
        .strip_prefix('v')
        .unwrap_or(s)
        .split(['-', '+'])
        .next()
        .unwrap_or("");
    core.split('.').count() == 3 && parse_version(s).is_some()
}

pub fn parse_version(s: &str) -> Option<Version> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let s = match s.split_once('+') {
        Some((version, build)) if valid_identifiers(build) => version,
        Some(_) => return None,
        None => s,
    };
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let mut parts = core.split('.');
    let major = parse_number(parts.next()?)?;
    let minor = parse_number(parts.next().unwrap_or("0"))?;
    let patch = parse_number(parts.next().unwrap_or("0"))?;
    if parts.next().is_some() {
        return None;
    }
    let pre = match pre {
        None => Vec::new(),
        Some(p) if core.split('.').count() == 3 && valid_identifiers(p) => p
            .split('.')
            .map(|part| {
                if part.bytes().all(|b| b.is_ascii_digit()) {
                    Some(PrePart::Num(parse_number(part)?))
                } else {
                    Some(PrePart::Str(part.to_string()))
                }
            })
            .collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
    };
    Some(Version {
        major,
        minor,
        patch,
        pre,
    })
}

fn parse_number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

/// Numeric npm OSV ECOSYSTEM interpretation, separate from strict npm/SemVer
/// validation. OSV's semver_index coerces missing components and leading core
/// zeros. Only that numeric subset is supported here; raw advisory strings are
/// never rewritten, and malformed suffixes are not repaired.
pub fn parse_osv_ecosystem_version(s: &str) -> Option<Version> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let end = s.find(['-', '+']).unwrap_or(s.len());
    let parts: Vec<_> = s[..end].split('.').collect();
    if !(1..=3).contains(&parts.len()) {
        return None;
    }
    let mut numbers = [0u64; 3];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        numbers[index] = part.parse().ok()?;
    }
    parse_version(&format!(
        "{}.{}.{}{}",
        numbers[0],
        numbers[1],
        numbers[2],
        &s[end..]
    ))
}

fn valid_identifiers(s: &str) -> bool {
    s.split('.').all(|part| {
        !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn cmp_pre(a: &[PrePart], b: &[PrePart]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if a.is_empty() && b.is_empty() {
        return Ordering::Equal;
    }
    if a.is_empty() {
        return Ordering::Greater; // release > prerelease
    }
    if b.is_empty() {
        return Ordering::Less;
    }
    for (x, y) in a.iter().zip(b.iter()) {
        let ord = match (x, y) {
            (PrePart::Num(m), PrePart::Num(n)) => m.cmp(n),
            (PrePart::Num(_), PrePart::Str(_)) => Ordering::Less,
            (PrePart::Str(_), PrePart::Num(_)) => Ordering::Greater,
            (PrePart::Str(s1), PrePart::Str(s2)) => s1.cmp(s2),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

impl Version {
    pub fn compare_to(&self, other: &Version) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then_with(|| cmp_pre(&self.pre, &other.pre))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.compare_to(other)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}

/// Does `version` satisfy the npm range `range`? npm grammar subset.
pub fn satisfies(version: &str, range: &str) -> bool {
    let v = match parse_version(version) {
        Some(v) => v,
        None => return false,
    };
    range
        .split("||")
        .map(|alt| satisfies_and(&v, alt.trim()))
        .collect::<Option<Vec<_>>>()
        .is_some_and(|alternatives| alternatives.into_iter().any(|matched| matched))
}

fn satisfies_and(v: &Version, range: &str) -> Option<bool> {
    let range = range.trim();
    // npm prerelease opt-in applies to the entire AND comparator set, and only
    // to the exact core tuple explicitly mentioned with a prerelease.
    let prerelease_allowed = v.pre.is_empty()
        || range.split_whitespace().any(|token| {
            parse_version(token.trim_start_matches(['<', '>', '=', '^', '~'])).is_some_and(|c| {
                !c.pre.is_empty() && (v.major, v.minor, v.patch) == (c.major, c.minor, c.patch)
            })
        });
    if range.is_empty() || range == "*" || range == "x" || range == "X" {
        return Some(prerelease_allowed);
    }
    let parts: Vec<&str> = range.split_whitespace().collect();
    if parts.len() == 3 && parts[1] == "-" {
        let (lo, hi) = (parse_partial(parts[0])?, parse_partial(parts[2])?);
        return Some(
            prerelease_allowed
                && (lo.precision == 0 || v >= &lo.version)
                && partial_comparator(v, "<=", &hi),
        );
    }
    let mut parts = parts.into_iter();
    let mut matches_all = prerelease_allowed;
    while let Some(part) = parts.next() {
        // npm accepts whitespace between an operator and its operand.
        let matched = if matches!(part, ">=" | "<=" | ">" | "<" | "=" | "^" | "~") {
            let operand = parts.next()?;
            satisfies_comparator(v, &format!("{part}{operand}"))
        } else {
            satisfies_comparator(v, part)
        };
        // Even a nonmatching comparator must not hide a later syntax error.
        matches_all &= matched?;
    }
    Some(matches_all)
}

fn satisfies_comparator(v: &Version, comp: &str) -> Option<bool> {
    let (op, ver_str) = if let Some(r) = comp.strip_prefix(">=") {
        (">=", r)
    } else if let Some(r) = comp.strip_prefix("<=") {
        ("<=", r)
    } else if let Some(r) = comp.strip_prefix('>') {
        (">", r)
    } else if let Some(r) = comp.strip_prefix('<') {
        ("<", r)
    } else if let Some(r) = comp.strip_prefix('=') {
        ("=", r)
    } else if let Some(r) = comp.strip_prefix('^') {
        ("^", r)
    } else if let Some(r) = comp.strip_prefix('~') {
        ("~", r)
    } else {
        ("", comp)
    };
    let c = parse_partial(ver_str)?;
    Some(match op {
        "^" => caret_match(v, ver_str),
        "~" => tilde_match(v, ver_str),
        _ => partial_comparator(v, op, &c),
    })
}

struct PartialVersion {
    version: Version,
    precision: usize,
}

fn parse_partial(s: &str) -> Option<PartialVersion> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let core = s.split(['-', '+']).next()?;
    let segments: Vec<_> = core.split('.').collect();
    if segments.len() > 3 {
        return None;
    }
    let mut numbers = [0; 3];
    let mut precision = segments.len();
    for (index, segment) in segments.iter().enumerate() {
        if matches!(*segment, "x" | "X" | "*") {
            precision = precision.min(index);
        } else {
            let number = parse_number(segment)?;
            if index < precision {
                numbers[index] = number;
            }
        }
    }
    let version = if precision == 3 {
        parse_version(s)?
    } else {
        if s.contains(['-', '+']) {
            return None;
        }
        Version {
            major: numbers[0],
            minor: numbers[1],
            patch: numbers[2],
            pre: vec![],
        }
    };
    Some(PartialVersion { version, precision })
}

fn next_release(version: &Version, precision: usize) -> Option<Version> {
    let (major, minor, patch) = match precision {
        1 => (version.major.checked_add(1)?, 0, 0),
        2 => (version.major, version.minor.checked_add(1)?, 0),
        3 => (version.major, version.minor, version.patch.checked_add(1)?),
        _ => return None,
    };
    Some(Version {
        major,
        minor,
        patch,
        pre: vec![],
    })
}

fn below_next(v: &Version, version: &Version, precision: usize) -> bool {
    next_release(version, precision).is_some_and(|mut upper| {
        // Expanded exclusive upper bounds must also exclude prereleases of
        // the next tuple, even when another comparator opts into that tuple.
        upper.pre = vec![PrePart::Num(0)];
        v < &upper
    })
}

fn partial_comparator(v: &Version, op: &str, c: &PartialVersion) -> bool {
    if c.precision == 0 {
        return matches!(op, "" | "=" | ">=" | "<=");
    }
    let lower = &c.version;
    match op {
        "" | "=" if c.precision < 3 => v >= lower && below_next(v, lower, c.precision),
        "" | "=" => v == lower,
        ">=" => v >= lower,
        "<=" if c.precision < 3 => below_next(v, lower, c.precision),
        "<=" => v <= lower,
        ">" if c.precision < 3 => next_release(lower, c.precision).is_some_and(|upper| v >= &upper),
        ">" => v > lower,
        "<" if c.precision < 3 => {
            let mut upper = lower.clone();
            upper.pre = vec![PrePart::Num(0)];
            v < &upper
        }
        "<" => v < lower,
        _ => false,
    }
}

/// Conservative compatibility wrapper: an uninterpretable range is not clean.
/// Call `evaluate_osv_range` when the caller can report an explicit unknown.
pub fn in_osv_range(version: &str, events: &[(String, String)]) -> bool {
    evaluate_osv_range(version, events) != Some(false)
}

/// OSV numeric npm evaluation. `None` means non-evaluable, never unaffected.
/// Status events are sorted by version; introduced="0" precedes prereleases.
/// Fixed bounds are exclusive, last_affected inclusive, limits an independent OR.
pub fn evaluate_osv_range(version: &str, events: &[(String, String)]) -> Option<bool> {
    let v = parse_osv_ecosystem_version(version)?;
    let has = |kind: &str| events.iter().any(|(key, _)| key == kind);
    if !has("introduced") || (has("fixed") && has("last_affected")) {
        return None;
    }
    // Parse every operand before any OR/limit shortcut can conceal an unknown.
    let parsed = events
        .iter()
        .map(|(kind, value)| {
            if !matches!(
                kind.as_str(),
                "introduced" | "fixed" | "last_affected" | "limit"
            ) {
                return None;
            }
            let bound =
                if kind == "introduced" && value == "0" || kind == "limit" && value.contains('*') {
                    None // sentinel or infinity, according to the event kind
                } else {
                    Some(parse_osv_ecosystem_version(value)?)
                };
            Some((kind.as_str(), bound))
        })
        .collect::<Option<Vec<_>>>()?;
    let limits: Vec<_> = parsed.iter().filter(|(kind, _)| *kind == "limit").collect();
    if !limits.is_empty()
        && !limits
            .iter()
            .any(|(_, bound)| bound.as_ref().is_none_or(|limit| &v < limit))
    {
        return Some(false);
    }
    let mut status_events: Vec<_> = parsed
        .into_iter()
        .filter(|(kind, _)| *kind != "limit")
        .collect();
    // Introductions precede equal closing events: fixed remains exclusive.
    status_events.sort_by(|(a_kind, a), (b_kind, b)| {
        a.cmp(b)
            .then_with(|| (a_kind != &"introduced").cmp(&(b_kind != &"introduced")))
    });
    let mut vulnerable = false;
    for (kind, bound) in status_events {
        match kind {
            "introduced" if bound.as_ref().is_none_or(|bound| &v >= bound) => vulnerable = true,
            "fixed" if bound.as_ref().is_some_and(|bound| &v >= bound) => vulnerable = false,
            "last_affected" if bound.as_ref().is_some_and(|bound| &v > bound) => vulnerable = false,
            _ => {}
        }
    }
    Some(vulnerable)
}

/// ^1.2.3 := >=1.2.3 <2.0.0 ; ^0.2.3 := >=0.2.3 <0.3.0 ; ^0.0.3 := >=0.0.3 <0.0.4
fn caret_match(v: &Version, r: &str) -> bool {
    let Some(c) = parse_partial(r) else {
        return false;
    };
    if c.precision == 0 {
        return true;
    }
    if v < &c.version {
        return false;
    }
    let precision = if c.version.major > 0 || c.precision == 1 {
        1
    } else if c.version.minor > 0 || c.precision == 2 {
        2
    } else {
        3
    };
    below_next(v, &c.version, precision)
}

/// ~1.2.3 := >=1.2.3 <1.3.0 ; ~1.2 := >=1.2.0 <1.3.0 ; ~1 := >=1.0.0 <2.0.0
fn tilde_match(v: &Version, r: &str) -> bool {
    let Some(c) = parse_partial(r) else {
        return false;
    };
    if c.precision == 0 {
        return true;
    }
    if v < &c.version {
        return false;
    }
    below_next(v, &c.version, c.precision.min(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_osv_calendar_bounds_use_separate_numeric_interpretation() {
        // Synthetic OSV ECOSYSTEM timeline, not a copied official advisory.
        let events = vec![
            ("introduced".into(), "2026.03.1".into()),
            ("fixed".into(), "2026.04.1".into()),
        ];
        for (version, expected) in [
            ("2026.3.0", false),
            ("2026.3.1", true),
            ("2026.4.0", true),
            ("2026.4.1-beta.1", true),
            ("2026.4.1", false),
            ("2026.4.2", false),
        ] {
            assert_eq!(in_osv_range(version, &events), expected, "{version}");
        }
        assert!(parse_version("2026.04.1").is_none());
        assert!(!is_valid_version("2026.04.1"));
        assert!(!satisfies("2026.4.1", "2026.04.1"));
        assert_eq!(events[1].1, "2026.04.1");
    }

    #[test]
    fn synthetic_unevaluable_osv_ranges_never_return_false_clean() {
        for events in [
            vec![("introduced".into(), "release-one".into())],
            vec![
                ("introduced".into(), "0".into()),
                ("limit".into(), "release-two".into()),
            ],
            vec![
                ("introduced".into(), "0".into()),
                ("fixed".into(), "18446744073709551616.0.0".into()),
            ],
        ] {
            assert!(
                in_osv_range("1.0.0", &events),
                "unknown cannot be clean: {events:?}"
            );
        }
    }

    #[test]
    fn package_versions_are_exact_while_numeric_range_bounds_can_be_partial() {
        assert!(!is_valid_version("13"));
        assert!(!is_valid_version("13.0"));
        assert!(is_valid_version("13.0.0"));
        assert!(parse_version("13.0").is_some());
        let events = vec![
            ("introduced".into(), "13.0".into()),
            ("limit".into(), "14.2.30".into()),
        ];
        assert!(in_osv_range("13.0.1", &events));
        assert!(!in_osv_range("14.2.30", &events));
    }

    #[test]
    fn version_parse_and_order() {
        assert!(parse_version("1.2.3").is_some());
        assert!(parse_version("1.2.3-alpha.1").is_some());
        assert!(parse_version("not-a-version").is_none());
        assert!(parse_version("1.2.3") < parse_version("1.2.4"));
        assert!(parse_version("1.2.3-alpha") < parse_version("1.2.3"));
        assert!(parse_version("1.0.0-alpha") < parse_version("1.0.0-alpha.1"));
        assert!(parse_version("1.0.0-alpha.1") < parse_version("1.0.0-alpha.beta"));
    }

    #[test]
    fn range_satisfaction_npm() {
        assert!(satisfies("3.22.4", "^3.22.0"));
        assert!(!satisfies("3.22.4", "^4.0.0"));
        assert!(satisfies("1.2.3", "~1.2.0"));
        assert!(!satisfies("1.3.0", "~1.2.0"));
        assert!(satisfies("1.5.0", "1.x"));
        assert!(satisfies("1.2.3", "1.2.3 - 2.0.0"));
        assert!(!satisfies("2.0.1", "1.2.3 - 2.0.0"));
        assert!(satisfies("1.2.3", ">=1.0.0 <2.0.0"));
        assert!(satisfies("1.2.3", "^1.0.0 || ^2.0.0"));
        assert!(satisfies("2.0.0", "^1.0.0 || ^2.0.0"));
        assert!(satisfies("2.0.0", "^2.0.0"));
        assert!(!satisfies("1.0.0-alpha", "^1.0.0")); // prerelease not matched by release range
        assert!(satisfies("1.0.0-alpha", ">=1.0.0-alpha <1.0.0"));
    }

    #[test]
    fn npm_tilde_partial_stays_in_its_minor() {
        assert!(!satisfies("1.3.0", "~1.2"));
        assert!(satisfies("1.2.5", "~1.2"));
        assert!(!satisfies("1.1.9", "~1.2"));
        assert!(satisfies("1.9.9", "~1"));
        assert!(!satisfies("2.0.0", "~1"));
    }

    #[test]
    fn npm_partial_versions_are_x_ranges() {
        assert!(satisfies("1.2.5", "1.2"));
        assert!(satisfies("1.2.5", "=1.2"));
        assert!(satisfies("1.9.9", "1"));
        assert!(!satisfies("1.3.0", "1.2"));
        assert!(!satisfies("2.0.0", "1"));
        assert!(satisfies("1.2.5", "1.2.X"));
    }

    #[test]
    fn npm_malformed_tokens_never_become_wildcards() {
        let invalid = [
            "xgarbage",
            "1.xgarbage",
            "1.2.garbage",
            "1..x",
            "1.2.3.4",
            ">=",
            "=",
            "latest",
            "1.02.x",
            "1.*junk",
            "1.2.3-",
            "1.2.3-01",
            "1.2.3+",
            "^1.2.3-",
            "~1.2.3+",
        ];
        let accepted: Vec<_> = invalid
            .into_iter()
            .filter(|range| satisfies("1.2.3", range))
            .collect();
        assert!(accepted.is_empty(), "invalid ranges accepted: {accepted:?}");
        assert!(!satisfies("1.0.0-alpha", "1.0.0-exp"));
        assert!(satisfies("1.0.0-exp", "1.0.0-exp"));
        assert!(satisfies("1.2.3", "1.2.3+build-x"));
        assert!(satisfies("1.2.3", "v1.2.3"));
        assert!(satisfies("1.2.3", "*"));
        assert!(satisfies("1.2.3", "X"));
    }

    #[test]
    fn npm_invalid_comparator_set_is_not_rescued_by_an_or_branch() {
        for range in [
            "xgarbage || *",
            "* || xgarbage",
            ">=2.0.0 xgarbage || *",
            "1..x || ^1",
            "* || >=",
        ] {
            assert!(!satisfies("1.2.3", range), "{range}");
        }
        assert!(satisfies("1.2.3", "^2 || ^1"));
        assert!(satisfies("1.2.3", " || ^2"));
    }

    #[test]
    fn npm_advanced_partial_ranges_follow_documented_expansion() {
        let cases = [
            ("1.2.5", ">=1.2", true),
            ("1.2.5", "<=1.2", true),
            ("1.3.0", "<=1.2", false),
            ("1.2.5", ">1.2", false),
            ("1.3.0", ">1.2", true),
            ("1.2.5", "<1.2", false),
            ("1.9.0", ">=1.x", true),
            ("2.0.0", "<=1.x", false),
            ("2.3.9", "1.2 - 2.3", true),
            ("2.4.0", "1.2 - 2.3", false),
            ("2.9.0", "1.2.3 - 2", true),
            ("3.0.0", "1.2.3 - 2", false),
            ("0.0.9", "^0.0", true),
            ("0.1.0", "^0.0", false),
            ("0.9.0", "^0", true),
            ("1.0.0", "^0", false),
            ("1.9.0", "^1.x", true),
            ("2.0.0", "^1.x", false),
            ("1.2.9", "~1.2.x", true),
            ("1.3.0", "~1.2.x", false),
            ("1.2.5", ">= 1.2 < 2", true),
            ("1.2.5", "~ 1.2", true),
        ];
        let mismatches: Vec<_> = cases
            .into_iter()
            .filter(|(v, r, expected)| satisfies(v, r) != *expected)
            .collect();
        assert!(
            mismatches.is_empty(),
            "npm expansion mismatches: {mismatches:?}"
        );
        for range in [
            "^18446744073709551615.0.0",
            "~1.18446744073709551615.0",
            "^0.0.18446744073709551615",
        ] {
            assert!(!satisfies("1.2.3", range), "{range}");
        }
    }

    #[test]
    fn npm_prerelease_opt_in_is_per_comparator_set_and_tuple() {
        assert!(!satisfies("1.1.0-beta.1", "^1.0.0"));
        for range in [
            "*",
            "x",
            "",
            "1",
            "1.x",
            "~1.0",
            ">=1.0.0 <2.0.0",
            "1.0.0 - 2.0.0",
        ] {
            assert!(!satisfies("1.1.0-beta.1", range), "{range}");
        }
        assert!(satisfies("1.1.0-beta.2", ">=1.1.0-beta.1 <2.0.0"));
        assert!(satisfies("1.1.0-beta.2", "^1.1.0-beta.1"));
        assert!(!satisfies("1.2.0-beta.2", "^1.1.0-beta.1"));
        assert!(!satisfies("1.1.0-beta.2", ">=1.0.0-alpha <2.0.0 || ^1.1.0"));
        assert!(!satisfies(
            "1.1.0-beta.2",
            ">=1.1.0-beta.1 <1.1.0-beta.2 || ^1.0.0"
        ));
        assert!(satisfies("1.1.0-beta.2", "^2.0.0 || >=1.1.0-beta.1 <2.0.0"));
        assert!(satisfies("1.1.0", "^1.0.0"));
        assert!(satisfies("1.0.0-exp", "1.0.0-exp"));
    }

    #[test]
    fn osv_reintroduced_intervals_are_a_union() {
        let open = vec![
            ("introduced".into(), "1.0.0".into()),
            ("fixed".into(), "2.0.0".into()),
            ("introduced".into(), "3.0.0".into()),
        ];
        assert!(in_osv_range("3.5.0", &open));
        assert!(in_osv_range("1.5.0", &open));
        assert!(!in_osv_range("2.5.0", &open));
        let mut closed = open;
        closed.push(("fixed".into(), "4.0.0".into()));
        for (version, affected) in [
            ("0.9.0", false),
            ("1.0.0", true),
            ("1.9.9", true),
            ("2.0.0", false),
            ("2.5.0", false),
            ("3.0.0", true),
            ("3.5.0", true),
            ("4.0.0", false),
        ] {
            assert_eq!(in_osv_range(version, &closed), affected, "{version}");
        }
        // A last_affected timeline must not retain a fixed event from the
        // preceding fixture: OSV forbids mixing these closing types.
        let inclusive = vec![
            ("introduced".into(), "1.0.0".into()),
            ("last_affected".into(), "2.0.0".into()),
            ("introduced".into(), "3.0.0".into()),
            ("last_affected".into(), "4.0.0".into()),
        ];
        assert!(in_osv_range("2.0.0", &inclusive));
        assert!(!in_osv_range("2.0.1", &inclusive));
        assert!(in_osv_range("4.0.0", &inclusive));
        assert!(!in_osv_range("4.0.1", &inclusive));
        assert!(!in_osv_range("2.5.0", &inclusive));
    }

    #[test]
    fn late_osv_every_permutation_preserves_numeric_status_and_limit_semantics() {
        // Synthetic normative truth table: two intervals, capped globally at 11.
        let mut events: Vec<(String, String)> = [
            ("introduced", "0"),
            ("fixed", "2.0.0"),
            ("introduced", "9.0.0"),
            ("fixed", "12.0.0"),
            ("limit", "11.0.0"),
        ]
        .into_iter()
        .map(|(kind, value)| (kind.into(), value.into()))
        .collect();
        fn permutations(events: &mut [(String, String)], index: usize, checked: &mut usize) {
            if index == events.len() {
                for (version, expected) in [
                    ("0.0.0-alpha", true),
                    ("1.9.9", true),
                    ("2.0.0", false),
                    ("8.9.9", false),
                    ("9.0.0", true),
                    ("10.0.0", true),
                    ("11.0.0-alpha", true),
                    ("11.0.0", false),
                    ("12.0.0", false),
                ] {
                    assert_eq!(
                        in_osv_range(version, events),
                        expected,
                        "synthetic {version}: {events:?}"
                    );
                }
                *checked += 1;
                return;
            }
            for next in index..events.len() {
                events.swap(index, next);
                permutations(events, index + 1, checked);
                events.swap(index, next);
            }
        }
        let mut checked = 0;
        permutations(&mut events, 0, &mut checked);
        assert_eq!(checked, 120);
    }

    #[test]
    fn late_osv_prerelease_build_metadata_and_equal_endpoints() {
        let events = vec![
            ("fixed".into(), "1.0.0-beta.2+build".into()),
            ("introduced".into(), "1.0.0-alpha".into()),
        ];
        assert!(in_osv_range("1.0.0-beta.1", &events));
        assert!(!in_osv_range("1.0.0-beta.2+other", &events));
        for events in [
            vec![
                ("fixed".into(), "1.0.0".into()),
                ("introduced".into(), "1.0.0".into()),
            ],
            vec![
                ("introduced".into(), "1.0.0".into()),
                ("fixed".into(), "1.0.0".into()),
            ],
        ] {
            assert!(!in_osv_range("1.0.0", &events));
        }
    }

    #[test]
    fn osv_ranges() {
        let ev = vec![
            ("introduced".to_string(), "0".to_string()),
            ("fixed".to_string(), "3.22.5".to_string()),
        ];
        assert!(in_osv_range("3.22.4", &ev));
        assert!(!in_osv_range("3.22.5", &ev));
        let ev2 = vec![
            ("introduced".to_string(), "1.0.0".to_string()),
            ("last_affected".to_string(), "1.2.0".to_string()),
        ];
        assert!(in_osv_range("1.2.0", &ev2));
        assert!(!in_osv_range("1.2.1", &ev2));
        assert!(!in_osv_range("0.9.0", &ev2));
    }
}
