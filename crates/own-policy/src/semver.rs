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
    parse_version(s).is_some()
}

pub fn parse_version(s: &str) -> Option<Version> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    // patch may carry build metadata after '+' — but version_format refuses '+'
    let patch_str = parts.next().unwrap_or("0");
    let patch: u64 = patch_str.split('+').next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let pre = match pre {
        None => Vec::new(),
        Some(p) => p
            .split('.')
            .map(|part| {
                if let Ok(n) = part.parse::<u64>() {
                    PrePart::Num(n)
                } else {
                    PrePart::Str(part.to_string())
                }
            })
            .collect(),
    };
    Some(Version {
        major,
        minor,
        patch,
        pre,
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
    range.split("||").any(|alt| satisfies_and(&v, alt.trim()))
}

fn satisfies_and(v: &Version, range: &str) -> bool {
    let range = range.trim();
    if range.is_empty() || range == "*" || range == "x" || range == "latest" {
        return true;
    }
    // hyphen range: "1.2.3 - 2.3.4"
    if let Some((lo, hi)) = range.split_once(" - ") {
        if let (Some(lo), Some(hi)) = (parse_version(lo.trim()), parse_version(hi.trim())) {
            return v.compare_to(&lo) != std::cmp::Ordering::Less
                && v.compare_to(&hi) != std::cmp::Ordering::Greater;
        }
    }
    // partial versions like 1.2.x / 1.x
    let parts: Vec<&str> = range.split_whitespace().collect();
    parts.iter().all(|p| satisfies_comparator(v, p))
}

fn satisfies_comparator(v: &Version, comp: &str) -> bool {
    use std::cmp::Ordering::*;
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
    } else {
        ("", comp)
    };
    // caret / tilde ranges
    if op.is_empty() {
        if let Some(r) = ver_str.strip_prefix('^') {
            return caret_match(v, r);
        }
        if let Some(r) = ver_str.strip_prefix('~') {
            return tilde_match(v, r);
        }
    }
    // wildcard handling: 1.2.x, 1.x, *
    if ver_str.contains('x') || ver_str.contains('*') || ver_str.is_empty() {
        return wildcard_match(
            v,
            if op.is_empty() {
                ver_str
            } else {
                return false_or(v, op, ver_str);
            },
        );
    }
    let Some(c) = parse_version(ver_str) else {
        return false;
    };
    match op {
        ">=" => v.compare_to(&c) != Less,
        "<=" => v.compare_to(&c) != Greater,
        ">" => v.compare_to(&c) == Greater,
        "<" => v.compare_to(&c) == Less,
        "=" | "" => {
            // npm: a prerelease version only satisfies a comparator that explicitly
            // mentions a prerelease of the same [major,minor,patch]
            if !v.pre.is_empty() && c.pre.is_empty() {
                return false;
            }
            v.compare_to(&c) == Equal
        }
        _ => false,
    }
}

fn false_or(_v: &Version, _op: &str, _s: &str) -> bool {
    false
}

fn wildcard_match(v: &Version, pat: &str) -> bool {
    let segs: Vec<&str> = pat.split('.').collect();
    let nums: Vec<Option<u64>> = segs
        .iter()
        .map(|s| {
            if *s == "x" || *s == "*" || s.is_empty() {
                None
            } else {
                s.parse::<u64>().ok()
            }
        })
        .collect();
    let get = |i: usize, cur: u64| nums.get(i).copied().flatten().unwrap_or(cur);
    if get(0, v.major) != v.major {
        return false;
    }
    if nums.len() > 1 && get(1, v.minor) != v.minor {
        return false;
    }
    if nums.len() > 2 && get(2, v.patch) != v.patch {
        return false;
    }
    true
}

/// OSV SEMVER/ECOSYSTEM range evaluation (SPEC §8.2): events introduced/fixed/
/// last_affected. `introduced: "0"` = from the beginning. `fixed` exclusive,
/// `last_affected` inclusive. GIT ranges ignored by caller.
pub fn in_osv_range(version: &str, events: &[(String, String)]) -> bool {
    // events: ("introduced"|"fixed"|"last_affected", value)
    let Some(v) = parse_version(version) else {
        return false;
    };
    let mut introduced = false;
    let mut upper: Option<(Version, bool)> = None; // (version, inclusive)
    for (kind, val) in events {
        match kind.as_str() {
            "introduced" => {
                if val == "0" {
                    introduced = true;
                } else if let Some(iv) = parse_version(val) {
                    if v.compare_to(&iv) != std::cmp::Ordering::Less {
                        introduced = true;
                    }
                }
            }
            "fixed" => {
                if let Some(fv) = parse_version(val) {
                    upper = Some((fv, false));
                }
            }
            "last_affected" => {
                if let Some(lv) = parse_version(val) {
                    upper = Some((lv, true));
                }
            }
            _ => {}
        }
    }
    if !introduced {
        return false;
    }
    match upper {
        None => true,
        Some((u, inclusive)) => {
            let ord = v.compare_to(&u);
            if inclusive {
                ord != std::cmp::Ordering::Greater
            } else {
                ord == std::cmp::Ordering::Less
            }
        }
    }
}

/// ^1.2.3 := >=1.2.3 <2.0.0 ; ^0.2.3 := >=0.2.3 <0.3.0 ; ^0.0.3 := >=0.0.3 <0.0.4
fn caret_match(v: &Version, r: &str) -> bool {
    let Some(c) = parse_version(r) else {
        return false;
    };
    if v.compare_to(&c) == std::cmp::Ordering::Less {
        return false;
    }
    let upper = if c.major > 0 {
        Version {
            major: c.major + 1,
            minor: 0,
            patch: 0,
            pre: vec![],
        }
    } else if c.minor > 0 {
        Version {
            major: 0,
            minor: c.minor + 1,
            patch: 0,
            pre: vec![],
        }
    } else {
        Version {
            major: 0,
            minor: 0,
            patch: c.patch + 1,
            pre: vec![],
        }
    };
    if !v.pre.is_empty()
        && c.pre.is_empty()
        && (v.major, v.minor, v.patch) == (c.major, c.minor, c.patch)
    {
        return false;
    }
    v.compare_to(&upper) == std::cmp::Ordering::Less
}

/// ~1.2.3 := >=1.2.3 <1.3.0 ; ~1.2 := >=1.2.0 <1.3.0 ; ~1 := >=1.0.0 <2.0.0
fn tilde_match(v: &Version, r: &str) -> bool {
    let Some(c) = parse_version(r) else {
        return false;
    };
    if v.compare_to(&c) == std::cmp::Ordering::Less {
        return false;
    }
    let segs: Vec<&str> = r.split('.').collect();
    let upper = if segs.len() >= 3 {
        Version {
            major: c.major,
            minor: c.minor + 1,
            patch: 0,
            pre: vec![],
        }
    } else {
        Version {
            major: c.major + 1,
            minor: 0,
            patch: 0,
            pre: vec![],
        }
    };
    v.compare_to(&upper) == std::cmp::Ordering::Less
}

#[cfg(test)]
mod tests {
    use super::*;

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
