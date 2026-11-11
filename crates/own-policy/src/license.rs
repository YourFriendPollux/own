//! SPDX license policy (SPEC §9.3, §7.4): strict SPDX parsing, pattern matching
//! (case-insensitive, `*` wildcard, anchored), class precedence deny > review > allow,
//! and expression evaluation with WITH > AND > OR precedence.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LicenseClass {
    Allow,
    Review,
    Deny,
}

#[derive(Debug, Clone)]
pub struct LicensePolicy {
    pub allow: Vec<String>,
    pub review: Vec<String>,
    pub deny: Vec<String>,
    pub unknown: String, // "deny" only in Phase 0
}

impl Default for LicensePolicy {
    fn default() -> Self {
        Self {
            allow: vec![
                "MIT".into(),
                "BSD-2-Clause".into(),
                "BSD-3-Clause".into(),
                "Apache-2.0".into(),
                "ISC".into(),
            ],
            review: vec![
                "LGPL-2.1-only".into(),
                "LGPL-3.0-only".into(),
                "MPL-2.0".into(),
            ],
            deny: vec![
                "GPL-*".into(),
                "AGPL-*".into(),
                "BSL-*".into(),
                "PolyForm-*".into(),
                "SSPL-*".into(),
                "Elastic-2.0".into(),
            ],
            unknown: "deny".into(),
        }
    }
}

/// Classify a single SPDX id against the policy lists (§7.4 pattern rules).
pub fn classify_id(id: &str, pol: &LicensePolicy) -> LicenseClass {
    let id_l = id.to_lowercase();
    let matches = |pat: &str| {
        let p = pat.to_lowercase();
        if let Some(prefix) = p.strip_suffix('*') {
            id_l.starts_with(prefix)
        } else {
            id_l == p
        }
    };
    if pol.deny.iter().any(|p| matches(p)) {
        LicenseClass::Deny
    } else if pol.review.iter().any(|p| matches(p)) {
        LicenseClass::Review
    } else if pol.allow.iter().any(|p| matches(p)) {
        LicenseClass::Allow
    } else {
        match pol.unknown.as_str() {
            "deny" => LicenseClass::Deny,
            "review" => LicenseClass::Review,
            _ => LicenseClass::Deny, // "allow" not permitted for unknown in Phase 0
        }
    }
}

/// Evaluate a full SPDX expression (§9.3): strict parse via the `spdx` crate
/// (postfix token stream), then fold per WITH > AND > OR precedence.
pub fn evaluate_expression(
    expr: &str,
    pol: &LicensePolicy,
) -> Result<(LicenseClass, Option<String>), String> {
    use spdx::expression::{ExprNode, Operator};
    let normalized = normalize_deprecated(expr);
    let parsed =
        spdx::Expression::parse(&normalized).map_err(|e| format!("LICENSE_UNPARSEABLE: {e}"))?;
    // postfix evaluation with an explicit stack; each item is (class, selected, with_flag)
    #[derive(Clone)]
    struct Item {
        class: LicenseClass,
        sel: Option<String>,
        with: bool,
    }
    let mut stack: Vec<Item> = Vec::new();
    for node in parsed.iter() {
        match node {
            ExprNode::Req(r) => {
                let (id, unknown) = match &r.req.license {
                    spdx::LicenseItem::Spdx { id, or_later } => {
                        let base = id.name;
                        // spdx normalizes "-only" away in Display but keeps full id in `name`;
                        // reconstruct the canonical full id: name is like "LGPL-2.1" for LGPL-2.1-only
                        let full = format!("{}", r.req.license);
                        let canonical = canonical_id(&full, *or_later);
                        let _ = base;
                        (canonical, false)
                    }
                    spdx::LicenseItem::Other { .. } => (String::new(), true),
                };
                let class = if unknown {
                    LicenseClass::Deny
                } else {
                    classify_id(&id, pol)
                };
                let with = r.req.exception.is_some();
                let sel = if class == LicenseClass::Allow {
                    Some(id.to_string())
                } else {
                    None
                };
                stack.push(Item { class, sel, with });
            }
            ExprNode::Op(Operator::And) => {
                let (b, a) = (stack.pop(), stack.pop());
                if let (Some(a), Some(b)) = (a, b) {
                    let class = if a.class == LicenseClass::Deny || b.class == LicenseClass::Deny {
                        LicenseClass::Deny
                    } else if a.class == LicenseClass::Allow && b.class == LicenseClass::Allow {
                        LicenseClass::Allow
                    } else {
                        LicenseClass::Review
                    };
                    stack.push(Item {
                        class,
                        sel: None,
                        with: a.with || b.with,
                    });
                }
            }
            ExprNode::Op(Operator::Or) => {
                let (b, a) = (stack.pop(), stack.pop());
                if let (Some(a), Some(b)) = (a, b) {
                    let class = *[a.class, b.class].iter().min().unwrap();
                    let sel = if class == LicenseClass::Allow {
                        let mut c: Vec<String> = [a.sel, b.sel].into_iter().flatten().collect();
                        c.sort();
                        c.first().cloned()
                    } else {
                        None
                    };
                    stack.push(Item {
                        class,
                        sel,
                        with: a.with || b.with,
                    });
                }
            }
        }
    }
    // WITH handling: any item flagged `with` forces Review unless the whole
    // expression string is in allow (§9.3)
    let mut item = stack.pop().unwrap_or(Item {
        class: LicenseClass::Deny,
        sel: None,
        with: false,
    });
    if item.with && item.class != LicenseClass::Deny {
        let full = expr.trim();
        if !pol.allow.iter().any(|p| p.eq_ignore_ascii_case(full)) {
            item.class = LicenseClass::Review;
            item.sel = None;
        }
    }
    Ok((item.class, item.sel))
}

/// Reconstruct the strict SPDX id from the crate's Display form, re-adding
/// `-only` / `-or-later` suffixes that Display strips (e.g. "LGPL-2.1" -> "LGPL-2.1-only").
fn canonical_id(display: &str, or_later: bool) -> String {
    let candidate_only = format!("{display}-only");
    if spdx::license_id(&candidate_only).is_some() {
        return candidate_only;
    }
    if or_later {
        let cand = format!("{display}-or-later");
        if spdx::license_id(&cand).is_some() {
            return cand;
        }
    }
    display.to_string()
}

/// Normalize deprecated SPDX ids (e.g. GPL-3.0+ -> GPL-3.0-or-later).
pub fn normalize_deprecated(expr: &str) -> String {
    let mut out = expr.to_string();
    for (old, new) in [
        ("GPL-1.0+", "GPL-1.0-or-later"),
        ("GPL-2.0+", "GPL-2.0-or-later"),
        ("GPL-3.0+", "GPL-3.0-or-later"),
        ("LGPL-2.0+", "LGPL-2.0-or-later"),
        ("LGPL-2.1+", "LGPL-2.1-or-later"),
        ("LGPL-3.0+", "LGPL-3.0-or-later"),
        ("AGPL-1.0+", "AGPL-1.0-or-later"),
        ("AGPL-3.0+", "AGPL-3.0-or-later"),
        ("GFDL-1.1+", "GFDL-1.1-or-later"),
        ("GFDL-1.2+", "GFDL-1.2-or-later"),
        ("GFDL-1.3+", "GFDL-1.3-or-later"),
    ] {
        // word-boundary replace
        out = out
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
            .map(|w| {
                if w == old.trim_end_matches('+') {
                    new.to_string()
                } else {
                    w.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        // simpler: direct replace when token matches
        out = out.replace(old, new);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_patterns() {
        let pol = LicensePolicy::default();
        assert_eq!(classify_id("MIT", &pol), LicenseClass::Allow);
        assert_eq!(classify_id("mit", &pol), LicenseClass::Allow);
        assert_eq!(classify_id("GPL-3.0-only", &pol), LicenseClass::Deny); // GPL-* matches
        assert_eq!(classify_id("LGPL-2.1-only", &pol), LicenseClass::Review); // not GPL-* (anchored)
        assert_eq!(classify_id("0BSD", &pol), LicenseClass::Deny); // unknown -> deny
        assert_eq!(classify_id("Apache-2.0", &pol), LicenseClass::Allow);
    }

    #[test]
    fn expression_or_picks_allow() {
        let pol = LicensePolicy::default();
        let (c, sel) = evaluate_expression("GPL-3.0-only OR MIT", &pol).unwrap();
        assert_eq!(c, LicenseClass::Allow);
        assert_eq!(sel.as_deref(), Some("MIT"));
    }

    #[test]
    fn expression_and_requires_all_allow() {
        let pol = LicensePolicy::default();
        let (c, _) = evaluate_expression("MIT AND LGPL-2.1-only", &pol).unwrap();
        assert_eq!(c, LicenseClass::Review);
        let (c2, _) = evaluate_expression("MIT AND GPL-3.0-only", &pol).unwrap();
        assert_eq!(c2, LicenseClass::Deny);
    }

    #[test]
    fn with_is_review_unless_allowed() {
        let pol = LicensePolicy::default();
        let (c, _) = evaluate_expression("Apache-2.0 WITH LLVM-exception", &pol).unwrap();
        assert_eq!(c, LicenseClass::Review);
    }

    #[test]
    fn unparseable_is_deny() {
        let pol = LicensePolicy::default();
        assert!(evaluate_expression("MIT/X11", &pol).is_err());
        // non-SPDX string -> unknown -> deny via classify path
        let (c, _) = evaluate_expression("BSD", &pol).unwrap_or((LicenseClass::Deny, None));
        assert_eq!(c, LicenseClass::Deny);
    }
}
