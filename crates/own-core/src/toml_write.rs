//! Canonical TOML writer for `own.lock` and manifests (SPEC §7.1, §7.2, ADR 0002).
//!
//! Normative layout:
//! - sections in order: `[metadata]`, all `[[package]]`, all `[[decision]]`;
//!   one blank line between sections; no trailing whitespace;
//! - `[[package]]` sorted by `(name, version)` byte-wise; same for `[[decision]]`;
//! - keys in the exact order of SPEC §7.1; absent optional keys omitted;
//! - strings in TOML basic syntax with escapes `\\`, `\"`, `\b`, `\t`, `\n`, `\f`,
//!   `\r`, other controls as `\u00XX`; non-ASCII written as-is (UTF-8);
//! - arrays on one line `["a", "b"]`, empty `[]`; inline tables
//!   `[{ path = "a", sha256 = "..." }]`;
//! - no comments, no timestamps; file ends with a single `\n`.

/// Escape a string into TOML basic-string form (without surrounding quotes).
pub fn escape_basic(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub fn basic_string(s: &str) -> String {
    format!("\"{}\"", escape_basic(s))
}

/// A writer for one TOML document. Sections are emitted in insertion order;
/// callers must add them in the normative order.
#[derive(Default)]
pub struct TomlWriter {
    buf: String,
}

impl TomlWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn section(&mut self, header: &str) -> &mut Self {
        if !self.buf.is_empty() {
            self.buf.push('\n');
        }
        self.buf.push_str(header);
        self.buf.push('\n');
        self
    }

    pub fn key_value(&mut self, key: &str, value: &str) -> &mut Self {
        self.buf.push_str(key);
        self.buf.push_str(" = ");
        self.buf.push_str(value);
        self.buf.push('\n');
        self
    }

    pub fn key_string(&mut self, key: &str, value: &str) -> &mut Self {
        self.key_value(key, &basic_string(value))
    }

    pub fn key_int(&mut self, key: &str, value: u64) -> &mut Self {
        self.key_value(key, &value.to_string())
    }

    /// Inline string array: `["a", "b"]`.
    pub fn key_str_array(&mut self, key: &str, values: &[String]) -> &mut Self {
        let inner: Vec<String> = values.iter().map(|v| basic_string(v)).collect();
        self.key_value(key, &format!("[{}]", inner.join(", ")))
    }

    pub fn finish(self) -> String {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_inv10() {
        assert_eq!(escape_basic("a\"b\\c\nd\u{01}e"), "a\\\"b\\\\c\\nd\\u0001e");
        assert_eq!(basic_string("héllo"), "\"héllo\"");
    }

    #[test]
    fn writer_layout_inv10() {
        let mut w = TomlWriter::new();
        w.section("[metadata]")
            .key_string("schema_version_marker", "x")
            .key_int("schema_version", 1);
        w.section("[[package]]").key_string("name", "zod");
        let out = w.finish();
        assert_eq!(
            out,
            "[metadata]\nschema_version_marker = \"x\"\nschema_version = 1\n\n[[package]]\nname = \"zod\"\n"
        );
    }
}
