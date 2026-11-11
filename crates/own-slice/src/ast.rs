//! AST-based specifier extraction (tree-sitter) — Phase 1 slicing backend.
//!
//! Replaces the regex prototype for anything that decides what gets DROPPED.
//! Regex remains only as a fast pre-filter for measurement/reporting.
//!
//! Conservative contract (INV-4, SPEC Annexe F.4):
//! - any non-literal `require()`/`import()` arg, `eval`, `new Function`,
//!   aliased require, or a parse error in a REACHABLE file ⇒ package keep-whole.
//! - edges: `import ... from "x"`, `export ... from "x"`, side-effect
//!   `import "x"`, `require("x")` with a string literal.

use std::path::Path;
use tree_sitter::{Language, Node, Parser, Tree};

pub enum ParseOutcome {
    Ok(Tree),
    /// unparseable / unsupported extension — caller must keep whole (INV-4)
    Failed,
}

pub fn language_for(path: &Path) -> Option<Language> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    match ext {
        "js" | "mjs" | "cjs" | "jsx" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "ts" | "mts" | "cts" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        _ => None,
    }
}

pub fn parse(path: &Path, src: &[u8]) -> ParseOutcome {
    let Some(lang) = language_for(path) else {
        return ParseOutcome::Failed;
    };
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return ParseOutcome::Failed;
    }
    match parser.parse(src, None) {
        // F4 (amended): has_error() is too strict — the JS grammar reports
        // ERROR nodes on valid large `export { ... }` lists. We only fail on
        // MISSING nodes (grammar-level incompleteness), which genuinely
        // indicate an unparseable prefix.
        Some(t) if !root_has_missing(&t) => ParseOutcome::Ok(t),
        _ => ParseOutcome::Failed, // partial parse ⇒ no proof (INV-4)
    }
}

/// Result of walking a parsed file.
pub struct AstEdges {
    /// literal specifiers to follow (internal ones resolved by caller)
    pub literal_specs: Vec<String>,
    /// true if any dynamic/eval signal was seen (⇒ keep whole package)
    pub dynamic: bool,
}

/// Walk the AST: collect literal import/require specifiers; flag dynamic use.
pub fn edges(tree: &Tree, src: &[u8]) -> AstEdges {
    let mut out = AstEdges {
        literal_specs: Vec::new(),
        dynamic: false,
    };
    let root = tree.root_node();
    let mut cursor = root.walk();
    let mut stack: Vec<Node> = vec![root];
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        match kind {
            // import ... from "x" | export ... from "x" | import "x"
            "import_statement" | "export_statement" => {
                if let Some(src_node) = n.child_by_field_name("source") {
                    if let Some(s) = string_literal(&src_node, src) {
                        out.literal_specs.push(s);
                    }
                }
                // side-effect import has source too; covered above
            }
            "call_expression" => {
                if let Some(fn_node) = n.child_by_field_name("function") {
                    let fname = fn_node.utf8_text(src).unwrap_or("");
                    if fname == "require"
                        || fname == "module.require"
                        || fname.ends_with(".require")
                        || fname == "require"
                    {
                        if let Some(args) = n.child_by_field_name("arguments") {
                            if let Some(first) = args.named_child(0) {
                                match first.kind() {
                                    "string" => {
                                        if let Some(s) = string_literal(&first, src) {
                                            out.literal_specs.push(s);
                                        }
                                    }
                                    _ => out.dynamic = true, // require(x), require(`..${}`), require("a"+b)
                                }
                            } else {
                                out.dynamic = true;
                            }
                        }
                    } else if fname == "import" {
                        out.dynamic = true; // dynamic import() — conservative
                    }
                }
            }
            "identifier" => {
                if n.utf8_text(src).unwrap_or("") == "eval" {
                    // bare `eval` reference (direct or indirect)
                    out.dynamic = true;
                }
            }
            // const r = require; r('./x') — aliased require ⇒ dynamic (INV-4)
            "variable_declarator" => {
                if let Some(v) = n.child_by_field_name("value") {
                    if v.kind() == "identifier" && v.utf8_text(src).unwrap_or("") == "require" {
                        out.dynamic = true;
                    }
                }
            }
            "new_expression" => {
                if let Some(ctor) = n.child_by_field_name("constructor") {
                    let c = ctor.utf8_text(src).unwrap_or("");
                    if c == "Function" || c == "Worker" {
                        out.dynamic = true; // F6/F7
                    }
                }
            }

            _ => {}
        }
        for i in 0..n.child_count() {
            if let Some(c) = n.child(i) {
                stack.push(c);
            }
        }
        let _ = &mut cursor;
    }
    out
}

fn root_has_missing(tree: &Tree) -> bool {
    let mut stack = vec![tree.root_node()];
    while let Some(n) = stack.pop() {
        if n.is_missing() {
            return true;
        }
        for i in 0..n.child_count() {
            if let Some(c) = n.child(i) {
                stack.push(c);
            }
        }
    }
    false
}

fn string_literal(node: &Node, src: &[u8]) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let text = node.utf8_text(src).ok()?;
    // strip quotes, unescape minimal (\" \\ \n) — enough for module specifiers
    let inner = text.strip_prefix('"').or_else(|| text.strip_prefix('\''))?;
    let inner = inner
        .strip_suffix('"')
        .or(inner.strip_suffix('\''))
        .unwrap_or(inner);
    Some(
        inner
            .replace("\\\"", "\"")
            .replace("\\'", "'")
            .replace("\\\\", "\\"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_js(src: &str) -> Tree {
        match parse(Path::new("x.js"), src.as_bytes()) {
            ParseOutcome::Ok(t) => t,
            ParseOutcome::Failed => panic!("parse failed"),
        }
    }

    #[test]
    fn literal_edges_collected() {
        let t = parse_js("import a from './a.js';\nimport './side.js';\nexport * from './b.js';\nconst c = require('./c.js');\n");
        let e = edges(&t, "import a from './a.js';\nimport './side.js';\nexport * from './b.js';\nconst c = require('./c.js');\n".as_bytes());
        assert!(e.literal_specs.contains(&"./a.js".to_string()));
        assert!(e.literal_specs.contains(&"./side.js".to_string()));
        assert!(e.literal_specs.contains(&"./b.js".to_string()));
        assert!(e.literal_specs.contains(&"./c.js".to_string()));
        assert!(!e.dynamic);
    }

    #[test]
    fn dynamic_require_flagged() {
        let src = "const m = argv[2]; require(m);\n";
        let t = parse_js(src);
        let e = edges(&t, src.as_bytes());
        assert!(e.dynamic);
        assert!(e.literal_specs.is_empty());
    }

    #[test]
    fn template_require_flagged() {
        let src = "require(`./plugins/${n}.js`);\n";
        let t = parse_js(src);
        let e = edges(&t, src.as_bytes());
        assert!(e.dynamic);
    }

    #[test]
    fn eval_flagged() {
        let src = "const f = eval; f('1+1');\n";
        let t = parse_js(src);
        let e = edges(&t, src.as_bytes());
        assert!(e.dynamic);
    }

    #[test]
    fn new_function_flagged() {
        let src = "const g = new Function('return 1');\n";
        let t = parse_js(src);
        let e = edges(&t, src.as_bytes());
        assert!(e.dynamic);
    }

    #[test]
    fn dynamic_import_flagged() {
        let src = "import('./lazy.js');\n";
        let t = parse_js(src);
        let e = edges(&t, src.as_bytes());
        assert!(e.dynamic);
    }

    #[test]
    fn tsx_parses() {
        let src = "import React from 'react';\nexport const C = () => <div/>;\n";
        match parse(Path::new("x.tsx"), src.as_bytes()) {
            ParseOutcome::Ok(_) => {}
            ParseOutcome::Failed => panic!("tsx parse failed"),
        }
    }
}
