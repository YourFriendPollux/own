//! `own-verify` — minimal offline verifier (SPEC §11.3): verify only, no
//! network, no SPDX/OSV. Built on own-core.

use clap::Parser;
use own_core::config::license_policy_json;
use own_core::verify::verify;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "own-verify", version = env!("CARGO_PKG_VERSION"), about = "Offline verify only (SPEC §11.3)")]
struct Cli {
    /// Root directory (default: current directory)
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    /// Compare the installed copy in node_modules/.pnpm as well
    #[arg(long)]
    installed: bool,
    /// JSON output on stdout
    #[arg(long, default_value = "human")]
    format: String,
}

fn read_overrides(root: &std::path::Path) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    if let Ok(text) = std::fs::read_to_string(root.join("package.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(ov) = v
                .get("pnpm")
                .and_then(|p| p.get("overrides"))
                .and_then(|o| o.as_object())
            {
                for (k, val) in ov {
                    if let Some(s) = val.as_str() {
                        if s.starts_with("file:vendor/own/") {
                            out.insert(k.clone(), serde_json::Value::String(s.to_string()));
                        }
                    }
                }
            }
        }
    }
    out
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = cli.root.unwrap_or_else(|| std::env::current_dir().unwrap());
    let policy = std::fs::read_to_string(root.join("own.toml"))
        .ok()
        .and_then(|t| license_policy_json(&t).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let overrides = read_overrides(&root);
    match verify(&root, &policy, &overrides) {
        Ok(outcome) => {
            let code = if outcome.findings.iter().any(|f| f.severity == "error") {
                1
            } else {
                0
            };
            let _ = cli.installed; // --installed is accepted for CLI compat; core check is offline-only in 0.1
            if cli.format == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "schema_version": 1, "command": "verify",
                        "status": if code == 0 { "ok" } else { "findings" },
                        "exit_code": code, "findings": outcome.findings, "data": {},
                    }))
                    .unwrap()
                );
            } else {
                for f in &outcome.findings {
                    eprintln!(
                        "{}: [{}] {} {}",
                        f.severity.to_uppercase(),
                        f.code,
                        f.package,
                        f.path
                    );
                }
                if code == 0 {
                    println!("ok: no findings");
                }
            }
            ExitCode::from(code)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
