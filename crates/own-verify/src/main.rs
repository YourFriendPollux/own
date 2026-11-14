//! `own-verify` — minimal offline verifier (SPEC §11.3): verify only, no
//! network, no SPDX/OSV. Built on own-core.

use clap::Parser;
use own_core::config::license_policy_json;
use own_core::verify::{verify, verify_installed};
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

fn read_overrides(
    root: &std::path::Path,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let text = std::fs::read_to_string(root.join("package.json"))
        .map_err(|e| format!("IO_ERROR: package.json: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("PARSE_ERROR: package.json: {e}"))?;
    let object = v
        .as_object()
        .ok_or("PARSE_ERROR: package.json: expected an object")?;
    let mut out = serde_json::Map::new();
    if let Some(pnpm) = object.get("pnpm") {
        let pnpm = pnpm
            .as_object()
            .ok_or("PARSE_ERROR: package.json: pnpm must be an object")?;
        if let Some(overrides) = pnpm.get("overrides") {
            let overrides = overrides
                .as_object()
                .ok_or("PARSE_ERROR: package.json: pnpm.overrides must be an object")?;
            for (key, value) in overrides {
                let value = value.as_str().ok_or_else(|| {
                    format!("PARSE_ERROR: package.json: pnpm.overrides[{key:?}] must be a string")
                })?;
                if value.starts_with("file:vendor/own/") {
                    out.insert(key.clone(), serde_json::Value::String(value.to_string()));
                }
            }
        }
    }
    Ok(out)
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if !error.use_stderr() {
                error.exit();
            }
            let args: Vec<_> = std::env::args_os()
                .skip(1)
                .take_while(|arg| arg != "--")
                .collect();
            let json = args.iter().any(|arg| arg == "--format=json")
                || args
                    .windows(2)
                    .any(|pair| pair[0] == "--format" && pair[1] == "json");
            return report_error(json, &format!("USAGE_ERROR: {error}"));
        }
    };
    let root = cli.root.unwrap_or_else(|| std::env::current_dir().unwrap());
    let result = (|| {
        if cli.format != "human" && cli.format != "json" {
            return Err(format!(
                "USAGE_ERROR: --format must be human or json, got {:?}",
                cli.format
            ));
        }
        for file in ["own.toml", "own.lock"] {
            std::fs::metadata(root.join(file)).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    format!("NOT_INITIALIZED: {file} missing (run `own init` first)")
                } else {
                    format!("IO_ERROR: {file}: {e}")
                }
            })?;
        }
        let config = std::fs::read_to_string(root.join("own.toml"))
            .map_err(|e| format!("IO_ERROR: own.toml: {e}"))?;
        let policy = license_policy_json(&config)?;
        let overrides = read_overrides(&root)?;
        let mut outcome = verify(&root, &policy, &overrides)?;
        if cli.installed {
            outcome.findings.extend(verify_installed(&root)?);
        }
        outcome
            .findings
            .sort_by(|a, b| (&a.code, &a.package, &a.path).cmp(&(&b.code, &b.package, &b.path)));
        Ok::<_, String>(outcome)
    })();
    match result {
        Ok(outcome) => {
            let code = outcome
                .findings
                .iter()
                .filter(|f| f.severity == "error")
                .map(|f| match f.code.as_str() {
                    "IO_ERROR"
                    | "PARSE_ERROR"
                    | "LOCK_NOT_CANONICAL"
                    | "LOCK_SCHEMA_UNSUPPORTED" => 2,
                    _ => 1,
                })
                .max()
                .unwrap_or(0);

            if cli.format == "json" {
                println!(
                    "{}",
                    own_core::jcs::canonicalize(&serde_json::json!({
                        "schema_version": 1, "command": "verify",
                        "status": match code { 0 => "ok", 1 => "findings", _ => "error" },
                        "exit_code": code, "findings": outcome.findings, "data": {},
                    }))
                    .expect("verify output contains only JCS-safe values")
                );
            } else {
                for f in &outcome.findings {
                    println!(
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
        Err(e) => report_error(cli.format == "json", &e),
    }
}

fn report_error(json: bool, error: &str) -> ExitCode {
    if json {
        let code = error.split(':').next().unwrap_or("IO_ERROR");
        println!(
            "{}",
            own_core::jcs::canonicalize(&serde_json::json!({
                "schema_version": 1,
                "command": "verify",
                "status": "error",
                "exit_code": 2,
                "findings": [{
                    "code": code,
                    "severity": "error",
                    "package": "",
                    "path": "",
                    "message": error,
                }],
                "data": {},
            }))
            .expect("verify output contains only JCS-safe values")
        );
    } else {
        eprintln!("error: {error}");
    }
    ExitCode::from(2)
}
