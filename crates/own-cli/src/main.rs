use clap::{Parser, Subcommand};
use own_core::canonical::{empty_lock, write_lock_canonical};
use own_core::config::{license_policy_json, DEFAULT_OWN_TOML};
use own_core::verify::{verify, verify_installed};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "own", version = env!("CARGO_PKG_VERSION"), about = "Verified vendoring for supply chain & compliance")]
struct Cli {
    /// Root directory (default: current directory)
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize own in the current project (SPEC §8.1)
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Scan runtime dependencies for eligibility (SPEC §8.1) — network
    Scan {
        #[arg(long)]
        include_dev: bool,
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Vendor a package verbatim (SPEC §8.1) — network
    Add {
        /// <pkg>@<version>
        spec: String,
        /// Ecosystem: npm (default) or pypi (Phase 2)
        #[arg(long, default_value = "npm")]
        ecosystem: String,
        #[arg(long)]
        allow_diamond: Option<String>,
        #[arg(long)]
        license_override: Option<String>,
        #[arg(long)]
        no_install: bool,
        #[arg(long)]
        allow_untested_pnpm: bool,
    },
    /// Verify vendored files against own.lock (offline by default) (SPEC §8.1)
    Verify {
        /// Also compare the copy pnpm installed in node_modules/.pnpm (§8.1)
        #[arg(long)]
        installed: bool,
        #[arg(long)]
        remote: bool,
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// List vendored packages' licenses; --write regenerates LICENSES.md (SPEC §8.1)
    Licenses {
        #[arg(long)]
        write: bool,
    },
    /// Recompute license_policy_sha256 and re-evaluate policies (SPEC §8.1)
    PolicySync,
    /// Migrate own.lock to the next schema_version (SPEC §8.1)
    Migrate,
    /// Fetch the OSV npm dump into .own/osv.json (SPEC §8.2) — network
    OsvFetch,
    /// Phase 1: report E1 slicing potential for vendored packages (conservative)
    Slice {
        #[arg(long, default_value = "human")]
        format: String,
        /// Consumer model for exports resolution: esm (default) or cjs
        #[arg(long, value_name = "MODEL")]
        model: Option<String>,
    },
    /// Verify a cosign keyless signature (+ optional SLSA provenance) offline (SPEC §8.3)
    VerifySignature {
        file: String,
        #[arg(long)]
        bundle: String,
        #[arg(long)]
        provenance: Option<String>,
        #[arg(long)]
        trusted_root: Option<String>,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        issuer: String,
    },
    /// Eject: adopt vendored code as first-party (SPEC §8.3)
    Eject {
        #[arg(long)]
        adopt: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Generate SBOM CycloneDX 1.5 and/or OpenVEX (SPEC §8.3)
    Sbom {
        #[arg(long, default_value = "cyclonedx")]
        format: String,
        /// Compute E1 reachability evidence for VEX statements (Phase 2, Annexe G)
        #[arg(long)]
        e1: bool,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        vex_output: Option<String>,
        #[arg(long, default_value = "own")]
        author: String,
    },
    /// Update a vendored package to a new version (SPEC §8.2) — network
    Update {
        /// <pkg>@<new-version>
        spec: String,
        #[arg(long)]
        no_pr: bool,
        #[arg(long)]
        allow_diamond: Option<String>,
        #[arg(long)]
        no_install: bool,
    },
    /// Diff two vendored versions of a package, with risk signals (SPEC §8.2)
    Diff {
        old: String,
        new: String,
        #[arg(long)]
        from_cache: bool,
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Check vendored packages against OSV advisories, E0 alerts (SPEC §8.2)
    Check {
        #[arg(long)]
        remote: bool,
        #[arg(long)]
        allow_stale_osv: bool,
        #[arg(long)]
        allow_missing_osv: bool,
        #[arg(long, default_value = "human")]
        format: String,
        /// Phase 2: E1 reachability evidence (SPEC §9.4) — alert stays E0 unless
        /// the vulnerable files provably miss the reachable set
        #[arg(long)]
        e1: bool,
        /// Phase 2: E2 executed-reachability evidence (requires node on PATH)
        #[arg(long)]
        e2: bool,
    },
    /// CI gate: verify + coherence + diamonds + licenses (offline) (SPEC §8.1)
    Ci {
        #[arg(long)]
        base_ref: Option<String>,
        #[arg(long)]
        fail_on_lock_change: bool,
        #[arg(long, default_value = "human")]
        format: String,
    },
}

mod add;
mod ci;
mod diff;
mod eject;
mod git_ignore;
mod licenses;
mod osv;
mod sbom;
mod scan;
mod update;
mod verify_signature;

fn root_of(cli: &Cli) -> PathBuf {
    cli.root
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap())
}

/// Read `file:vendor/own/...` entries of pnpm.overrides from the root package.json.
fn read_overrides(
    root: &std::path::Path,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let pj = root.join("package.json");
    let text =
        std::fs::read_to_string(&pj).map_err(|e| format!("IO_ERROR: {}: {e}", pj.display()))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("PARSE_ERROR: package.json: {e}"))?;
    let mut out = serde_json::Map::new();
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
    Ok(out)
}

fn cmd_init(root: &std::path::Path, force: bool) -> Result<u8, String> {
    use std::fs;
    if !root.join("package.json").is_file() {
        return Err("USAGE_ERROR: package.json required at root".to_string());
    }
    let already = root.join("own.toml").exists() && root.join("own.lock").exists();
    if already && !force {
        return Err("ALREADY_INITIALIZED".to_string());
    }
    if force
        && root
            .join("vendor/own")
            .read_dir()
            .map(|mut r| r.next().is_some())
            .unwrap_or(false)
    {
        return Err("USAGE_ERROR: --force refused: vendor/own/ is not empty".to_string());
    }
    // INV-9 / §8.0: `init` writes project state, so it takes the exclusive lock
    // and journals its work like every other writing command. A failure (or a
    // signal) then leaves the directory as it was instead of half-initialised.
    let txn = own_core::txn::Txn::begin(root)?;
    let res = (|| -> Result<(), String> {
        // own.toml
        if !root.join("own.toml").exists() || force {
            txn.write_file("own.toml", DEFAULT_OWN_TOML.as_bytes())?;
        }
        // empty own.lock with computed digest
        let overrides = read_overrides(root)?;
        let lock = empty_lock(env!("CARGO_PKG_VERSION"), "1", &overrides);
        txn.write_file("own.lock", write_lock_canonical(&lock).as_bytes())?;
        // .own/ tree (tmp and txn already created by Txn::begin)
        for d in ["cache", "tmp", "txn"] {
            fs::create_dir_all(root.join(".own").join(d)).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        fs::create_dir_all(root.join("vendor/own")).map_err(|e| format!("IO_ERROR: {e}"))?;
        // Preserve existing rules; only a missing file defaults to empty.
        let read_optional = |path: &std::path::Path| -> Result<String, String> {
            match fs::read_to_string(path) {
                Ok(text) => Ok(text),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
                Err(e) => Err(format!("IO_ERROR: {}: {e}", path.display())),
            }
        };
        let gi = root.join(".gitignore");
        let mut gi_text: String = read_optional(&gi)?
            .split_inclusive('\n')
            .filter(|line| line.trim() != "!vendor/own/**")
            .collect();
        if !gi_text.is_empty() && !gi_text.ends_with('\n') {
            gi_text.push('\n');
        }
        if !gi_text.lines().any(|line| line.trim() == ".own/") {
            gi_text.push_str(".own/\n");
        }
        // A pre-existing negation may precede later rules such as dist/.
        // It must be the final rule, not merely present somewhere in the file.
        gi_text.push_str("!vendor/own/**\n");
        txn.write_file(".gitignore", gi_text.as_bytes())?;
        // .gitattributes: append idempotently
        let ga = root.join(".gitattributes");
        let mut ga_text = read_optional(&ga)?;
        for line in [
            "vendor/own/** -text",
            "own.lock text eol=lf",
            "own.toml text eol=lf",
        ] {
            if !ga_text.lines().any(|l| l.trim() == line) {
                if !ga_text.is_empty() && !ga_text.ends_with('\n') {
                    ga_text.push('\n');
                }
                ga_text.push_str(line);
                ga_text.push('\n');
            }
        }
        txn.write_file(".gitattributes", ga_text.as_bytes())?;
        // Detect git repositories in parent directories too (workspaces), and
        // never interpret a failed git command as a successful ignore check.
        let in_repo = std::process::Command::new("git")
            .args(["rev-parse", "--is-inside-work-tree"])
            .current_dir(root)
            .output();
        let has_git_metadata = root.ancestors().any(|dir| dir.join(".git").exists());
        let check_git = match in_repo {
            Ok(out) if out.status.success() => out.stdout.starts_with(b"true"),
            Ok(out) if has_git_metadata => {
                return Err(format!(
                    "GIT_ERROR: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            Err(e) if has_git_metadata => return Err(format!("GIT_ERROR: {e}")),
            _ => false, // init also supports projects not yet in a git repository
        };
        if check_git {
            let out = std::process::Command::new("git")
                .args(["check-ignore", "--no-index", "vendor/own/_probe/x"])
                .current_dir(root)
                .output()
                .map_err(|e| format!("GIT_ERROR: {e}"))?;
            match out.status.code() {
                Some(0) => return Err("VENDOR_PATH_IGNORED: un-ignore the parent directory of vendor/ (a negation cannot re-include under an excluded parent)".to_string()),
                Some(1) => {}, // no ignored path: the only successful negative result
                _ => return Err(format!("GIT_ERROR: {}", String::from_utf8_lossy(&out.stderr))),
            }
        }
        Ok(())
    })();
    match res {
        Ok(()) => {
            txn.commit()?;
            Ok(0)
        }
        Err(e) => {
            let _ = txn.rollback();
            Err(e)
        }
    }
}

/// §8.0 `NOT_INITIALIZED`: `own.toml` and `own.lock` are the project state, and
/// only `init` creates them. Every other command must fail with the documented
/// precondition code (exit 2) instead of a bare `IO_ERROR`.
fn require_init(root: &std::path::Path) -> Result<(), String> {
    for f in ["own.toml", "own.lock"] {
        if !root.join(f).is_file() {
            return Err(format!(
                "NOT_INITIALIZED: {f} missing (run `own init` first)"
            ));
        }
    }
    Ok(())
}

/// §8.0: `--format` accepts `human|json`. An unknown value is a usage error
/// (exit 2), never a value that is silently ignored.
fn validate_format(format: &str) -> Result<(), String> {
    match format {
        "human" | "json" => Ok(()),
        other => Err(format!(
            "USAGE_ERROR: --format must be human|json (got `{other}`)"
        )),
    }
}

fn cmd_verify(
    root: &std::path::Path,
    installed: bool,
    remote: bool,
    format: &str,
) -> Result<u8, String> {
    validate_format(format)?;
    if remote {
        return Err(
            "USAGE_ERROR: --remote requires own-net (not yet linked in 0.1 core)".to_string(),
        );
    }
    require_init(root)?;
    let toml_text = std::fs::read_to_string(root.join("own.toml"))
        .map_err(|e| format!("IO_ERROR: own.toml: {e}"))?;
    let policy = license_policy_json(&toml_text)?;
    let overrides = read_overrides(root)?;
    let mut outcome = verify(root, &policy, &overrides)?;
    // §8.1 `--installed`: every file present in the pnpm copy must exist in the
    // manifest with the same bytes (DRIFT_INSTALLED). Files absent from the copy
    // are not reported (§5), and a package that was never installed is skipped.
    if installed {
        outcome.findings.extend(verify_installed(root)?);
        outcome.findings.sort_by(|a, b| {
            (a.code.as_str(), a.package.as_str(), a.path.as_str()).cmp(&(
                b.code.as_str(),
                b.package.as_str(),
                b.path.as_str(),
            ))
        });
    }
    let has_error = outcome.findings.iter().any(|f| f.severity == "error");
    let exit_code = if has_error { 1 } else { 0 };
    if format == "json" {
        let findings_json: Vec<serde_json::Value> = outcome
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "code": f.code, "severity": f.severity, "package": f.package,
                    "path": f.path, "message": f.message,
                })
            })
            .collect();
        let status = if has_error { "findings" } else { "ok" };
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "verify",
                "status": status,
                "exit_code": exit_code,
                "findings": findings_json,
                "data": {},
            })
        );
        return Ok(exit_code);
    }
    // human: the result goes to stdout, logs go to stderr (§8.0)
    if outcome.findings.is_empty() {
        println!("ok: no findings");
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
    }
    Ok(exit_code)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = root_of(&cli);
    let result = match &cli.command {
        Commands::Init { force } => cmd_init(&root, *force),
        Commands::Scan {
            include_dev,
            format,
        } => match scan::scan(&root, *include_dev) {
            Ok((rows, errors)) => {
                if format == "json" {
                    let data: Vec<serde_json::Value> = rows
                        .iter()
                        .map(|r| {
                            serde_json::json!({
                                "package": r.name, "version": r.version,
                                "size": r.size, "license": r.license, "deps": r.deps,
                                "install_scripts": r.install_scripts, "types": r.types,
                                "status": r.status,
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "schema_version": 1, "command": "scan",
                            "status": if errors > 0 { "error" } else { "ok" },
                            "exit_code": if errors > 0 { 3 } else { 0 },
                            "findings": [], "data": { "rows": data },
                        }))
                        .unwrap()
                    );
                } else {
                    let header = format!(
                        "{:<28} {:<10} {:>10} {:<12} {:>4} {:>7} {:<14} {}",
                        "Package",
                        "Version",
                        "Size",
                        "License",
                        "Deps",
                        "Scripts",
                        "Types",
                        "Status"
                    );
                    println!("{header}");
                    for r in &rows {
                        println!(
                            "{:<28} {:<10} {:>10} {:<12} {:>4} {:>7} {:<14} {}",
                            r.name,
                            r.version,
                            r.size.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                            r.license.clone().unwrap_or_else(|| "-".into()),
                            r.deps,
                            r.install_scripts,
                            r.types,
                            r.status
                        );
                    }
                }
                Ok(if errors > 0 { 3 } else { 0 })
            }
            Err(e) => Err(e),
        },
        Commands::Add {
            spec,
            ecosystem,
            allow_diamond,
            license_override,
            no_install,
            allow_untested_pnpm,
        } => {
            // scoped: @scope/name@1.2.3 -> split at last '@'
            let (pkg, version) = if spec.starts_with('@') {
                match spec.rfind('@') {
                    Some(i) if i > 0 => (&spec[..i], &spec[i + 1..]),
                    _ => ("", ""),
                }
            } else {
                match spec.split_once('@') {
                    Some((p, v)) if !p.is_empty() => (p, v),
                    _ => ("", ""),
                }
            };
            if pkg.is_empty() || version.is_empty() {
                eprintln!("error: USAGE_ERROR: expected <pkg>@<version>");
                return ExitCode::from(2);
            }
            if allow_diamond.as_deref() == Some("vendor-all") {
                // Phase 2 (SPEC §9.2): vendor-all = vendor EVERY version of
                // <pkg> resolved in pnpm-lock.yaml, not just the requested one.
                let lock_text = match std::fs::read_to_string(root.join("pnpm-lock.yaml")) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("error: IO_ERROR: {e}");
                        return ExitCode::from(2);
                    }
                };
                let pl = match own_policy::pnpm_lock::parse_pnpm_lock(&lock_text) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: PARSE_ERROR: {e}");
                        return ExitCode::from(2);
                    }
                };
                let mut versions: Vec<String> = pl
                    .packages
                    .iter()
                    .filter(|e| e.name == pkg)
                    .map(|e| e.version.clone())
                    .collect();
                versions.sort();
                versions.dedup();
                if versions.is_empty() {
                    versions.push(version.to_string());
                }
                let base = add::AddArgs {
                    pkg: pkg.to_string(),
                    version: version.to_string(),
                    ecosystem: ecosystem.clone(),
                    allow_diamond: Some("vendor-all".to_string()),
                    license_override: license_override
                        .as_deref()
                        .map(|s| s.starts_with("human-review:"))
                        .unwrap_or(false),
                    no_install: *no_install,
                    allow_untested_pnpm: *allow_untested_pnpm,
                };
                return match add::add_vendor_all(&root, &base, &versions) {
                    Ok(count) => {
                        println!(
                            "vendor-all: {count}/{} versions of {pkg} vendored",
                            versions.len()
                        );
                        ExitCode::from(0)
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        ExitCode::from(1)
                    }
                };
            }
            let args = add::AddArgs {
                pkg: pkg.to_string(),
                version: version.to_string(),
                ecosystem: ecosystem.clone(),
                allow_diamond: allow_diamond.clone(),
                license_override: license_override
                    .as_deref()
                    .map(|s| s.starts_with("human-review:"))
                    .unwrap_or(false),
                no_install: *no_install,
                allow_untested_pnpm: *allow_untested_pnpm,
            };
            add::add(&root, &args).map(|_| 0)
        }
        Commands::Verify {
            installed,
            remote,
            format,
        } => cmd_verify(&root, *installed, *remote, format),
        Commands::Licenses { write } => {
            require_init(&root).and_then(|()| licenses::licenses(&root, *write))
        }
        Commands::PolicySync => require_init(&root).and_then(|()| licenses::policy_sync(&root)),
        Commands::Migrate => require_init(&root).and_then(|()| licenses::migrate(&root)),
        Commands::OsvFetch => {
            let now = std::env::var("OWN_NOW").ok();
            match osv::osv_fetch(&root, osv::DEFAULT_OSV_URL, 500, now.as_deref()) {
                Ok(c) => Ok(c),
                Err(e) => Err(e),
            }
        }
        Commands::Slice { format, model } => {
            if let Err(e) = validate_format(format).and_then(|()| require_init(&root)) {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
            let lock_text = match std::fs::read_to_string(root.join("own.lock")) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error: IO_ERROR: own.lock: {e}");
                    return ExitCode::from(2);
                }
            };
            let lock = match own_core::lock::parse_lock(&lock_text) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("error: PARSE_ERROR: {e}");
                    return ExitCode::from(2);
                }
            };
            let mut reports = Vec::new();
            let mut tt = 0u64;
            let mut tr = 0u64;
            for p in &lock.packages {
                let cm = match model.as_deref() {
                    Some("cjs") => own_slice::ConsumerModel::Cjs,
                    _ => own_slice::ConsumerModel::Esm,
                };
                let rep = own_slice::slice_package_model(
                    &root.join(&p.dir),
                    &format!("{}@{}", p.name, p.version),
                    cm,
                );
                tt += rep.total_bytes;
                tr += rep.kept_bytes;
                reports.push((p.name.clone(), p.version.clone(), rep));
            }
            if format == "json" {
                let data: Vec<serde_json::Value> = reports
                    .iter()
                    .map(|(n, v, r)| {
                        serde_json::json!({
                            "package": n, "version": v,
                            "total_bytes": r.total_bytes, "kept_bytes": r.kept_bytes,
                            "reduction_pct": r.reduction_pct(),
                            "keep_whole": r.keep_whole, "reason": r.reason,
                            "dropped_files": r.dropped_files.len(),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": 1, "command": "slice", "status": "ok", "exit_code": 0,
                    "findings": [],
                    "data": { "packages": data, "total_bytes": tt, "kept_bytes": tr,
                              "reduction_pct": if tt > 0 { 100.0 - 100.0 * tr as f64 / tt as f64 } else { 0.0 } },
                })).unwrap());
            } else {
                let header = format!(
                    "{:<28} {:>10} {:>10} {:>8} {}",
                    "Package", "Total", "Kept", "Reduct%", "Note"
                );
                println!("{header}");
                for (n, v, r) in &reports {
                    let note = if r.keep_whole {
                        format!("keep-whole: {}", r.reason.clone().unwrap_or_default())
                    } else {
                        format!("drops {} files", r.dropped_files.len())
                    };
                    println!(
                        "{:<28} {:>10.1} {:>10.1} {:>7.1}% {}",
                        format!("{}@{}", n, v),
                        r.total_bytes as f64 / 1024.0,
                        r.kept_bytes as f64 / 1024.0,
                        r.reduction_pct(),
                        note
                    );
                }
                println!(
                    "\nTOTAL: {:.2}MB -> {:.2}MB  reduction {:.1}%",
                    tt as f64 / 1e6,
                    tr as f64 / 1e6,
                    if tt > 0 {
                        100.0 - 100.0 * tr as f64 / tt as f64
                    } else {
                        0.0
                    }
                );
            }
            Ok(0)
        }
        Commands::VerifySignature {
            file,
            bundle,
            provenance,
            trusted_root,
            identity,
            issuer,
        } => {
            let args = verify_signature::VerifySignatureArgs {
                file: file.clone(),
                bundle: bundle.clone(),
                provenance: provenance.clone(),
                trusted_root: trusted_root.clone(),
                identity: identity.clone(),
                issuer: issuer.clone(),
            };
            verify_signature::verify_signature(&root, &args)
        }
        Commands::Eject { adopt, yes } => {
            let args = eject::EjectArgs {
                adopt: *adopt,
                yes: *yes,
            };
            require_init(&root).and_then(|()| eject::eject(&root, &args))
        }
        Commands::Sbom {
            format,
            e1,
            output,
            vex_output,
            author,
        } => {
            let args = sbom::SbomArgs {
                format: format.clone(),
                e1: *e1,
                output: output.clone(),
                vex_output: vex_output.clone(),
                author: author.clone(),
                now: std::env::var("OWN_NOW").ok(),
            };
            require_init(&root).and_then(|()| sbom::sbom(&root, &args))
        }
        Commands::Update {
            spec,
            no_pr,
            allow_diamond,
            no_install,
        } => {
            let (pkg, new_version) = update::split_spec_pub(spec);
            if pkg.is_empty() || new_version.is_empty() {
                eprintln!("error: USAGE_ERROR: expected <pkg>@<new-version>");
                return ExitCode::from(2);
            }
            let args = update::UpdateArgs {
                pkg,
                new_version,
                no_pr: *no_pr,
                allow_diamond: allow_diamond.clone(),
                no_install: *no_install,
            };
            update::update(&root, &args)
        }
        Commands::Diff {
            old,
            new,
            from_cache,
            format,
        } => {
            if let Err(e) = validate_format(format).and_then(|()| require_init(&root)) {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
            if *from_cache {
                eprintln!("error: USAGE_ERROR: --from-cache not yet wired");
                return ExitCode::from(2);
            }
            let old_dir = match diff::resolve_dir(&root, old) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let new_dir = match diff::resolve_dir(&root, new) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            match diff::diff_dirs(&root, &old_dir, &new_dir) {
                Ok(rep) => {
                    if format == "json" {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "schema_version": 1, "command": "diff", "status": "ok",
                                "exit_code": 0, "findings": [],
                                "data": {
                                    "added": rep.added, "removed": rep.removed,
                                    "modified": rep.modified,
                                    "renamed": rep.renamed.iter().map(|(a,b)| json!({"from":a,"to":b})).collect::<Vec<_>>(),
                                    "signals": rep.signals,
                                },
                            }))
                            .unwrap()
                        );
                    } else {
                        println!(
                            "added: {}  removed: {}  modified: {}  renamed: {}",
                            rep.added.len(),
                            rep.removed.len(),
                            rep.modified.len(),
                            rep.renamed.len()
                        );
                        for s in &rep.signals {
                            println!("SIGNAL {}: {} at {}:{}", s.kind, s.name, s.path, s.line);
                        }
                    }
                    Ok(0)
                }
                Err(e) => Err(e),
            }
        }
        Commands::Check {
            remote,
            allow_stale_osv,
            allow_missing_osv,
            format,
            e1,
            e2,
        } => {
            if let Err(e) = validate_format(format).and_then(|()| require_init(&root)) {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
            if *remote {
                eprintln!(
                    "error: NETWORK_ERROR: check --remote not yet wired (uses [osv].api_url)"
                );
                return ExitCode::from(3);
            }
            let args = osv::CheckArgs {
                remote: false,
                allow_stale_osv: *allow_stale_osv,
                allow_missing_osv: *allow_missing_osv,
                now: std::env::var("OWN_NOW").ok(),
                max_age_days: 7,
                e1: *e1,
                e2: *e2,
            };
            match osv::check(&root, &args, ".own/osv.json") {
                Ok((alerts, warnings)) => {
                    for w in &warnings {
                        eprintln!("warning: {w}");
                    }
                    let code = if alerts.is_empty() { 0 } else { 1 };
                    if format == "json" {
                        let data: Vec<serde_json::Value> = alerts
                            .iter()
                            .map(|a| {
                                serde_json::json!({
                                    "advisory_id": a.advisory_id,
                                    "aliases": a.aliases,
                                    "package": a.package,
                                    "current_version": a.current_version,
                                    "affected_ranges": a.affected_ranges,
                                    "fixed_versions": a.fixed_versions,
                                    "evidence_level": a.evidence_level,
                                })
                            })
                            .collect();
                        // §8.0: `findings` is the public list, so an alert that
                        // decides the exit code must appear there too — an empty
                        // array beside `"status": "findings"` tells a consumer
                        // nothing failed. `data.alerts` keeps the full detail.
                        let findings: Vec<serde_json::Value> = alerts
                            .iter()
                            .map(|a| {
                                serde_json::json!({
                                    "code": "CVE_ALERT",
                                    "severity": "error",
                                    "package": format!("{}@{}", a.package, a.current_version),
                                    "path": "",
                                    "message": format!(
                                        "{}: {} ({}) affects {}@{}; fixed in {:?}",
                                        a.evidence_level,
                                        a.advisory_id,
                                        a.aliases.join(", "),
                                        a.package,
                                        a.current_version,
                                        a.fixed_versions
                                    ),
                                })
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "schema_version": 1, "command": "check",
                                "status": if code == 0 { "ok" } else { "findings" },
                                "exit_code": code, "findings": findings,
                                "data": { "alerts": data },
                            }))
                            .unwrap()
                        );
                    } else {
                        for a in &alerts {
                            println!(
                                "CVE_ALERT E0: {} ({}) affects {}@{} fixed in {:?}",
                                a.advisory_id,
                                a.aliases.join(","),
                                a.package,
                                a.current_version,
                                a.fixed_versions
                            );
                        }
                        if code == 0 {
                            println!("ok: no E0 alerts (absence of alerts is not a security guarantee, INV-7)");
                        }
                    }
                    Ok(code)
                }
                Err(e) => Err(e),
            }
        }
        Commands::Ci {
            base_ref,
            fail_on_lock_change,
            format,
        } => {
            if let Err(e) = validate_format(format).and_then(|()| require_init(&root)) {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
            let args = ci::CiArgs {
                base_ref: base_ref.clone(),
                fail_on_lock_change: *fail_on_lock_change,
            };
            match ci::ci(&root, &args) {
                Ok((findings, notes)) => {
                    let code = if findings.iter().any(|f| f.severity == "error") {
                        1
                    } else {
                        0
                    };
                    if format == "json" {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "schema_version": 1, "command": "ci",
                                "status": if code == 0 { "ok" } else { "findings" },
                                "exit_code": code, "findings": findings, "data": { "notes": notes },
                            }))
                            .unwrap()
                        );
                    } else {
                        for note in &notes {
                            println!("{note}");
                        }
                        for f in &findings {
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
                    Ok(code)
                }
                Err(e) => Err(e),
            }
        }
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            // error codes map to exit 2 (usage/precondition) or 1 (policy) per §8.0;
            // here: usage/precondition errors -> 2, known drift/policy -> 1
            let code = match e.split(':').next().unwrap_or("") {
                "ALREADY_INITIALIZED" | "NOT_INITIALIZED" | "USAGE_ERROR" | "LOCK_BUSY" => 2,
                "VENDOR_PATH_IGNORED" => 1,
                "PARSE_ERROR" | "IO_ERROR" | "LOCK_SCHEMA_UNSUPPORTED" => 2,
                "ALREADY_VENDORED"
                | "PACKAGE_NOT_VENDORED"
                | "VERSION_NOT_FOUND"
                | "VENDOR_DIR_EXISTS"
                | "OVERRIDE_CONFLICT"
                | "WORKTREE_DIRTY"
                | "GIT_ERROR"
                | "PNPM_UNSUPPORTED"
                | "ECOSYSTEM_UNSUPPORTED"
                | "PNPM_FAILED"
                | "OSV_MISSING"
                | "OSV_STALE"
                | "OSV_INCOMPLETE"
                | "LOCK_NOT_CANONICAL" => 2,
                "NETWORK_ERROR" | "REGISTRY_UNAVAILABLE" | "TARBALL_REMOVED" | "GH_FAILED" => 3,
                _ => 1,
            };
            eprintln!("error: {e}");
            ExitCode::from(code)
        }
    }
}
