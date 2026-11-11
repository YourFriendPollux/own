//! `own eject --adopt` (SPEC §8.3): irreversible (git-reversible) adoption of
//! the vendored code as first-party. Keeps vendor/own/<dir>/, LICENSES.md,
//! pnpm.overrides and file: deps; removes own.lock, own.toml, .own/,
//! .manifests/. Then pnpm install --frozen-lockfile + project build script.

use own_core::txn::Txn;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub struct EjectArgs {
    pub adopt: bool,
    pub yes: bool,
}

pub fn eject(root: &Path, args: &EjectArgs) -> Result<u8, String> {
    if !args.adopt {
        return Err("USAGE_ERROR: only --adopt is supported in Phase 0".to_string());
    }
    // interactive confirmation unless --yes
    if !args.yes {
        if !atty() {
            return Err("USAGE_ERROR: non-interactive; pass --yes".to_string());
        }
        eprint!("This removes own.lock/own.toml/.own and adopts vendor/own as first-party code. Irreversible except via git. Continue? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("IO_ERROR: {e}"))?;
        if line.trim() != "y" && line.trim() != "Y" {
            println!("aborted");
            return Ok(0);
        }
    }
    // clean worktree required
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("GIT_ERROR: {e}"))?;
    if !dirty.stdout.is_empty() {
        return Err("WORKTREE_DIRTY".to_string());
    }
    // verify must pass first
    let toml =
        std::fs::read_to_string(root.join("own.toml")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let pol = own_core::config::license_policy_json(&toml)?;
    let mut overrides = serde_json::Map::new();
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
                            overrides.insert(k.clone(), serde_json::Value::String(s.to_string()));
                        }
                    }
                }
            }
        }
    }
    let outcome = own_core::verify::verify(root, &pol, &overrides)?;
    if outcome.findings.iter().any(|f| f.severity == "error") {
        return Err(format!(
            "{}: verify failed before eject",
            outcome.findings[0].code
        ));
    }
    // transaction: prepare removals (keep vendor dirs, LICENSES.md, overrides, .gitattributes/.gitignore/CODEOWNERS)
    let txn = Txn::begin(root)?;
    let res = (|| -> Result<(), String> {
        for f in ["own.lock", "own.toml"] {
            if root.join(f).exists() {
                txn.backup(f)?;
                std::fs::remove_file(root.join(f)).map_err(|e| format!("IO_ERROR: {e}"))?;
            }
        }
        let manifests = root.join("vendor/own/.manifests");
        if manifests.exists() {
            txn.backup("vendor/own/.manifests")?;
            std::fs::remove_dir_all(&manifests).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        // .own/ is disposable (cache/tmp/txn) and self-recursive to back up:
        // skip the backup entirely — it is reconstructible (§8.0).
        let own_dir = root.join(".own");
        if own_dir.exists() {
            std::fs::remove_dir_all(&own_dir).map_err(|e| format!("IO_ERROR: {e}"))?;
        }
        Ok(())
    })();
    if let Err(e) = res {
        let _ = txn.rollback();
        return Err(e);
    }
    // pnpm install --frozen-lockfile + build
    let st = Command::new("pnpm")
        .args(["install", "--frozen-lockfile"])
        .current_dir(root)
        .status()
        .map_err(|e| format!("PNPM_FAILED: {e}"))?;
    if !st.success() {
        let _ = txn.rollback();
        return Err("INSTALL_VERIFY_FAILED: pnpm install --frozen-lockfile".to_string());
    }
    // project build script if present
    if let Ok(text) = std::fs::read_to_string(root.join("package.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if v.pointer("/scripts/build")
                .and_then(|b| b.as_str())
                .is_some()
            {
                let st = Command::new("pnpm")
                    .arg("run")
                    .arg("build")
                    .current_dir(root)
                    .stdin(Stdio::null())
                    .status()
                    .map_err(|e| format!("PNPM_FAILED: {e}"))?;
                if !st.success() {
                    let _ = txn.rollback();
                    return Err("INSTALL_VERIFY_FAILED: build script".to_string());
                }
            }
        }
    }
    txn.commit()?;
    println!("ejected: vendor/own/* adopted as first-party; own.lock/own.toml/.own removed (recover via git)");
    Ok(0)
}

fn atty() -> bool {
    unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 }
}
