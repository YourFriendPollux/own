//! Phase 2 — E2 evidence: executed reachability.
//!
//! Runs the vendored package's entry point under `node` with a `require`/`import`
//! hook that records every file actually loaded, then compares that set to the
//! advisory's vulnerable files. E2 fires only if NO vulnerable file was loaded.
//!
//! Conservative (INV-4/INV-7): any failure (node missing, nonzero exit, timeout,
//! unparseable hook output, dynamic code already proven at E1 level) ⇒ `None`
//! ⇒ the alert stays at its lower level. E2 is never `not_affected`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Outcome of an E2 execution probe.
pub enum E2Outcome {
    /// loaded files (relative, `/`-separated) — proof available
    Loaded(HashSet<String>),
    /// execution inconclusive — no proof (INV-4)
    Inconclusive,
}

/// The node require-hook source. Records resolved module filenames on stdout.
// Capture the writer before package code runs; no filesystem-write grant is
// needed. Additional trace paths can only add potential vulnerable-file hits.
const HOOK: &str = r#"
const Module = require('module');
const fs = require('fs');
const writeTrace = process.stdout.write.bind(process.stdout);
const resolvePath = require('path').resolve.bind(require('path'));
const emit = (p) => { writeTrace('\nE2T ' + p + '\n'); };
const orig = Module._resolveFilename;
Module._resolveFilename = function (request, parent, ...rest) {
  const r = orig.call(this, request, parent, ...rest);
  emit(r);
  return r;
};
// E2-04: trace fs reads (sync + async + promises + streams) — data assets can
// carry the vulnerable payload without going through require().
const origRead = fs.readFileSync;
fs.readFileSync = function (p, ...rest) {
  try { emit(resolvePath(String(p))); } catch (e) {}
  return origRead.call(this, p, ...rest);
};
const origReadAsync = fs.readFile;
fs.readFile = function (p, ...rest) {
  try { emit(resolvePath(String(p))); } catch (e) {}
  return origReadAsync.call(this, p, ...rest);
};
if (fs.promises && fs.promises.readFile) {
  const origP = fs.promises.readFile;
  fs.promises.readFile = function (p, ...rest) {
    try { emit(resolvePath(String(p))); } catch (e) {}
    return origP.call(this, p, ...rest);
  };
}
const origCRS = fs.createReadStream;
fs.createReadStream = function (p, ...rest) {
  try { emit(resolvePath(String(p))); } catch (e) {}
  return origCRS.call(this, p, ...rest);
};
// Hook removal is not a successful trace. Freeze the instrumentation surfaces.
for (const [obj, key] of [[Module, '_resolveFilename'], [fs, 'readFileSync'],
  [fs, 'readFile'], [fs, 'createReadStream'], [fs.promises, 'readFile']]) {
  Object.defineProperty(obj, key, {value: obj[key], writable: false, configurable: false});
}
// A package-controlled early exit is incomplete, even if stdout forges the
// completion marker. Preserve a nonzero native exit that cannot be replaced.
const failIncomplete = process.reallyExit.bind(process, 1);
for (const key of ['exit', 'reallyExit']) {
  Object.defineProperty(process, key, {value: failIncomplete, writable: false, configurable: false});
}
// ESM named imports must see the same frozen process/fs instrumentation.
Module.syncBuiltinESMExports();
"#;

/// ESM loader hook (registered with `--import`): records every resolved ESM
/// module URL so `import` edges are traced too (F2).
const ESM_HOOK: &str = r#"
// E2-03 (deepseek): ESM resolve hook via registerHooks (node >= 22.15).
// Writes a marker line `E2T ESM-OK` on successful registration — if absent
// from the output, the whole ESM graph is untraced ⇒ caller must treat as
// Inconclusive.
const writeTrace = process.stdout.write.bind(process.stdout);
const emit = (p) => { writeTrace('\nE2T ' + p + '\n'); };
try {
  const { registerHooks } = await import('node:module');
  registerHooks({
    resolve(specifier, context, next) {
      const r = next(specifier, context);
      try {
        if (r.url && r.url.startsWith('file://')) {
          emit(decodeURIComponent(r.url.slice(7)));
        }
      } catch (e) {}
      return r;
    },
  });
  emit('ESM-OK');
} catch (e) { /* older node: no ESM trace => caller sees no ESM-OK marker */ }
"#;

/// Resolve Node against the caller's PATH before clearing the child environment.
/// Canonicalization also anchors relative PATH entries before changing cwd.
fn node_from_incoming_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let name = if cfg!(windows) { "node.exe" } else { "node" };
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        let Ok(metadata) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        if let Ok(absolute) = std::fs::canonicalize(candidate) {
            return Some(absolute);
        }
    }
    None
}

/// Execute the package entry under node with the trace hook.
/// `entry` = absolute path to the entry file. Timeout 10s.
pub fn trace_loaded_files(pkg_root: &Path, entry: &Path) -> E2Outcome {
    let Ok(canonical_root) = std::fs::canonicalize(pkg_root) else {
        return E2Outcome::Inconclusive;
    };
    let Ok(canonical_entry) = std::fs::canonicalize(entry) else {
        return E2Outcome::Inconclusive;
    };
    let pkg_root = canonical_root.as_path();
    let entry = canonical_entry.as_path();
    if !entry.starts_with(pkg_root) || pkg_root.to_string_lossy().contains('*') {
        return E2Outcome::Inconclusive;
    }
    if !entry.is_file() {
        return E2Outcome::Inconclusive;
    }
    let Some(node) = node_from_incoming_path() else {
        return E2Outcome::Inconclusive;
    };
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(_) => return E2Outcome::Inconclusive,
    };
    let hook = tmp.path().join("hook.cjs");
    let esm_hook = tmp.path().join("esm-hook.mjs");
    if std::fs::write(&hook, HOOK).is_err() || std::fs::write(&esm_hook, ESM_HOOK).is_err() {
        return E2Outcome::Inconclusive;
    }
    let runner = tmp.path().join("run.cjs");
    let entry_str = entry.to_string_lossy().replace('\\', "/");
    // ESM-safe runner: try require, fall back to dynamic import() so .mjs
    // entries are traced too (F3). CJS files are traced via the
    // Module._resolveFilename hook; ESM imports are traced via the
    // --import ESM hook below.
    let runner_src = format!(
        "const writeTrace = process.stdout.write.bind(process.stdout); (async () => {{ try {{ require({:?}); }} catch (e) {{ if (e && (e.code === 'ERR_REQUIRE_ESM' || e.code === 'ERR_REQUIRE_ASYNC_MODULE')) {{ await import({:?}); }} else throw e; }} writeTrace('\\nE2T RUN-COMPLETE\\n'); }})();\n",
        entry_str, entry_str
    );
    if std::fs::write(&runner, runner_src).is_err() {
        return E2Outcome::Inconclusive;
    }
    // F4: bounded execution — 10s timeout, kill on expiry ⇒ Inconclusive
    // The selected Node runs with a cleared environment and a fixed child PATH.
    // Reads are limited to the package and temporary driver; never grant read=/.
    // --permission leaves network, fs-write, workers and child processes denied;
    // --no-addons denies native addons. Unsupported permissions fail closed.
    let mut cmd = Command::new(node);
    cmd.arg("--max-old-space-size=256") // E2-F3: cap child memory too
        .arg("--permission")
        .arg("--no-addons")
        .arg(format!("--allow-fs-read={}", pkg_root.display()))
        .arg(format!("--allow-fs-read={}", tmp.path().display()))
        .arg("--require")
        .arg(&hook)
        .arg("--import")
        .arg(&esm_hook)
        .arg(&runner)
        .current_dir(pkg_root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return E2Outcome::Inconclusive,
    };
    // Drain concurrently, retaining at most cap+1 bytes. Exceeding the cap
    // terminates the probe, rather than accepting a truncated trace.
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return E2Outcome::Inconclusive;
    };
    let overflow = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_overflow = overflow.clone();
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut bytes = Vec::new();
        let result = stdout.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes);
        reader_overflow.store(
            bytes.len() > 8 * 1024 * 1024,
            std::sync::atomic::Ordering::Relaxed,
        );
        result.map(|_| bytes)
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                status = Some(st);
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline
                    || overflow.load(std::sync::atomic::Ordering::Relaxed)
                {
                    let _ = child.kill();
                    let _ = child.wait();
                    status = None;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                status = None;
                break;
            }
        }
    }
    // E2-02 (deepseek): nonzero exit ⇒ Inconclusive (entry threw before
    // loading everything — proven false E2 otherwise).
    let Ok(Ok(bytes)) = reader.join() else {
        return E2Outcome::Inconclusive;
    };
    if status.is_none_or(|s| !s.success()) || overflow.load(std::sync::atomic::Ordering::Relaxed) {
        return E2Outcome::Inconclusive;
    }
    let Ok(buf) = String::from_utf8(bytes) else {
        return E2Outcome::Inconclusive;
    };
    // Both instrumentation and runner must complete, even for a CJS entry:
    // CJS can import ESM without leaving an `import(` string in stdout.
    if !buf.lines().any(|line| line == "E2T RUN-COMPLETE")
        || !buf.lines().any(|line| line == "E2T ESM-OK")
    {
        return E2Outcome::Inconclusive;
    }
    let mut set = HashSet::new();
    for line in buf.lines() {
        if let Some(rest) = line.trim().strip_prefix("E2T ") {
            let p = PathBuf::from(rest.trim());
            if let Ok(r) = p.strip_prefix(pkg_root) {
                set.insert(r.to_string_lossy().replace('\\', "/"));
            }
        }
    }

    if set.is_empty() {
        return E2Outcome::Inconclusive;
    }
    E2Outcome::Loaded(set)
}

/// E2 evidence level for an advisory: like E1 but the reachable set is the
/// **executed** set. Returns ("E2", Some(files)) if no vulnerable file was
/// loaded, else ("E1-or-lower", ...). We return E2 only on proof.
pub fn evidence_level_e2(
    pkg_root: &Path,
    advisory: &serde_json::Value,
    entry: &Path,
) -> (&'static str, Option<HashSet<String>>) {
    // E2-F1/F6 (apinex): E2 requires a clean static graph — if E1 cannot prove
    // the reachable set (dynamic code, fs.*, worker_threads, vm), the executed
    // trace can only be partial ⇒ no E2 proof.
    if crate::e1::reachable_files(pkg_root, crate::ConsumerModel::Esm).is_none() {
        return ("E0", None);
    }
    let Some(vuln_files) = crate::e1::vulnerable_files(advisory) else {
        return ("E0", None); // incomplete file info ⇒ no proof
    };
    match trace_loaded_files(pkg_root, entry) {
        E2Outcome::Inconclusive => ("E0", None),
        E2Outcome::Loaded(loaded) => {
            let all_files = crate::e1::all_package_files_pub(pkg_root);
            let hit = vuln_files.iter().any(|f| {
                f.contains('*') || !all_files.contains(f) || loaded.contains(f) || {
                    let prefix = format!("{f}/");
                    loaded.iter().any(|r| r.starts_with(&prefix))
                }
            });
            if hit {
                ("E0", Some(loaded))
            } else {
                ("E2", Some(loaded))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    #[test]
    fn e2_when_vuln_file_not_loaded() {
        if Command::new("node").arg("--version").output().is_err() {
            eprintln!("node unavailable, skipping");
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(root, "package.json", r#"{"name":"x","main":"index.js"}"#);
        write(root, "index.js", "require('./a.js');\n");
        write(root, "a.js", "module.exports = 1;\n");
        write(root, "vuln.js", "module.exports = 2;\n"); // never required
        let adv = serde_json::json!({
            "id": "GHSA-e2a",
            "affected": [{ "package": "x", "database_specific": { "vulnerable_files": ["vuln.js"] } }]
        });
        let (lvl, loaded) = evidence_level_e2(root, &adv, &root.join("index.js"));
        assert_eq!(lvl, "E2");
        let l = loaded.unwrap();
        assert!(l.contains("index.js") && l.contains("a.js"));
        assert!(!l.contains("vuln.js"));
    }

    #[test]
    fn e0_when_vuln_file_loaded() {
        if Command::new("node").arg("--version").output().is_err() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(root, "package.json", r#"{"name":"x","main":"index.js"}"#);
        write(root, "index.js", "require('./vuln.js');\n");
        write(root, "vuln.js", "module.exports = 2;\n");
        let adv = serde_json::json!({
            "id": "GHSA-e2b",
            "affected": [{ "package": "x", "database_specific": { "vulnerable_files": ["vuln.js"] } }]
        });
        let (lvl, _) = evidence_level_e2(root, &adv, &root.join("index.js"));
        assert_eq!(lvl, "E0");
    }

    #[test]
    fn e0_when_no_file_info() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        write(root, "package.json", r#"{"name":"x","main":"index.js"}"#);
        write(root, "index.js", "module.exports=1;\n");
        let adv = serde_json::json!({ "id": "GHSA-e2c", "affected": [{ "package": "x" }] });
        let (lvl, _) = evidence_level_e2(root, &adv, &root.join("index.js"));
        assert_eq!(lvl, "E0");
    }
}
