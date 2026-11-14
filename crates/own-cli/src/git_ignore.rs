//! Shared, deadlock-free git-ignore probe for add and CI.
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn ignored_paths(root: &Path, paths: &[String]) -> Result<Vec<String>, String> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut child = Command::new("git")
        .args(["check-ignore", "--no-index", "-z", "--stdin"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("GIT_ERROR: {e}"))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    // Drain stdout/stderr while feeding stdin. Writing all paths first can
    // deadlock once both pipes fill for a large ignored vendor tree.
    let out = std::thread::scope(|scope| {
        let writer = scope.spawn(move || -> std::io::Result<()> {
            for path in paths {
                stdin.write_all(path.as_bytes())?;
                stdin.write_all(&[0])?;
            }
            Ok(())
        });
        let output = child.wait_with_output();
        let written = writer
            .join()
            .map_err(|_| "GIT_ERROR: stdin writer panicked".to_string())?;
        let output = output.map_err(|e| format!("GIT_ERROR: {e}"))?;
        if !matches!(output.status.code(), Some(0 | 1)) {
            // Outside a work tree git refuses to answer at all (exit 128,
            // "fatal: not a git repository"). Nothing can be ignored without a
            // repository, so the probe answers "nothing ignored" rather than
            // failing the command: a project with no VCS is legitimate and
            // `own init` accepts one. Every other failure stays an error — a
            // corrupt repository, a dubious-ownership config or a missing git
            // must not be read as "no ignore rules" (INV-4: doubt fails closed).
            let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            if output.status.code() == Some(128) && stderr.contains("not a git repository") {
                // The writer's broken pipe is expected here: git exits before it
                // reads stdin, so it must not turn this answer into an error.
                return Ok(output);
            }
            return Err(format!(
                "GIT_ERROR: check-ignore exited {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        written.map_err(|e| format!("GIT_ERROR: {e}"))?;
        Ok(output)
    })?;
    out.stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| {
            String::from_utf8(p.to_vec())
                .map_err(|e| format!("GIT_ERROR: invalid path encoding: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("own-gitignore-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn git(dir: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn outside_a_repository_nothing_is_ignored_and_nothing_fails() {
        let dir = tmp("norepo");
        let paths = vec!["vendor/own/a/index.js".to_string()];
        let ignored = ignored_paths(&dir, &paths).expect("a missing repository is not an error");
        assert!(
            ignored.is_empty(),
            "expected no ignored paths, got {ignored:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_repository_without_rules_ignores_nothing() {
        let dir = tmp("norules");
        if !git(&dir, &["init", "-q"]) {
            eprintln!("git unavailable, skipping");
            return;
        }
        let paths = vec!["vendor/own/a/index.js".to_string()];
        let ignored = ignored_paths(&dir, &paths).expect("probe");
        assert!(
            ignored.is_empty(),
            "expected no ignored paths, got {ignored:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_repository_rule_is_still_reported() {
        let dir = tmp("rules");
        if !git(&dir, &["init", "-q"]) {
            eprintln!("git unavailable, skipping");
            return;
        }
        std::fs::write(dir.join(".gitignore"), "vendor/\n").unwrap();
        let paths = vec!["vendor/own/a/index.js".to_string()];
        let ignored = ignored_paths(&dir, &paths).expect("probe");
        assert_eq!(ignored, paths, "the rule must still be reported");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
