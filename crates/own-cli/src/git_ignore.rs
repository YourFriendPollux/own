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
