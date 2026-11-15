//! Shared fail-closed checks for paths beneath a canonical project root.
//! Symlinks are rejected at every existing component, including the leaf.
//! These checks do not provide isolation from concurrent filesystem changes.

use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Component, Path, PathBuf};

/// Resolve a project-relative path without traversing any existing symlink.
/// Call this before direct creation/extraction, including .own/tmp children.
/// Missing descendants are allowed; existing special files are refused.
pub fn project_path(root: &Path, rel: &str) -> io::Result<PathBuf> {
    checked_path(&fs::canonicalize(root)?, rel)
}

pub(crate) fn validate_relative(rel: &str) -> io::Result<()> {
    if rel.is_empty()
        || rel.contains('\\')
        || rel
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || Path::new(rel)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "unsafe relative path",
        ));
    }
    Ok(())
}

pub(crate) fn checked_path(root: &Path, rel: &str) -> io::Result<PathBuf> {
    validate_relative(rel)?;
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "unsafe root directory",
        ));
    }
    let mut path = root.to_path_buf();
    let parts: Vec<_> = Path::new(rel).components().collect();
    for (i, part) in parts.iter().enumerate() {
        path.push(part.as_os_str());
        match fs::symlink_metadata(&path) {
            Ok(md) => {
                if md.file_type().is_symlink()
                    || (!md.is_file() && !md.is_dir())
                    || (i + 1 < parts.len() && !md.is_dir())
                {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("unsafe path component: {}", path.display()),
                    ));
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(path)
}

pub(crate) fn checked_absolute(root: &Path, path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let rel = absolute
        .strip_prefix(root)
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "path outside project root"))?
        .to_str()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "path is not UTF-8"))?;
    checked_path(root, rel)
}
