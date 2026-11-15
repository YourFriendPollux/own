//! `own osv fetch` + `own check` (SPEC §8.2): download the OSV npm dump into
//! `.own/osv.json` (deterministic compact JSON), then evaluate E0 alerts
//! offline against the vendored packages.

use own_core::lock::parse_lock;
use own_net::{build_client, fetch_osv_dump_configured};
use own_policy::semver;
use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;

fn valid_osv_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.-".contains(&b))
}

/// Reduce one OSV advisory to the fields `check` needs (§8.2).
fn reduce_advisory(a: &Value) -> Option<Value> {
    let id = a.get("id")?.as_str()?.to_string();
    if a.get("withdrawn").and_then(|w| w.as_str()).is_some() {
        return None;
    }
    let aliases: Vec<String> = a
        .get("aliases")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let mut affected_out = Vec::new();
    if let Some(affected) = a.get("affected").and_then(|x| x.as_array()) {
        for aff in affected {
            let ecosystem = aff
                .get("package")
                .and_then(|p| p.get("ecosystem"))
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .to_string();
            // Ecosystem first: a non-npm record must never make the npm
            // reduction of the same advisory depend on its own fields.
            if ecosystem != "npm" {
                continue;
            }
            let pkg = aff
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())?
                .to_string();
            if pkg.is_empty() {
                return None;
            }
            // Preserve present fields until typed validation. Converting a
            // malformed array/value to [] would silently erase constraints.
            // Unsupported range types must reach the validator too.
            let ranges_out = aff.get("ranges").cloned().unwrap_or_else(|| json!([]));
            let versions = aff.get("versions").cloned().unwrap_or_else(|| json!([]));
            let mut reduced = json!({ "package": pkg, "ranges": ranges_out, "versions": versions });
            // Keep hints attached to the original affected record: filtering
            // other ecosystems must never shift an E1 hint onto another package.
            for key in ["database_specific", "ecosystem_specific"] {
                if let Some(value) = aff.get(key) {
                    reduced[key] = value.clone();
                }
            }
            affected_out.push(reduced);
        }
    }
    let severity = a.get("severity").cloned();
    // Phase 2 (Annexe G): keep file-level hints for E1 evidence evaluation
    let obj = json!({
        "id": id,
        "aliases": aliases,
        "affected": affected_out,
        "severity": severity,
    });
    Some(obj)
}

/// Reduce one raw dump record, refusing anything structurally invalid.
///
/// The published dump is machine-generated: an entry that cannot be reduced is
/// evidence of a corrupt or truncated mirror, not something to drop quietly.
/// A dropped record would leave a snapshot that looks complete while missing an
/// advisory (`OSV_INCOMPLETE` only detects absent package names) — INV-5.
fn reduce_advisory_checked(raw: &Value) -> Result<Option<Value>, String> {
    let id = raw
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| valid_osv_id(id));
    let Some(id) = id else {
        return Err("PARSE_ERROR: OSV advisory without a usable id".to_string());
    };
    if let Some(aliases) = raw.get("aliases").filter(|value| !value.is_null()) {
        let aliases: Vec<String> = serde_json::from_value(aliases.clone())
            .map_err(|e| format!("PARSE_ERROR: OSV aliases: {e}"))?;
        if aliases.iter().any(|alias| !usable_osv_token(alias)) {
            return Err("PARSE_ERROR: invalid OSV alias".to_string());
        }
    }
    if let Some(withdrawn) = raw.get("withdrawn") {
        let withdrawn = withdrawn
            .as_str()
            .ok_or("PARSE_ERROR: OSV withdrawn must be a timestamp")?;
        timestamp_utc(withdrawn)?;
        return Ok(None); // §8.2: a valid withdrawn advisory is ignored
    }
    let affected = raw
        .get("affected")
        .and_then(Value::as_array)
        .ok_or_else(|| "PARSE_ERROR: OSV advisory without affected records".to_string())?;
    for record in affected {
        if !record.is_object() {
            return Err("PARSE_ERROR: OSV affected record must be an object".to_string());
        }
        // The OSV schema allows affected entries without package (for example
        // GIT-only entries). They cannot identify an npm package. A present
        // package, however, must not hide a missing or mistyped ecosystem.
        let Some(package) = record.get("package") else {
            let ranges: Vec<OsvRange> = serde_json::from_value(record["ranges"].clone())
                .map_err(|e| format!("PARSE_ERROR: OSV unattributed GIT ranges: {e}"))?;
            if ranges.is_empty() || ranges.iter().any(|r| r.kind != "GIT") {
                return Err(
                    "PARSE_ERROR: OSV record without package must have GIT ranges".to_string(),
                );
            }
            for range in &ranges {
                validate_range(range, id, "<no package>")?;
            }
            if let Some(versions) = record.get("versions") {
                let versions: Vec<String> = serde_json::from_value(versions.clone())
                    .map_err(|e| format!("PARSE_ERROR: OSV GIT versions: {e}"))?;
                if versions.iter().any(|v| !usable_osv_token(v)) {
                    return Err("PARSE_ERROR: invalid OSV GIT version".to_string());
                }
            }
            continue;
        };
        let ecosystem = package
            .get("ecosystem")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "PARSE_ERROR: OSV record without a string package ecosystem".to_string()
            })?;
        if ecosystem != "npm" {
            continue;
        }
        if record
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err("PARSE_ERROR: OSV npm record without a package name".to_string());
        }
    }
    match reduce_advisory(raw) {
        Some(reduced) => {
            validate_advisory(&reduced)?;
            Ok(Some(reduced))
        }
        None => Err("PARSE_ERROR: OSV advisory could not be reduced".to_string()),
    }
}

/// Read every zip entry in memory (§11.2 guards, never extracted to disk) and
/// keep the reduced advisories that touch a covered package.
pub(crate) fn collect_advisories(
    bytes: &[u8],
    covered: &std::collections::HashSet<&String>,
) -> Result<Vec<Value>, String> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| format!("PARSE_ERROR: osv zip: {e}"))?;
    let max_entries = 2_000_000usize; // OSV npm dump has ~100k+ entries
    if archive.len() > max_entries {
        return Err("NETWORK_ERROR: osv dump exceeds entry cap".to_string());
    }
    let max_entry_bytes = 5 * 1_048_576u64;
    let mut advisories = Vec::new();
    for i in 0..archive.len() {
        let mut f = archive
            .by_index(i)
            .map_err(|e| format!("IO_ERROR: osv zip entry: {e}"))?;
        if f.size() > max_entry_bytes {
            return Err(format!(
                "NETWORK_ERROR: osv zip entry {i} exceeds advisory byte cap"
            ));
        }
        let mut s = String::new();
        // Enforce the limit on decompressed bytes too, not only ZIP metadata.
        f.by_ref()
            .take(max_entry_bytes + 1)
            .read_to_string(&mut s)
            .map_err(|e| format!("IO_ERROR: osv entry: {e}"))?;
        if s.len() as u64 > max_entry_bytes {
            return Err(format!(
                "NETWORK_ERROR: osv zip entry {i} exceeds advisory byte cap"
            ));
        }
        let raw: Value = serde_json::from_str(&s)
            .map_err(|e| format!("PARSE_ERROR: osv zip entry {i} is not valid JSON: {e}"))?;
        let Some(reduced) = reduce_advisory_checked(&raw)
            .map_err(|e| format!("{e} (zip entry {i}: {:?})", f.name()))?
        else {
            continue;
        };
        let touches = reduced
            .get("affected")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter().any(|aff| {
                    aff.get("package")
                        .and_then(Value::as_str)
                        .map(|name| covered.contains(&name.to_string()))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        if touches {
            advisories.push(reduced);
        }
    }
    Ok(advisories)
}

/// Convert an HTTP `Last-Modified` header to the canonical RFC 3339 UTC form
/// written to `source_last_modified` (SPEC §8.2).
fn source_date_to_utc(header: &str) -> Result<String, String> {
    let date = httpdate::parse_http_date(header)
        .map_err(|e| format!("PARSE_ERROR: OSV Last-Modified: {e}"))?;
    let seconds = match date.duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()),
        Err(before) => i64::try_from(before.duration().as_secs()).map(|seconds| -seconds),
    }
    .map_err(|e| format!("PARSE_ERROR: OSV Last-Modified: {e}"))?;
    Ok(crate::sbom::epoch_to_rfc3339(seconds))
}

/// Test-only explicit URL/cap override; production calls `osv_fetch_project`.
#[allow(dead_code)]
pub fn osv_fetch(
    root: &Path,
    osv_url: &str,
    max_download_mb: u64,
    now: Option<&str>,
) -> Result<u8, String> {
    osv_fetch_inner(root, Some((osv_url, max_download_mb)), now)
}

/// Project entry: acquire URL/cap/client settings only after the exclusive lock.
pub fn osv_fetch_project(root: &Path, now: Option<&str>) -> Result<u8, String> {
    osv_fetch_inner(root, None, now)
}

fn osv_fetch_inner(
    root: &Path,
    source_override: Option<(&str, u64)>,
    now: Option<&str>,
) -> Result<u8, String> {
    // Lock before recovery, reading project state, preparing or publishing.
    let txn = own_core::txn::Txn::begin(root)?;
    let prepared = (|| {
        let root = &txn.root;
        let lock_text = std::fs::read_to_string(checked_input_path(root, "own.lock")?)
            .map_err(|e| format!("IO_ERROR: own.lock: {e}"))?;
        let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
        let covered: Vec<String> = lock.packages.iter().map(|p| p.name.clone()).collect();
        let config = read_config(root)?;
        let output = config.local_path.as_deref().unwrap_or(".own/osv.json");
        checked_snapshot_path(root, output)?;
        let settings = crate::project_config::load(root)?;
        let (osv_url, max_download_mb) =
            source_override.unwrap_or((&settings.osv_url, settings.osv_max_download_mb));
        let client = build_client(&settings.net)?;
        // The explicit test entry overrides only URL/cap, never the locked client.
        let download = fetch_osv_dump_configured(&client, &settings.net, osv_url, max_download_mb)?;
        let source_last_modified = download
            .last_modified
            .as_deref()
            .map(source_date_to_utc)
            .transpose()?;
        let covered_set: std::collections::HashSet<&String> = covered.iter().collect();
        let mut advisories = collect_advisories(&download.bytes, &covered_set)?;
        advisories.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let generated_at = match now {
            Some(now) => {
                timestamp_utc(now)?;
                now.to_string()
            }
            None => {
                let seconds = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| format!("IO_ERROR: clock: {e}"))?
                    .as_secs();
                crate::sbom::epoch_to_rfc3339(
                    i64::try_from(seconds).map_err(|e| format!("IO_ERROR: clock: {e}"))?,
                )
            }
        };
        let doc = json!({
            "schema_version": 1, "generated_at": generated_at, "source": osv_url,
            "source_last_modified": source_last_modified, "covered_packages": covered,
            "advisories": advisories,
        });
        let canon = own_core::jcs::canonicalize(&doc).map_err(|e| format!("IO_ERROR: jcs: {e}"))?;
        publish_snapshot(&txn, output, canon.as_bytes())?;
        Ok::<_, String>((output.to_string(), advisories.len(), covered.len()))
    })();
    let (output, advisory_count, package_count) = match prepared {
        Ok(result) => result,
        Err(error) => {
            return match txn.rollback() {
                Ok(()) => Err(error),
                Err(rollback) => Err(format!("{error}; rollback failed: {rollback}")),
            }
        }
    };
    txn.commit()?;
    println!("wrote {output} ({advisory_count} advisories for {package_count} packages)");
    Ok(0)
}

fn checked_input_path(root: &Path, rel: &str) -> Result<std::path::PathBuf, String> {
    own_core::path_safety::project_path(root, rel)
        .map_err(|e| format!("IO_ERROR: OSV_INPUT_REFUSED:{rel}: {e}"))
}

fn checked_snapshot_path(root: &Path, rel: &str) -> Result<std::path::PathBuf, String> {
    let path = Path::new(rel);
    if path == Path::new(".own/lock")
        || path.starts_with(".own/tmp")
        || path.starts_with(".own/txn")
        || path.starts_with("vendor")
        || path.components().any(|c| c.as_os_str() == ".git")
        || path.starts_with(".own/cache") && path.extension().is_some_and(|ext| ext == "tgz")
        || [
            "own.lock",
            "own.toml",
            "package.json",
            "pnpm-lock.yaml",
            "package-lock.json",
            "npm-shrinkwrap.json",
            ".gitignore",
        ]
        .iter()
        .any(|name| path.file_name().is_some_and(|leaf| leaf == *name))
    {
        return Err("PARSE_ERROR: OSV_OUTPUT_REFUSED:sensitive".to_string());
    }
    let target = own_core::path_safety::project_path(root, rel)
        .map_err(|e| format!("IO_ERROR: OSV_OUTPUT_REFUSED:path: {e}"))?;
    match std::fs::symlink_metadata(&target) {
        Ok(metadata) if !metadata.is_file() => {
            return Err("IO_ERROR: OSV_OUTPUT_REFUSED:not_file".to_string())
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("IO_ERROR: OSV_OUTPUT_REFUSED:path: {e}")),
    }
    Ok(target)
}

fn publish_snapshot(txn: &own_core::txn::Txn, output: &str, bytes: &[u8]) -> Result<(), String> {
    // Recheck real filesystem components after a potentially long download.
    checked_snapshot_path(&txn.root, output)?;
    let mut prefix = std::path::PathBuf::new();
    for component in Path::new(output)
        .parent()
        .unwrap_or(Path::new(""))
        .components()
    {
        prefix.push(component.as_os_str());
        let rel = prefix.to_str().ok_or("IO_ERROR: OSV parent is not UTF-8")?;
        let parent = own_core::path_safety::project_path(&txn.root, rel)
            .map_err(|e| format!("IO_ERROR: OSV_OUTPUT_REFUSED:path: {e}"))?;
        match std::fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.is_dir() => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Persist rollback intent BEFORE each new directory. Sync both
                // its containing entry and the new directory before publishing.
                txn.note_created_dir(rel)?;
                std::fs::create_dir(&parent).map_err(|e| format!("IO_ERROR: OSV parent: {e}"))?;
                sync_snapshot_dir(
                    parent
                        .parent()
                        .ok_or("IO_ERROR: OSV parent has no parent")?,
                )?;
                sync_snapshot_dir(&parent)?;
            }
            Ok(_) => return Err("IO_ERROR: OSV_OUTPUT_REFUSED:parent".to_string()),
            Err(e) => return Err(format!("IO_ERROR: OSV parent: {e}")),
        }
    }
    checked_snapshot_path(&txn.root, output)?;
    // Txn backs up and syncs the journal/original, then syncs its private
    // temporary before rename and syncs the destination directory afterwards.
    txn.write_file(output, bytes)
}

fn sync_snapshot_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| format!("IO_ERROR: OSV directory sync: {e}"))
    }
    #[cfg(not(unix))]
    {
        let _ = path; // same platform limitation as own_core::Txn
        Ok(())
    }
}

pub struct CheckArgs {
    #[allow(dead_code)] // --remote handled in CLI before calling check()
    pub remote: bool,
    pub allow_stale_osv: bool,
    pub allow_missing_osv: bool,
    pub now: Option<String>,
    pub max_age_days: u32,
    /// Phase 2: compute E1 reachability evidence per alert (SPEC §9.4)
    pub e1: bool,
    /// Phase 2: compute E2 executed-reachability evidence (requires node)
    pub e2: bool,
}

pub struct Alert {
    pub advisory_id: String,
    pub aliases: Vec<String>,
    pub package: String,
    pub current_version: String,
    pub affected_ranges: Vec<String>,
    pub fixed_versions: Vec<String>,
    pub evidence_level: String,
    /// Phase 2: sha256 (JCS) of the sorted reachable file set when E1 was computed
    pub reachable_sha256: Option<String>,
}

#[derive(serde::Deserialize)]
struct Snapshot {
    schema_version: u32,
    generated_at: String,
    source: String,
    source_last_modified: Option<String>,
    covered_packages: Vec<String>,
    advisories: Vec<Value>,
}

#[derive(Default, serde::Deserialize)]
struct OsvConfig {
    local_path: Option<String>,
    max_age_days: Option<u32>,
    #[serde(default)]
    ignore: Vec<OsvIgnore>,
}

#[derive(serde::Deserialize)]
struct OsvIgnore {
    id: String,
    reason: String,
    expires: String,
}

fn read_config(root: &Path) -> Result<OsvConfig, String> {
    #[derive(serde::Deserialize)]
    struct Config {
        #[serde(default)]
        osv: OsvConfig,
    }
    let text = std::fs::read_to_string(checked_input_path(root, "own.toml")?)
        .map_err(|e| format!("IO_ERROR: own.toml: {e}"))?;
    let mut config: Config =
        toml::from_str(&text).map_err(|e| format!("PARSE_ERROR: own.toml: {e}"))?;
    for key in ["OWN_OSV_LOCAL_PATH", "OWN_OSV_MAX_AGE_DAYS"] {
        match std::env::var(key) {
            Ok(value) => {
                if key == "OWN_OSV_LOCAL_PATH" {
                    config.osv.local_path = Some(value);
                } else {
                    config.osv.max_age_days = Some(
                        value
                            .parse()
                            .map_err(|e| format!("PARSE_ERROR: {key}: {e}"))?,
                    );
                }
            }
            Err(std::env::VarError::NotPresent) => {}
            Err(_) => return Err(format!("PARSE_ERROR: {key}: invalid UTF-8")),
        }
    }
    for entry in &config.osv.ignore {
        if entry.id.trim().is_empty() || entry.reason.trim().is_empty() {
            return Err("PARSE_ERROR: OSV ignore requires a nonempty id and reason".to_string());
        }
        timestamp_utc(&format!("{}T00:00:00Z", entry.expires))?;
    }
    if let Some(path) = &config.osv.local_path {
        let path = Path::new(path);
        if path.file_name().is_none()
            || !path.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )
            })
        {
            return Err("PARSE_ERROR: OSV local_path must be a project-relative file path without parent components".to_string());
        }
    }
    Ok(config.osv)
}

/// Validate the complete npm version token, not just an evaluator's loose
/// numeric prefix. Keep OSV's introduced="0" sentinel outside this grammar.
fn valid_npm_osv_version(text: &str) -> bool {
    let text = text.strip_prefix('v').unwrap_or(text);
    let identifier = |part: &str| {
        !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    let (version, build) = match text.split_once('+') {
        Some((version, build)) => (version, Some(build)),
        None => (text, None),
    };
    if build.is_some_and(|build| !build.split('.').all(identifier)) {
        return false;
    }
    let (core, pre) = match version.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (version, None),
    };
    let numeric = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'))
    };
    if core.split('.').count() != 3 || !core.split('.').all(numeric) {
        return false;
    }
    if pre.is_some_and(|pre| {
        !pre.split('.').all(|part| {
            identifier(part) && (!part.bytes().all(|b| b.is_ascii_digit()) || numeric(part))
        })
    }) {
        return false;
    }
    semver::is_valid_version(text)
}

#[derive(serde::Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: String,
    events: Vec<std::collections::BTreeMap<String, String>>,
    repo: Option<String>,
}

fn usable_osv_token(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn validate_range(range: &OsvRange, id: &str, package: &str) -> Result<(), String> {
    let invalid = || {
        format!(
            "PARSE_ERROR: invalid OSV advisory {id:?}: {} range for {package:?}",
            range.kind
        )
    };
    if !matches!(range.kind.as_str(), "SEMVER" | "ECOSYSTEM" | "GIT") {
        return Err(format!(
            "PARSE_ERROR: unsupported OSV range type {}",
            range.kind
        ));
    }
    if range.kind == "GIT"
        && range
            .repo
            .as_deref()
            .is_none_or(|repo| !usable_osv_token(repo))
    {
        return Err(invalid());
    }
    let has = |kind: &str| range.events.iter().any(|event| event.contains_key(kind));
    if !has("introduced") || (has("fixed") && has("last_affected")) {
        return Err(invalid());
    }
    for event in &range.events {
        if event.len() != 1
            || event.iter().any(|(key, value)| {
                !matches!(
                    key.as_str(),
                    "introduced" | "fixed" | "last_affected" | "limit"
                ) || !usable_osv_token(value)
                    || !(key == "introduced" && value == "0"
                        || key == "limit" && value.contains('*')
                        || match range.kind.as_str() {
                            "SEMVER" => valid_npm_osv_version(value),
                            "ECOSYSTEM" => true, // uninterpreted by schema; unknown at evaluation
                            "GIT" => {
                                matches!(value.len(), 40 | 64)
                                    && value.bytes().all(|b| b.is_ascii_hexdigit())
                            }
                            _ => false,
                        })
            })
        {
            return Err(format!("{}: event {event:?}", invalid()));
        }
    }
    Ok(())
}

fn validate_advisory(raw: &Value) -> Result<(), String> {
    #[derive(serde::Deserialize)]
    struct Advisory {
        id: String,
        #[serde(default)]
        aliases: Vec<String>,
        affected: Vec<Affected>,
    }
    #[derive(serde::Deserialize)]
    struct Affected {
        package: String,
        #[serde(default)]
        versions: Vec<String>,
        #[serde(default)]
        ranges: Vec<OsvRange>,
    }
    let advisory: Advisory = serde_json::from_value(raw.clone())
        .map_err(|e| format!("PARSE_ERROR: OSV advisory: {e}"))?;
    let invalid = || format!("PARSE_ERROR: invalid OSV advisory {:?}", advisory.id);
    if !valid_osv_id(&advisory.id)
        || advisory
            .aliases
            .iter()
            .any(|alias| !usable_osv_token(alias))
    {
        return Err(invalid());
    }
    for affected in advisory.affected {
        if affected.package.is_empty() {
            return Err(invalid());
        }
        // Git ranges can enumerate repository tags as well as npm releases.
        // ECOSYSTEM versions are also opaque by schema; keep them, never infer
        // unaffected from a version list/range our evaluator cannot interpret.
        let opaque_versions = affected
            .ranges
            .iter()
            .any(|r| matches!(r.kind.as_str(), "GIT" | "ECOSYSTEM"));
        if let Some(value) = affected.versions.iter().find(|value| {
            !usable_osv_token(value)
                || !opaque_versions && semver::parse_osv_ecosystem_version(value).is_none()
        }) {
            return Err(format!(
                "PARSE_ERROR: invalid OSV advisory {:?}: npm version {:?} for {:?}",
                advisory.id, value, affected.package
            ));
        }
        for range in affected.ranges {
            validate_range(&range, &advisory.id, &affected.package)?;
        }
    }
    Ok(())
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct UtcTimestamp {
    seconds: i64,
    // Canonical decimal fraction without trailing zeros. Lexical ordering is
    // exact for any precision and does not round values at the age deadline.
    fraction: String,
}

fn timestamp_utc(text: &str) -> Result<UtcTimestamp, String> {
    let invalid = || "PARSE_ERROR: invalid UTC RFC3339 timestamp".to_string();
    if !text.is_ascii() {
        return Err(invalid());
    }
    let core = text
        .strip_suffix('Z')
        .or_else(|| text.strip_suffix("+00:00"))
        .ok_or_else(invalid)?;
    if core.len() < 19 {
        return Err(invalid());
    }
    let fraction = match &core[19..] {
        "" => String::new(),
        suffix => {
            let digits = suffix.strip_prefix('.').ok_or_else(invalid)?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            digits.trim_end_matches('0').to_string()
        }
    };
    let b = core.as_bytes();
    for (i, delimiter) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
        if b[i] != delimiter {
            return Err(invalid());
        }
    }
    let number = |range: std::ops::Range<usize>| -> Result<i64, String> {
        if !b[range.clone()].iter().all(u8::is_ascii_digit) {
            return Err(invalid());
        }
        text[range].parse().map_err(|_| invalid())
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return Err(invalid()),
    };
    if !(1..=max_day).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return Err(invalid());
    }
    // Gregorian civil date to Unix days, inverse of the SBOM formatter.
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(UtcTimestamp {
        seconds: (era * 146_097 + doe - 719_468) * 86_400 + hour * 3600 + minute * 60 + second,
        fraction,
    })
}

/// `own check` (offline, E0): evaluate .own/osv.json against the lock (§8.2).
pub fn check(
    root: &Path,
    args: &CheckArgs,
    osv_local_path: &str,
) -> Result<(Vec<Alert>, Vec<String>), String> {
    let lock_text = std::fs::read_to_string(checked_input_path(root, "own.lock")?)
        .map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let config = read_config(root)?;
    let path = checked_snapshot_path(root, config.local_path.as_deref().unwrap_or(osv_local_path))?;
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if args.allow_missing_osv {
                return Ok((vec![], vec!["W_OSV_MISSING".to_string()]));
            }
            return Err("OSV_MISSING".to_string());
        }
        Err(error) => return Err(format!("IO_ERROR: OSV snapshot: {error}")),
    };
    let doc: Snapshot =
        serde_json::from_str(&text).map_err(|e| format!("PARSE_ERROR: osv.json: {e}"))?;
    if doc.schema_version != 1 || doc.source.is_empty() {
        return Err("PARSE_ERROR: invalid OSV snapshot schema or source".to_string());
    }
    for advisory in &doc.advisories {
        validate_advisory(advisory)?;
    }
    let snapshot_time = timestamp_utc(&doc.generated_at)?;
    let source_time = doc
        .source_last_modified
        .as_deref()
        .map(timestamp_utc)
        .transpose()?;
    // freshness
    let now_time = match &args.now {
        Some(now) => timestamp_utc(now)?,
        None => {
            let elapsed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("IO_ERROR: clock: {e}"))?;
            UtcTimestamp {
                seconds: i64::try_from(elapsed.as_secs())
                    .map_err(|e| format!("IO_ERROR: clock: {e}"))?,
                fraction: format!("{:09}", elapsed.subsec_nanos())
                    .trim_end_matches('0')
                    .to_string(),
            }
        }
    };
    if snapshot_time > now_time {
        return Err("PARSE_ERROR: OSV generated_at is in the future".to_string());
    }
    // §8.2 risk table ("a mirror that lies about its dates"): a source date
    // later than the real clock is refused, and --allow-stale-osv, which only
    // downgrades OSV_STALE, cannot mask it. The mirror cannot know an injected
    // OWN_NOW, so this plausibility check reads the system clock, never
    // `args.now` — otherwise a live fetch under a pinned CI clock would be
    // rejected for telling the truth.
    if let Some(source_time) = source_time {
        let real_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("IO_ERROR: clock: {e}"))?;
        if i64::try_from(real_now.as_secs()).map_err(|e| format!("IO_ERROR: clock: {e}"))?
            < source_time.seconds
        {
            return Err("PARSE_ERROR: OSV source_last_modified is in the future".to_string());
        }
    }
    let age_seconds = now_time.seconds - snapshot_time.seconds;
    let max_age_days = config.max_age_days.unwrap_or(args.max_age_days);
    let max_age_seconds = i64::from(max_age_days) * 86_400;
    let mut warnings = Vec::new();
    if age_seconds > max_age_seconds
        || (age_seconds == max_age_seconds && now_time.fraction > snapshot_time.fraction)
    {
        if args.allow_stale_osv {
            warnings.push("W_OSV_STALE".to_string());
        } else {
            return Err("OSV_STALE".to_string());
        }
    }
    // completeness: every lock package must be covered
    let covered = &doc.covered_packages;
    for p in &lock.packages {
        if !covered.contains(&p.name) {
            return Err("OSV_INCOMPLETE".to_string());
        }
    }
    let mut ignored_ids = Vec::new();
    for entry in &config.ignore {
        let expiration = timestamp_utc(&format!("{}T00:00:00Z", entry.expires))?.seconds + 86_400;
        if now_time.seconds < expiration {
            ignored_ids.push(entry.id.as_str());
        } else {
            warnings.push(format!("W_IGNORE_EXPIRED: {}", entry.id));
        }
    }
    let mut alerts = Vec::new();
    for p in &lock.packages {
        for adv in &doc.advisories {
            let id = adv
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let aliases: Vec<String> = adv
                .get("aliases")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            if ignored_ids.contains(&id.as_str())
                || aliases
                    .iter()
                    .any(|alias| ignored_ids.contains(&alias.as_str()))
            {
                continue;
            }
            for aff in adv
                .get("affected")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let pkg = aff.get("package").and_then(|p| p.as_str()).unwrap_or("");
                if pkg != p.name {
                    continue;
                }
                let mut hit = false;
                let mut range_desc = Vec::new();
                let mut fixed = Vec::new();
                let mut unevaluable = Vec::new();
                for r in aff
                    .get("ranges")
                    .and_then(|r| r.as_array())
                    .cloned()
                    .unwrap_or_default()
                {
                    let evs: Vec<(String, String)> = r
                        .get("events")
                        .and_then(|e| e.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|e| {
                                    let obj = e.as_object()?;
                                    let (k, val) = obj.iter().next()?;
                                    Some((k.clone(), val.as_str()?.to_string()))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let kind = r["type"].as_str().unwrap(); // validated above
                    let evaluated = if kind == "GIT" {
                        None // a commit graph cannot be inferred from a release version
                    } else {
                        semver::evaluate_osv_range(&p.version, &evs)
                    };
                    if evaluated.is_some() {
                        for (k, v) in &evs {
                            if k == "fixed" {
                                fixed.push(v.clone());
                            }
                        }
                    }
                    match evaluated {
                        Some(true) => {
                            hit = true;
                            range_desc.push(format!("{evs:?}"));
                        }
                        Some(false) => {}
                        None => unevaluable.push(kind.to_string()),
                    }
                }
                let versions: Vec<String> = aff
                    .get("versions")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                // An explicit ecosystem version is a point, not a wildcard:
                // e.g. 12.0 may conservatively identify 12.0.0, never 12.0.1.
                let current = semver::parse_osv_ecosystem_version(&p.version);
                if versions.iter().any(|v| {
                    v == &p.version
                        || current.as_ref().is_some_and(|current| {
                            semver::parse_osv_ecosystem_version(v).as_ref() == Some(current)
                        })
                }) {
                    hit = true;
                }
                if !hit {
                    if versions
                        .iter()
                        .any(|v| semver::parse_osv_ecosystem_version(v).is_none())
                    {
                        unevaluable.push("versions".to_string());
                    }
                    if !unevaluable.is_empty() {
                        unevaluable.sort();
                        unevaluable.dedup();
                        return Err(format!(
                            "OSV_UNEVALUABLE: {id}: {}: {}",
                            p.name,
                            unevaluable.join(",")
                        ));
                    }
                }
                if hit {
                    let mut level = "E0".to_string();
                    let mut reach_hash: Option<String> = None;
                    // Applicability belongs to this exact package/version
                    // record, not every package or platform of the advisory.
                    let evidence_advisory = json!({"id": id, "affected": [aff]});
                    if args.e2 {
                        // E2 needs an entry file: use main from package.json
                        let dir = root.join(&p.dir);
                        let entry = std::fs::read_to_string(dir.join("package.json"))
                            .ok()
                            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                            .and_then(|v| {
                                v.get("main")
                                    .and_then(|m| m.as_str())
                                    .map(|s| s.to_string())
                            })
                            .map(|m| dir.join(m))
                            .unwrap_or_else(|| dir.join("index.js"));
                        let (lvl, loaded) =
                            own_slice::e2::evidence_level_e2(&dir, &evidence_advisory, &entry);
                        if lvl == "E2" {
                            level = "E2".to_string();
                        } else if args.e1 {
                            // fall back to E1
                        }
                        if let Some(r) = loaded {
                            let mut v: Vec<&String> = r.iter().collect();
                            v.sort();
                            let j = serde_json::to_string(&v).unwrap_or_default();
                            reach_hash = Some(own_core::sha256_hex(j.as_bytes()));
                        }
                    }
                    if args.e1 && level == "E0" {
                        let dir = root.join(&p.dir);
                        let (lvl, reach) = own_slice::e1::evidence_level(
                            &dir,
                            &evidence_advisory,
                            own_slice::ConsumerModel::Esm,
                        );
                        level = lvl.to_string();
                        if let Some(r) = reach {
                            let mut v: Vec<&String> = r.iter().collect();
                            v.sort();
                            let j = serde_json::to_string(&v).unwrap_or_default();
                            reach_hash = Some(own_core::sha256_hex(j.as_bytes()));
                        }
                    }
                    alerts.push(Alert {
                        advisory_id: id.clone(),
                        aliases: aliases.clone(),
                        package: p.name.clone(),
                        current_version: p.version.clone(),
                        affected_ranges: range_desc,
                        fixed_versions: fixed,
                        evidence_level: level,
                        reachable_sha256: reach_hash,
                    });
                }
            }
        }
    }
    Ok((alerts, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    // All unit documents, ZIPs, HTTP dates and filesystem states here are
    // synthetic fixtures. Only the explicit integration live tests use OSV data.

    struct SyntheticSnapshotFixture(std::path::PathBuf);
    impl SyntheticSnapshotFixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "own-osv-publish-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for SyntheticSnapshotFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn synthetic_snapshot_new_parents_are_journaled_before_publication() {
        let fixture = SyntheticSnapshotFixture::new();
        let txn = own_core::txn::Txn::begin(&fixture.0).unwrap();
        publish_snapshot(&txn, "cache/deep/osv.json", b"synthetic-snapshot-bytes").unwrap();
        let journal: Value =
            serde_json::from_slice(&std::fs::read(txn.txn_dir.join("journal.json")).unwrap())
                .unwrap();
        assert_eq!(journal["created_dirs"], json!(["cache", "cache/deep"]));
        assert_eq!(journal["state"], "started");
        assert_eq!(
            std::fs::read(fixture.0.join("cache/deep/osv.json")).unwrap(),
            b"synthetic-snapshot-bytes"
        );
        txn.rollback().unwrap();
    }

    #[test]
    fn synthetic_snapshot_rollback_removes_all_new_parent_directories() {
        let fixture = SyntheticSnapshotFixture::new();
        let txn = own_core::txn::Txn::begin(&fixture.0).unwrap();
        publish_snapshot(&txn, "cache/deep/osv.json", b"synthetic-snapshot-bytes").unwrap();
        txn.rollback().unwrap();
        assert!(
            !fixture.0.join("cache").exists(),
            "rollback must undo the entire OSV path creation"
        );
        assert_eq!(
            std::fs::read_dir(fixture.0.join(".own/txn"))
                .unwrap()
                .count(),
            0
        );
    }

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in entries {
            writer
                .start_file(
                    *name,
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored),
                )
                .unwrap();
            std::io::Write::write_all(&mut writer, body).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn covered_one() -> std::collections::HashSet<&'static String> {
        static A: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| "a".to_string());
        [&*A].into_iter().collect()
    }

    #[test]
    fn synthetic_ecosystem_partial_bound_is_kept_and_evaluated() {
        let raw = json!({"id":"GHSA-3h52-269p-cp9r", "affected":[{"package":{"name":"next", "ecosystem":"npm"}, "ranges":[{"type":"ECOSYSTEM", "events":[{"introduced":"13.0"},{"fixed":"14.2.30"}]}]}]});
        let reduced = reduce_advisory_checked(&raw).unwrap().unwrap();
        assert_eq!(
            reduced["affected"][0]["ranges"][0]["events"][0]["introduced"],
            "13.0"
        );
        let events = vec![
            ("introduced".into(), "13.0".into()),
            ("fixed".into(), "14.2.30".into()),
        ];
        assert!(semver::in_osv_range("14.2.29", &events));
        assert!(!semver::in_osv_range("14.2.30", &events));
    }

    #[test]
    fn http_source_date_is_written_as_canonical_utc_p2_02() {
        // Synthetic headers in the format used by the OSV mirror.
        assert_eq!(
            source_date_to_utc("Sat, 14 Nov 2026 08:33:14 GMT").unwrap(),
            "2026-11-14T08:33:14Z"
        );
        assert_eq!(
            source_date_to_utc("Thu, 01 Jan 1970 00:00:00 GMT").unwrap(),
            "1970-01-01T00:00:00Z"
        );
        // A pre-epoch header is refused, never wrapped into 1970.
        assert!(source_date_to_utc("Wed, 31 Dec 1969 23:59:59 GMT")
            .expect_err("pre-epoch date is refused")
            .starts_with("PARSE_ERROR"));
        let error = source_date_to_utc("not a date").expect_err("garbage must be refused");
        assert!(error.starts_with("PARSE_ERROR"), "{error}");
    }

    #[test]
    fn corrupt_osv_zip_entry_is_refused_not_skipped_p2_02() {
        let bytes = zip_of(&[
            ("GHSA-ok.json", br#"{"id":"GHSA-ok","affected":[{"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]}]}"#),
            ("truncated.json", b"{\"id\":\"GHSA-broken\",\"affected\":["),
        ]);
        let error = collect_advisories(&bytes, &covered_one())
            .expect_err("a truncated dump member must not be dropped silently");
        assert!(error.starts_with("PARSE_ERROR"), "{error}");
    }

    #[test]
    fn malformed_npm_record_for_unvendored_package_is_refused_p2_02() {
        // The record names no package, so it cannot be attributed: skipping it
        // would hide corruption for a package that may be vendored later.
        let bytes = zip_of(&[(
            "GHSA-nameless.json",
            br#"{"id":"GHSA-nameless","affected":[{"package":{"ecosystem":"npm"},"versions":["1.0.0"]}]}"#,
        )]);
        let error = collect_advisories(&bytes, &covered_one())
            .expect_err("a nameless npm record must not be dropped silently");
        assert!(error.starts_with("PARSE_ERROR"), "{error}");
    }

    #[test]
    fn well_formed_advisory_for_unvendored_package_is_skipped_without_error_p2_02() {
        let bytes = zip_of(&[
            (
                "GHSA-other.json",
                br#"{"id":"GHSA-other","affected":[{"package":{"ecosystem":"npm","name":"z-other"},"versions":["2.0.0"]}]}"#,
            ),
            (
                "GHSA-a.json",
                br#"{"id":"GHSA-a","affected":[{"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]}]}"#,
            ),
        ]);
        let kept = collect_advisories(&bytes, &covered_one()).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["id"], "GHSA-a");
    }

    #[test]
    fn non_npm_record_cannot_break_the_npm_reduction_p2_04() {
        // Reordering the ecosystem filter must keep a malformed non-npm record
        // from discarding the npm record of the same advisory.
        let bytes = zip_of(&[(
            "GHSA-mixed.json",
            br#"{"id":"GHSA-mixed","affected":[{"package":{"ecosystem":"PyPI"}},{"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]}]}"#,
        )]);
        let kept = collect_advisories(&bytes, &covered_one()).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["affected"][0]["package"], "a");
    }

    #[test]
    fn reduced_hints_stay_with_their_package_after_ecosystem_filtering_p2_04() {
        let advisory = json!({
            "id": "GHSA-fixture-package-hints",
            "affected": [
                {
                    "package": {"name": "python-fixture", "ecosystem": "PyPI"},
                    "database_specific": {"vulnerable_files": ["python-only.py"]},
                    "ecosystem_specific": {"vulnerable_files": ["wrong-npm-file.js"]}
                },
                {
                    "package": {"name": "a", "ecosystem": "npm"},
                    "versions": ["1.0.0"],
                    "database_specific": {"vulnerable_files": ["a.js"]},
                    "ecosystem_specific": {"vulnerable_files": ["a-extra.js"]}
                },
                {
                    "package": {"name": "b", "ecosystem": "npm"},
                    "versions": ["2.0.0"],
                    "database_specific": {"vulnerable_files": ["b.js"]}
                }
            ]
        });
        let reduced = reduce_advisory(&advisory).unwrap();
        let affected = reduced["affected"].as_array().unwrap();
        assert_eq!(affected.len(), 2);
        assert_eq!(affected[0]["package"], "a");
        assert_eq!(
            affected[0]["database_specific"]["vulnerable_files"],
            json!(["a.js"])
        );
        assert_eq!(
            affected[0]["ecosystem_specific"]["vulnerable_files"],
            json!(["a-extra.js"])
        );
        assert_eq!(affected[1]["package"], "b");
        assert_eq!(
            affected[1]["database_specific"]["vulnerable_files"],
            json!(["b.js"])
        );
        assert!(affected[1].get("ecosystem_specific").is_none());
        validate_advisory(&reduced).unwrap();
    }
}
