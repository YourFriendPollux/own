//! `own osv fetch` + `own check` (SPEC §8.2): download the OSV npm dump into
//! `.own/osv.json` (deterministic compact JSON), then evaluate E0 alerts
//! offline against the vendored packages.

use own_core::lock::parse_lock;
use own_net::{build_client, fetch_osv_dump, NetConfig};
use own_policy::semver;
use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;

pub const DEFAULT_OSV_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

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
            let mut ranges_out = Vec::new();
            if let Some(ranges) = aff.get("ranges").and_then(|r| r.as_array()) {
                for r in ranges {
                    let ty = r
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string();
                    if ty == "GIT" {
                        continue; // ignored per §8.2
                    }
                    let events: Vec<Value> = r
                        .get("events")
                        .and_then(|e| e.as_array())
                        .cloned()
                        .unwrap_or_default();
                    ranges_out.push(json!({ "type": ty, "events": events }));
                }
            }
            let versions: Vec<String> = aff
                .get("versions")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
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
    if raw.get("withdrawn").and_then(Value::as_str).is_some() {
        return Ok(None); // §8.2: withdrawn advisories are ignored
    }
    if raw
        .get("id")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err("PARSE_ERROR: OSV advisory without a usable id".to_string());
    }
    let affected = raw
        .get("affected")
        .and_then(Value::as_array)
        .ok_or_else(|| "PARSE_ERROR: OSV advisory without affected records".to_string())?;
    for record in affected {
        let ecosystem = record
            .get("package")
            .and_then(|p| p.get("ecosystem"))
            .and_then(Value::as_str)
            .unwrap_or("");
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
fn collect_advisories(
    bytes: &[u8],
    covered: &std::collections::HashSet<&String>,
) -> Result<Vec<Value>, String> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| format!("PARSE_ERROR: osv zip: {e}"))?;
    let max_entries = 2_000_000usize; // OSV npm dump has ~100k+ entries
    let mut advisories = Vec::new();
    for (entries, i) in (0..archive.len()).enumerate() {
        if entries > max_entries {
            return Err("NETWORK_ERROR: osv dump exceeds entry cap".to_string());
        }
        let mut f = archive
            .by_index(i)
            .map_err(|e| format!("IO_ERROR: osv zip entry: {e}"))?;
        if f.size() > 5 * 1_048_576 {
            // individual advisory files are small
            continue;
        }
        let mut s = String::new();
        f.read_to_string(&mut s)
            .map_err(|e| format!("IO_ERROR: osv entry: {e}"))?;
        let raw: Value = serde_json::from_str(&s)
            .map_err(|e| format!("PARSE_ERROR: osv zip entry {i} is not valid JSON: {e}"))?;
        let Some(reduced) = reduce_advisory_checked(&raw)? else {
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

/// `own osv fetch`: download dump, filter to lock packages, write .own/osv.json.
pub fn osv_fetch(
    root: &Path,
    osv_url: &str,
    max_download_mb: u64,
    now: Option<&str>,
) -> Result<u8, String> {
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let covered: Vec<String> = lock.packages.iter().map(|p| p.name.clone()).collect();
    let config = read_config(root)?;
    let output = config.local_path.as_deref().unwrap_or(".own/osv.json");
    let output_path = root.join(output);
    let client = build_client(&NetConfig::default())?;
    let download = fetch_osv_dump(&client, osv_url, max_download_mb)?;
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
        "schema_version": 1,
        "generated_at": generated_at,
        "source": osv_url,
        "source_last_modified": source_last_modified,
        "covered_packages": covered,
        "advisories": advisories,
    });
    // compact deterministic JSON (keys sorted via JCS)
    let canon = own_core::jcs::canonicalize(&doc).map_err(|e| format!("IO_ERROR: jcs: {e}"))?;
    let parent = output_path
        .parent()
        .ok_or_else(|| "IO_ERROR: OSV path has no parent".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| format!("IO_ERROR: {e}"))?;
    // atomic write
    let mut temp_name = output_path
        .file_name()
        .ok_or_else(|| "IO_ERROR: invalid OSV path".to_string())?
        .to_os_string();
    temp_name.push(".tmp");
    let tmp = output_path.with_file_name(temp_name);
    std::fs::write(&tmp, canon.as_bytes()).map_err(|e| format!("IO_ERROR: {e}"))?;
    std::fs::rename(&tmp, output_path).map_err(|e| format!("IO_ERROR: {e}"))?;
    println!(
        "wrote {} ({} advisories for {} packages)",
        output,
        advisories.len(),
        covered.len()
    );
    Ok(0)
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
    let text = std::fs::read_to_string(root.join("own.toml"))
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
        ranges: Vec<Range>,
    }
    #[derive(serde::Deserialize)]
    struct Range {
        #[serde(rename = "type")]
        kind: String,
        events: Vec<std::collections::BTreeMap<String, String>>,
    }
    let advisory: Advisory = serde_json::from_value(raw.clone())
        .map_err(|e| format!("PARSE_ERROR: OSV advisory: {e}"))?;
    let invalid = || "PARSE_ERROR: invalid OSV advisory".to_string();
    if advisory.id.is_empty() || advisory.aliases.iter().any(String::is_empty) {
        return Err(invalid());
    }
    for affected in advisory.affected {
        if affected.package.is_empty() || affected.versions.iter().any(String::is_empty) {
            return Err(invalid());
        }
        for range in affected.ranges {
            if !matches!(range.kind.as_str(), "SEMVER" | "ECOSYSTEM" | "GIT")
                || range.events.is_empty()
            {
                return Err(invalid());
            }
            for event in range.events {
                if event.len() != 1
                    || event.iter().any(|(key, value)| {
                        !matches!(
                            key.as_str(),
                            "introduced" | "fixed" | "last_affected" | "limit"
                        ) || value.is_empty()
                    })
                {
                    return Err(invalid());
                }
            }
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
    let lock_text =
        std::fs::read_to_string(root.join("own.lock")).map_err(|e| format!("IO_ERROR: {e}"))?;
    let lock = parse_lock(&lock_text).map_err(|e| format!("PARSE_ERROR: own.lock: {e}"))?;
    let config = read_config(root)?;
    let path = root.join(config.local_path.as_deref().unwrap_or(osv_local_path));
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
                    for (k, v) in &evs {
                        if k == "fixed" {
                            fixed.push(v.clone());
                        }
                    }
                    if semver::in_osv_range(&p.version, &evs) {
                        hit = true;
                        range_desc.push(format!("{:?}", evs));
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
                if versions.iter().any(|v| v == &p.version) {
                    hit = true;
                }
                if hit {
                    let mut level = "E0".to_string();
                    let mut reach_hash: Option<String> = None;
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
                        let (lvl, loaded) = own_slice::e2::evidence_level_e2(&dir, adv, &entry);
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
                        let (lvl, reach) =
                            own_slice::e1::evidence_level(&dir, adv, own_slice::ConsumerModel::Esm);
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
    fn http_source_date_is_written_as_canonical_utc_p2_02() {
        // Real header shape served by the OSV mirror.
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
