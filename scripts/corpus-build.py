#!/usr/bin/env python3
"""Regenerate scripts/corpus.txt from a measured npm weekly-download ranking.

The corpus feeds the SPEC §13 acceptance line "≥ 15 packages out of a corpus of
at least 100 are eligible under §9.1 (types and size aside)". It is data, not a
hand-written list: a candidate pool is harvested from the npm search API, ranked
by measured weekly downloads, and the top 250 are kept.

Eligibility is measured here with the same criteria as
`crates/own-policy/src/eligibility.rs` (packument-level only):

  dependencies (none vendored -> must be empty), peerDependencies,
  optionalDependencies, bundledDependencies, the install scripts pnpm would run
  (preinstall|install|postinstall; `prepare` is not blocking in the code),
  gypfile, bin / directories.bin, os/cpu/libc, dist.integrity carrying sha512,
  and a valid semver without build metadata.

Not measurable from the packument, so not claimed here: native binaries inside
the tarball, a binding.gyp inside the archive, license-file UTF-8, the §9.3
license allowlist, and the size limits (excluded on purpose, as in the spec).

Usage: python3 scripts/corpus-build.py   (network; rewrites scripts/corpus.txt)
"""
import collections
import datetime
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

UA = {"User-Agent": "own-corpus-build/1 (+https://github.com/own-published)"}
REGISTRY = "https://registry.npmjs.org"
SEARCH_TERMS = [
    "utility", "string", "date", "validation", "parser", "color", "promise",
    "numbers", "filesystem", "json", "array", "object", "url", "http",
    "assert", "cache", "stream", "math", "time", "text",
]
CORPUS_SIZE = 250
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "scripts" / "corpus.txt"


def get(url, timeout=45):
    last = None
    for attempt, pause in enumerate((0, 3, 8, 20)):
        if pause:
            time.sleep(pause)
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            last = e
            if e.code != 429:  # only rate limiting is worth retrying
                raise
        except Exception as e:  # timeouts and connection resets
            last = e
    raise last if last is not None else RuntimeError(f"no attempt made for {url}")


def search(term):
    url = f"{REGISTRY}/-/v1/search?text={urllib.parse.quote(term)}&size=250&popularity=1.0"
    try:
        return [o["package"]["name"] for o in get(url)["objects"]]
    except Exception as e:
        print(f"  ! search {term}: {e}", file=sys.stderr)
        return []


def downloads_chunk(names):
    url = "https://api.npmjs.org/downloads/point/last-week/" + ",".join(names)
    try:
        d = get(url)
    except Exception as e:
        print(f"  ! downloads ({len(names)} names): {e}", file=sys.stderr)
        return {}
    return {k: v.get("downloads", 0) for k, v in d.items() if isinstance(v, dict)}


def downloads(names):
    # The bulk endpoint rejects scoped names (@scope/name) in any encoding with
    # HTTP 400 and rate-limits single-name calls, so the ranking uses unscoped
    # names only; 100 names per call, two calls at a time.
    plain = [n for n in names if not n.startswith("@")]
    chunks = [plain[i:i + 100] for i in range(0, len(plain), 100)]
    out = {}
    with ThreadPoolExecutor(2) as ex:
        for part in ex.map(downloads_chunk, chunks):
            out.update(part)
    return out


def latest(name):
    try:
        return name, get(f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}/latest", timeout=30)
    except Exception:
        return name, None


def judge(v):
    """Return the blocking §9.1 criterion, or None when eligible."""
    if not v:
        return "fetch_failed"
    if v.get("dependencies"):
        return "dependencies"
    if v.get("peerDependencies"):
        return "peer_dependencies"
    if v.get("optionalDependencies"):
        return "optional_dependencies"
    if v.get("bundledDependencies") or v.get("bundleDependencies"):
        return "bundled_dependencies"
    scripts = v.get("scripts") or {}
    if any(s in scripts for s in ("preinstall", "install", "postinstall")):
        return "install_scripts"
    if v.get("gypfile") is True:
        return "binding_gyp"
    if v.get("bin") is not None or (v.get("directories") or {}).get("bin") is not None:
        return "bin"
    if v.get("os") is not None or v.get("cpu") is not None or v.get("libc") is not None:
        return "os_cpu"
    if "sha512-" not in ((v.get("dist") or {}).get("integrity") or ""):
        return "integrity_missing"
    ver = v.get("version") or ""
    if "+" in ver or not SEMVER.match(ver):
        return "version_format"
    return None


def seed_pool():
    if not CORPUS.exists():
        return []
    names = []
    for line in CORPUS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.append(re.sub(r"@\d[^/]*$", "", line))
    return names


def main():
    pool, seen = [], set()
    for n in seed_pool():
        if n and n not in seen:
            seen.add(n)
            pool.append(n)
    print(f"seed pool: {len(pool)}", file=sys.stderr)
    for term in SEARCH_TERMS:
        for n in search(term):
            if n not in seen:
                seen.add(n)
                pool.append(n)
    print(f"candidate pool: {len(pool)}", file=sys.stderr)

    dl = downloads(pool)
    print(f"download counts: {len(dl)}", file=sys.stderr)
    if len(dl) < len(pool) // 2:
        sys.exit(f"refusing to write a corpus: {len(dl)}/{len(pool)} download counts")

    ranked = sorted(((n, dl.get(n, 0)) for n in pool), key=lambda kv: (-kv[1], kv[0]))
    top = [n for n, c in ranked[:CORPUS_SIZE] if c > 0]
    if len(top) < 100:
        sys.exit(f"refusing to write a corpus: only {len(top)} names")
    print(f"top {len(top)} kept; weakest = {ranked[len(top) - 1][0]} "
          f"({ranked[len(top) - 1][1]} downloads/week)", file=sys.stderr)

    verdicts = {}
    with ThreadPoolExecutor(4) as ex:
        for name, manifest in ex.map(latest, top):
            verdicts[name] = judge(manifest)
    eligible = [n for n in top if verdicts[n] is None]
    dist = collections.Counter(v for v in verdicts.values() if v)
    failed = dist.pop("fetch_failed", 0)
    if failed:
        print(f"  ! {failed} manifests could not be fetched — counted as ineligible, "
              f"not as clean", file=sys.stderr)

    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    header = [
        "# Corpus for the SPEC §13 eligibility line (>=100 packages, one name per line).",
        f"# Generated {today} by scripts/corpus-build.py from the npm registry:",
        f"#   pool  = {REGISTRY}/-/v1/search, {len(SEARCH_TERMS)} neutral terms, popularity ordering",
        f"#   rank  = measured weekly downloads, https://api.npmjs.org/downloads/point/last-week/",
        f"# top {len(top)} kept; scoped names are excluded (the bulk downloads endpoint",
        "# rejects them with HTTP 400). Versions resolve at run time (npm view <name>@latest).",
        f"# Measured on this list: {len(eligible)}/{len(top)} eligible under §9.1 with the",
        "# packument criteria alone (no size limit, no tarball inspection) — see the",
        "# script's docstring for exactly what that covers and what it does not.",
    ]
    lines = header + top
    CORPUS.write_text("\n".join(lines) + "\n")
    print(json.dumps({
        "total": len(top),
        "eligible_packument_criteria": len(eligible),
        "threshold": 15,
        "blocking": dict(dist.most_common()),
    }, indent=1))
    pathlib.Path("/tmp/eligibility.json").write_text(json.dumps(
        {"total": len(top), "eligible": eligible, "blocking": dist, "verdicts": verdicts},
        indent=1, sort_keys=True))


main()