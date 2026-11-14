# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Corpus rebuilt from measured data, J1 eligibility measured**
  (`scripts/corpus-build.py`, `scripts/e2e-pnpm.sh`): the committed corpus was
  250 `name@version` lines with no header, so `day1.sh`'s `npm view
  "$pkg@latest"` skipped every entry and the acceptance line counted 0 packages.
  The corpus is now 250 bare names ranked by measured weekly downloads
  (`api.npmjs.org`), with a dated header naming the ranking source, and
  `corpus-build.py` regenerates it and measures §9.1 eligibility with the same
  criteria as `own-policy`. Running `day1.sh` step 1 verbatim on it reports
  **106 / 250 eligible** (0 skipped, threshold 15) — GO; the packument criteria
  alone give 122 / 250. A second run reproduced the same set, the same two
  numbers. `e2e-pnpm.sh` drives the real registry end to end on pnpm 9.15.9 and
  10.34.9: install, `--frozen-lockfile`, `require`, byte-identical installed
  copy, `verify --installed`, `DRIFT_MODIFIED`/`DRIFT_EXTRA` on tamper, clean
  again after restore, and `own-verify` agreement. It also pins the lifecycle
  question: pnpm 9 runs a `file:` dependency's `postinstall` (2
  `pnpm:lifecycle` events, detector satisfied) and pnpm 10 ignores build
  scripts (0 events).
- **Provenance detection (§8.1 step 4, partial)**: `own add` and `own update`
  now evaluate what the registry advertises through a single, tested
  `evaluate_provenance` (npm attestations, registry signatures) and report it as
  `W_PROVENANCE_UNVERIFIED` instead of silently dropping the information. The
  lock keeps `provenance_level = "integrity-only"`: `attested` and
  `registry-signed` are never written without the matching verification
  (INV-7). 4 unit tests in `own-cli`.
- **CLI integration tests**: `crates/own-cli/tests/cli.rs`, 28 offline tests
  driving the real binary — `init` (layout, `.gitignore`/`.gitattributes`,
  transaction lock, `ALREADY_INITIALIZED`, `--root`), `verify`
  (clean/deterministic, drift codes, `--installed` incl. `DRIFT_INSTALLED`,
  `--format json`, unknown `--format`), uninitialized-directory preconditions,
  `ci`, `licenses` (incl. the `Hash` column), `policy-sync`, `migrate`, `check`
  (`OSV_MISSING`), `slice`, `sbom` (CycloneDX/OpenVEX, stdout and `--output`,
  determinism), `eject`, JSON envelope and §8.0 exit codes.
- `.gitignore` now ignores `/fuzz/target/` (cargo-fuzz has its own workspace;
  those artifacts had been committed before the history rewrite).

### Fixed
- **Git-ignore probe outside a repository (`add` step 5, `ci`)**: git exits 128
  with "not a git repository" when asked about a directory that is not a work
  tree, and every such refusal was surfaced as `GIT_ERROR`, so `own add` could
  not vendor into a project without git even though `own init` accepts one. The
  probe now answers "nothing ignored" for exactly that refusal (a work tree with
  no rules hides nothing either), while an unavailable git, a corrupt repository
  or any other failure stays a hard `GIT_ERROR` — the distinction is the exit
  code *and* git's message, not the exit code alone. 3 unit tests plus the
  rewritten `ci_guards` pair (`ci_without_a_repository_has_nothing_to_ignore`,
  `ci_git_unavailable_is_not_a_clean_ignore_check_inv5`, the latter with `PATH`
  emptied so git cannot spawn).
- **OSV cache and policy checks (partial)**: validate snapshot/advisory
  structure and UTC dates; compare elapsed seconds using the system clock
  when `OWN_NOW` is absent. `check` and VEX share configured cache paths, age
  limits, environment overrides and id/alias exceptions requiring a reason
  and valid expiry date. Expired exceptions retain alerts with
  `W_IGNORE_EXPIRED`; stale overrides retain `W_OSV_STALE`. Reject absolute
  or parent-traversing cache paths. VEX no longer implicitly bypasses
  missing/stale snapshots.
- **OSV source date and real-age comparison (§8.2, INV-5/INV-10)**:
  `fetch_osv_dump` now returns the `Last-Modified` header with the archive
  bytes, and `own osv fetch` writes it to `source_last_modified` as RFC 3339
  UTC instead of a constant `null`. Age comparison keeps sub-second
  precision, so the inclusive deadline is decided exactly. A snapshot dated
  in the future is refused (`PARSE_ERROR ... in the future`) for both
  `generated_at` and `source_last_modified`, and `--allow-stale-osv` cannot
  mask it: the §8.2 risk table names a mirror that lies about its dates. The
  mirror's own date is judged against the system clock, never an injected
  `OWN_NOW`, which the mirror cannot know.
- **Strict dump validation (§8.2, INV-5)**: every zip member is now validated
  before the package filter. A truncated or non-JSON member, a nameless npm
  record, or an advisory without an id is a hard `PARSE_ERROR` instead of a
  silently dropped record — a dropped record would leave a snapshot that looks
  complete while missing an advisory. Well-formed advisories for packages
  outside the lock are still skipped, and the non-npm filter now runs before
  the npm field extraction so a malformed non-npm record cannot discard the npm
  record of the same advisory. The whole published dump passes this validation
  in the live fetch test.
  `--allow-missing-osv` no longer masks a snapshot that exists but is
  unreadable. Ecosystem filtering keeps `database_specific` and
  `ecosystem_specific` attached to their own affected record, so a hint can
  no longer move onto another package. Two opt-in network tests exercise the
  real HTTPS mirror: a four-byte ranged fetch for the transport header, and
  a full `osv fetch` writing to a configured path. A VEX regression test drives
  `sbom --format vex --e1` twice through the real binary and requires
  byte-identical output, settling the counter-review claim that the OpenVEX
  `@id` would drift with a `HashSet`-ordered reachable set. 9 new tests. These
  changes do not certify phase 2.
- **vendor-all keeps and verifies every version (§9.2, INV-5)**: a name
  vendored in several versions now carries one `name@version` override per
  version. The previous code skipped the override whenever a bare key already
  existed, and a bare `file:` key pins every version to one directory, so the
  second version was never reachable. `own verify` and `own ci` compare the
  versioned shape, so a missing, stale or bare key for a multi-version package
  is `OVERRIDE_MISMATCH` instead of being skipped — that skip is what left
  vendor-all packages unverified. `own update` rewrites the key for the version
  it moves, collapses back to the bare key when one version remains, and
  refuses to overwrite an override own did not write. Every version's local
  preconditions are checked before the first write and all writes share one
  transaction, so a refusal leaves no partial set of versions; re-running
  vendor-all vendors only the versions that are new. 7 new tests. The
  end-to-end pnpm 9/10 run against a local registry is still open.
- **Manifest integrity anchor (INV-8)**: recompute the digest, file count and
  total size of the actual manifest records against `own.lock`. Changing a file
  and its manifest hash no longer bypasses verification while the lock stays
  unchanged. Both verifier binaries use this shared check.
- **Git pipe deadlock (INV-5)**: `add` and `ci` share a NUL-delimited ignore
  probe that feeds stdin while draining stdout/stderr. Regression test with
  3,000 ignored files; Git failures remain explicit errors.
- **Git safety and transactional initialization (INV-1/5/9)**: `init` keeps the
  vendor negation last, preserves unreadable Git configuration by refusing the
  operation, checks repositories in parent directories, and rolls back on Git
  errors. `VENDOR_PATH_IGNORED` uses exit 1. `add` and `ci` no longer confuse
  failed ignore checks with clean results; `ci` checks project-relative paths.
- **CI JSON output**: `--base-ref` change notes stay inside `data.notes`, not
  before the JSON document. Human findings are results on stdout.
- **Minimal verifier**: `own-verify --installed` performs the installed-file
  comparison. Missing configuration/lock and unreadable or malformed inputs
  are explicit errors, not empty policy/override values. JSON error envelopes
  and sorted findings use the same output contract as successful verification.
- **Determinism gate**: replace the ineffective network setup and swallowed
  errors with an offline, non-empty fixture comparing verify and SBOM output.
- **Dependency advisories**: upgrade `zip` from 2.6.1 to 9.5.1 for
  RUSTSEC-2026-0367/0368/0369/0429; remove its unused dependency from `own-net`.
  OSV still reads ZIP entries in memory, never using disk extraction APIs.
- **CLI conformance (§8.0/§8.1/§8.3)**, from the divergences the integration suite
  documented:
  - `NOT_INITIALIZED` (exit 2) is now the answer of every command that needs
    project state (`verify`, `ci`, `licenses`, `policy-sync`, `migrate`, `slice`,
    `sbom`, `diff`, `check`, `eject`). `verify` used to report an unmatchable
    `NOT_INITIALIZED or IO_ERROR: own.toml: …` and exit 1; the others reported a
    bare `IO_ERROR`.
  - `--format human|json` is declared by `verify` and validated everywhere
    (`scan`, `slice`, `diff`, `check`, `ci`): an unknown value is a
    `USAGE_ERROR` (exit 2) instead of being silently ignored. The result now goes
    to stdout in human mode too (§8.0: logs on stderr), and the JSON envelope is
    emitted only with `--format json`.
  - `verify --installed` is implemented (`own_core::verify::verify_installed`):
    every file present in `node_modules/.pnpm` must exist in the manifest with
    the same bytes (`DRIFT_INSTALLED`); files absent from the copy are not
    reported (§5), and a package that was never installed is skipped.
  - `init` is transactional (INV-9): it takes `.own/lock`, journals its writes
    and commits, so a failure (or a signal) leaves the directory untouched
    instead of half-initialised.
  - `sbom --format vex` no longer requires `--output`: without it the OpenVEX
    document goes to stdout, like CycloneDX (§8.3).
  - `licenses` prints the `Hash` column required by §8.1.
  - Remaining documented deviation: `ci` requires `pnpm-lock.yaml`, because its
    overrides/pnpm coherence check needs it; the failure is an `IO_ERROR`
    (exit 2).
- **Signal handling (INV-9)**: the SIGINT/SIGTERM handler is now
  async-signal-safe — it only calls `write(2)` and `_exit(128+signal)`. It no
  longer takes the active-transaction mutex, reads the journal or copies files
  from inside the handler (a signal could interrupt the thread holding that
  mutex, and none of those calls are in POSIX's async-signal-safe list). An
  interrupted run leaves the journal `started` and the **next writing command**
  restores the backup and emits `W_TXN_RECOVERED`, the same path as `kill -9`.
  New tests `sigterm_leaves_started_journal_that_next_writer_restores` and
  `sigint_leaves_started_journal_that_next_writer_restores` assert the exit code
  (143/130), the handler message and the recovery.
- **Durability (INV-9)**: every journal write, every backup file and every
  `rename` is now `fsync`ed (file, then parent directory) *before* the work it
  protects is considered done, so the journal survives a power loss and not only
  `kill -9`. The ordering enforced is backup durable → journal entry durable →
  rename → directory sync, in `begin`/`backup`/`write_file`/`move_dir_into`/
  `commit`/`rollback` (recursive `sync_tree` for prepared trees).
- **rust-toolchain.toml** was malformed (`channel` without the `[toolchain]`
  table), so *every* `cargo`/`rustup` invocation inside the repository failed
  with ``missing field `toolchain` ``. It now declares
  `[toolchain] channel = "1.99.1"` + `rustfmt`/`clippy`.
- **Transactions (INV-9)**: `Txn::begin` now takes the exclusive lock **before**
  scanning/recovering journals, so a concurrent `own` gets `LOCK_BUSY` instead of
  rolling back the active transaction. New regression test
  `lock_taken_before_recovery_so_second_writer_cannot_rollback_active_txn`.
- **Rollback path encoding**: backup journal entries now store the original
  relative path explicitly (`{"rel": ..., "flat": ...}`), so names containing a
  literal `__` (e.g. `@types+babel__core`) round-trip correctly. Legacy string
  entries are still decoded. New test
  `rollback_preserves_literal_double_underscore_in_names`.
- **Extraction (§11.2)**: the compression-ratio check now compares decompressed
  bytes against **compressed** bytes (counter moved before the GzDecoder), the
  temp file is created with `create_new(true)`, non-UTF-8 entry names are
  refused (`EXTRACT_REFUSED:non_utf8_path`) instead of lossy-converted, the
  actual bytes written are checked against `max_file_size`, and multi-member /
  trailing gzip data is refused (`EXTRACT_REFUSED:trailing_data`). New tests:
  `rule_max_file_size_refused`, `rule_max_unpacked_size_refused`,
  `rule_compression_ratio_refused`, `rule_trailing_data_refused`,
  `rule_non_utf8_path_refused` (18 → 23 hostile tests).
- **Verify (CRLF)**: the CRLF→LF normalization no longer doubles `\n`, so
  `LINE_ENDINGS_REWRITTEN` actually fires.
- **Release workflow**: all `uses:` refs pinned to real, verified 40-char commit
  SHAs (checkout v4.2.2, upload-artifact v4.6.2, download-artifact v4.3.0,
  cosign-installer v4.1.1, action-gh-release v3.0.3, dtolnay/rust-toolchain v1).
  aarch64-linux now cross-compiles with `gcc-aarch64-linux-gnu`. SLSA provenance
  uses a dedicated `provenance` job calling the reusable
  `generator_generic_slsa3.yml@v2.1.0` with the correct `base64-subjects` input.
- **Installer**: `OWN_REPO` defaults to `YourFriendPollux/own`; cosign is fetched
  per-OS (darwin/linux); the non-existent detached `.sig` is gone — verification
  uses the `.bundle` produced by the release; SLSA attestation is fetched as
  `<asset>.intoto.jsonl`.
- **CI**: installs `cargo-deny`, `cargo-vet` and `cargo-fuzz` before use.

### Changed
- `fuzz/corpus/` (3 449 generated libFuzzer artifacts, ~14 MB) is untracked and
  gitignored; regenerate with `cargo +nightly fuzz run <target>`.
- README updated: real test count (110), corpus size (250), known limits section,
  note that SPEC.md/docs are not in the published archive.

## [0.1.0] - 2026-11-10

### Added
- `own init` / `verify` / `ci` / `scan` / `add` / `licenses --write` /
  `policy-sync` / `migrate` (0.1 Core, SPEC §8.1)
- `own osv-fetch` / `check` (E0 alerts) / `diff` / `update` (0.2, §8.2)
- `own sbom` (CycloneDX 1.5 + OpenVEX) / `eject --adopt` / `verify-signature` (0.3, §8.3)
- `own-verify`: minimal offline verifier binary (no network deps)
- Hardened extraction (§11.2) with hostile tests; cargo-fuzz targets
  (extraction, packument, SPDX, OSV)
- INV-9 transactions with kill -9 recovery test; JCS RFC 8785 + golden §7.3
  vectors; canonical TOML writer
- Release workflow (cosign keyless + SLSA) + verified installer script
- Measured: `own ci` 16 ms (release) on 12 pkgs / 9.4 MB vendored
