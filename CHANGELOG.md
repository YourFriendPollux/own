# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
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
- **own-verify**: `--installed` now prints a warning instead of being silently
  ignored.
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
- **CI**: installs `cargo-deny`, `cargo-vet` and `cargo-fuzz` before use; the
  determinism check now runs `own init` + `own add` on a real package instead
  of verifying an empty repo twice.

### Changed
- `fuzz/corpus/` (3 449 generated libFuzzer artifacts, ~14 MB) is untracked and
  gitignored; regenerate with `cargo +nightly fuzz run <target>`.
- README updated: real test count (79), corpus size (250), known limits section,
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
