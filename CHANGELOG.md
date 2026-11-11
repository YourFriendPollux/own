# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-10

### Added
- `own init` / `verify` / `ci` / `scan` / `add` / `licenses --write` /
  `policy-sync` / `migrate` (0.1 Core, SPEC §8.1)
- `own osv-fetch` / `check` (E0 alerts) / `diff` / `update` (0.2, §8.2)
- `own sbom` (CycloneDX 1.5 + OpenVEX) / `eject --adopt` / `verify-signature` (0.3, §8.3)
- `own-verify`: minimal offline verifier binary (no network deps)
- Hardened extraction (§11.2) with 18 hostile tests; cargo-fuzz targets
  (extraction, packument, SPDX, OSV) with ~4.6M smoke executions, no crash
- INV-9 transactions with kill -9 recovery test; JCS RFC 8785 + golden §7.3
  vectors; canonical TOML writer; SPEC v0.6 with 6 review amendments (Annexe E)
- Day-1 GO recorded; 5 cross-model spec reviews in docs/reviews/
- Release workflow (cosign keyless + SLSA) + verified installer script
- Measured: `own ci` 16 ms (release) on 12 pkgs / 9.4 MB vendored
## [Unreleased]

### Added

- Initial repository scaffold per SPEC.md §15 (workspace, crates, scripts, docs).
- `scripts/corpus.txt`: 127-package corpus generated from the public npms.io ranking.
- `own-core` hashing module with golden vectors from SPEC.md §7.3.
