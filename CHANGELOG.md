# Changelog

Notable user-facing changes follow
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Unreleased entries are
local source changes, not evidence that a signed release has been published.

## [Unreleased]

### Added

- Shared installed-file verification in `own verify --installed` and
  `own-verify --installed`, including aliases, file dependencies and peer contexts.
- Transactional multi-version `vendor-all`, version-scoped overrides and safe
  extension of previously owned versions.
- Conservative E1/E2 reachability evidence and CycloneDX/OpenVEX generation.
- Explicit detection of advertised npm provenance without upgrading
  `provenance_level` beyond `integrity-only`.
- Regression coverage for parser refusals, real lock shapes, integrity anchors,
  transaction recovery, CI output, adoption and release/installer behavior.

### Fixed

- Enforce initialization for state-consuming commands and improve human/JSON
  result reporting. Report actionable error codes, failing paths and advisory
  findings instead of clean-looking partial results; JSON error handling and
  validation of format options are not uniform across every command.
- Validate actual manifest digests, file counts and sizes against the lock;
  reject coordinated file/manifest changes while the lock anchor is unchanged.
- Preserve aliases, catalog resolutions, current-directory links and file-peer
  contexts in supported pnpm v9 locks. Refuse unsupported schemas and
  multi-document locks instead of losing the project graph.
- Accept exact single-version scoped overrides while retaining rejection of
  ambiguous or incomplete override maps. Preserve an existing bare version when
  extending a multi-version set, and check conflicts before removing its key.
- Compare registry-to-file parent identities in CI only through known lock
  entries, retaining coverage checks for unknown parents and versions.
- Drain Git subprocess pipes concurrently, use NUL-delimited paths, distinguish
  Git errors from clean ignore checks and keep vendored files trackable.
- Lock before journal recovery, preserve original backups, sync publication
  boundaries and recover interrupted transactions on the next writing command.
- Reject unsafe extraction paths, non-UTF-8 names, invalid gzip tails and
  resource-limit violations; read verified archive data for extraction.
- Validate OSV snapshot/advisory structure, ranges, timestamps, freshness and
  dated exceptions. Preserve conservative alerts and explicit stale/missing
  warnings rather than silently discarding unsupported or malformed records.
- Bind release provenance to the tarball, repository and exact tag; request the
  SLSA generator's `multiple.intoto.jsonl` asset and require trusted verifiers
  before installing. Hosted cryptographic verification remains unvalidated.
- Keep release jobs behind the shared CI gate and normalize archive/checksum
  metadata in the packaging script.
- Refuse PyPI vendoring explicitly in the ordinary add path before reading an
  npm lockfile; no support is claimed for non-npm diamond-mode combinations.

### Changed

- Retain only installer, packaging and their regression helpers under `scripts/`.
  Remove one-off eligibility/corpus, exploratory audit and repository-campaign
  scripts along with generated output and caches.
- Refresh the README, contributor/security guidance and GitHub templates to
  describe the current command boundaries and publication limitations.
- Ignore generated Python, Rust, fuzz, release and editor output while keeping
  `vendor/own/**` trackable.

### Known limitations

- Package provenance is not cryptographically verified.
- The complete public OSV npm dump is accepted: 232,472 archive entries produce 231,720 live npm advisories, preserving raw ECOSYSTEM tokens and marking non-evaluable ranges `OSV_UNEVALUABLE`.
- `verify --remote` is unimplemented; `migrate` is a schema-1 no-op.
- `check --remote` and `diff --from-cache` are refused. Normal `update` is
  blocked by its absolute-extraction/project-relative-diff path mismatch;
  its accepted diamond option is not implemented as a strategy.
- Generated network, mirror and security TOML fields are not general CLI
  configuration; only the implemented license/local-OSV settings should be
  relied on. No fresh-download air-gap or private-registry support is claimed.
- Slicing/reachability features are experimental, and PyPI is unsupported.
- Dependency audit coverage is incomplete; required CI gates and actual hosted
  signing must succeed before a release can be treated as verified.

## [0.1.0] - 2026-11-10

Initial development baseline:

- npm vendoring, lock/manifests, license policy, offline verification and CI checks.
- OSV/check/diff/update command surfaces, SBOM output, adoption and external
  signature-verification support.
- `own-verify`, hardened extraction, canonical serialization and transaction
  recovery with regression and fuzz harnesses.
- GitHub release workflow and installer sources.

This entry records the development version's history, not a claim that release
assets or their hosted signatures have been exercised.
