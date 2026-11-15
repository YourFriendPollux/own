# own — verified npm vendoring

`own` copies eligible npm packages from their published tarballs into
`vendor/own/` without rewriting package source. It records package integrity,
file manifests, license decisions and pnpm overrides in `own.lock`, then checks
those records offline with `own verify` or the smaller `own-verify` binary.

**Status: pre-1.0, version 0.1.0.** The supported vendoring ecosystem is npm.
The command set includes local version comparison, OSV checks, SBOM/OpenVEX
output and adoption of vendored code; the update surface has a known blocker
listed below. Command presence is not a claim of full specification
conformance, completed dependency audits or a verified hosted release.

## Requirements

- An existing npm project with `package.json` and a **single-document pnpm v9
  lockfile**. Unsupported schemas and multi-document locks are refused rather
  than interpreted as an empty graph.
- Git 2.30 or newer and a worktree for vendoring, updates, CI checks and adoption.
- pnpm 9 or 10 for automatic installation. A newer major requires the explicit
  `--allow-untested-pnpm` opt-in; that flag does not add support for a new lock
  schema.
- Network access for registry downloads, updates and OSV refreshes. Ordinary
  integrity verification and `own ci` are offline.

npm aliases, catalogs, workspace links and peer-qualified resolutions are read
from supported locks. Non-registry edges are preserved, not reported as npm
versions. `own scan --include-dev` adds informational development-dependency
rows; it is not a recursive vulnerability scan of every dependency.
`scan` can run before `init`; commands consuming own state require initialization.

## Installation

### Build from source

The repository pins Rust **1.99.1**, including rustfmt and clippy. No separate
minimum-supported-Rust-version guarantee is declared.

```sh
git clone https://github.com/YourFriendPollux/own.git
cd own
cargo build --release --locked -p own-cli -p own-verify
mkdir -p "$HOME/.local/bin"
install -m 0755 target/release/own target/release/own-verify "$HOME/.local/bin/"
own --version
```

Ensure `$HOME/.local/bin` is on PATH. The build produces two binaries; neither
is installed automatically by Cargo's workspace build.

### Install a signed release

From a trusted checkout, and only after assets for the selected tag exist:

```sh
OWN_VERSION=v0.1.0 ./scripts/install-own.sh
```

The installer requires trusted, preinstalled `cosign` and `slsa-verifier`, plus
curl, tar, install and a SHA-256 checksum tool. It downloads the archive,
checksum, cosign bundle and signed SLSA `multiple.intoto.jsonl`, binds them to
the artifact, repository and exact tag, and verifies them before installing.
`OWN_BIN_DIR`, `OWN_REPO` and `OWN_PROVENANCE_ASSET` configure destination,
repository and provenance asset name. Verification tools are not bootstrapped
from the downloads they would authenticate.

The release workflow defines **linux-amd64**, **linux-arm64** and
**darwin-arm64** archives. Windows and darwin-x64 are not release targets.
A prepared workflow or a passing local installer test is not proof of a
published, successfully signed release.

## Use in an existing project

The exact package version must already be resolved in the project's supported
lockfile. The following example assumes `zod@3.22.4` is present:

```sh
own init
own scan
own add zod@3.22.4 --allow-diamond vendor-all
own verify
own verify --installed
own ci
own licenses --write
own-verify --installed
```

`init` creates configuration, an empty lock and the vendoring layout, and
updates Git ignore/attribute rules without excluding vendored bytes from Git.
`add` verifies registry metadata and tarball integrity before publication,
checks eligibility and license policy, updates overrides and runs pnpm with
installation scripts disabled. It performs a forced post-install pass and
checks the installed copies. **Budget disk space for pnpm's forced installation
of optional platform variants.**

As an alternative to automatic installation, deliberately split preparation
and installation:

```sh
own add zod@3.22.4 --allow-diamond vendor-all --no-install
pnpm install --ignore-scripts
own verify --installed
own ci
```

`--no-install` explicitly skips post-install verification; it is not proof that
an application can build. Run the project's own build and tests afterwards.
A project-wide linter may need to exclude third-party files under
`vendor/own/**` from application-style rules. Keep those files tracked by Git;
do not solve a lint problem by ignoring the vendored tree in `.gitignore`.

### Commands and boundaries

| Command | Behavior |
|---|---|
| `scan` | Registry eligibility for dependencies declared by lock importers. |
| `add` | Verified verbatim vendoring; explicit diamond and license decisions. |
| `verify`, `own-verify` | Offline lock/manifest/file checks; `--installed` additionally checks discovered pnpm copies. |
| `ci` | Offline verification, override/lock coherence, dependent/version coverage, license policy and generated license-document checks. Requires pnpm-lock.yaml. |
| `licenses --write`, `policy-sync` | License inventory generation and policy re-evaluation. |
| `migrate` | Validates the current schema; **schema 1 is current and migration is a no-op**. Other schemas are refused. |
| `osv-fetch`, `check` | OSV snapshot refresh and advisory evaluation for owned packages. Missing or stale snapshots are not silently clean. |
| `diff` | Offline comparison of two versions already present in own.lock and on disk. `--from-cache` is refused. |
| `update` | Transactional update with offline verification. Its default downstream path would create a branch, commit, push and PR; use `--no-pr` to disable that automation. |
| `sbom` | CycloneDX 1.5 and/or OpenVEX. VEX requires a usable local OSV snapshot; no stale/missing-snapshot CLI opt-out is exposed by this command. |
| `slice`, `check --e1/--e2` | Experimental reachability evidence; slicing does not rewrite or reduce the vendored package. |
| `verify-signature` | External cosign verification, optionally with SLSA provenance verification. Requires appropriate trusted tools and may use network access. |
| `eject --adopt` | Adopts the files as first-party, keeps files/license notices/overrides, removes own bookkeeping and runs installation/build checks. Requires a clean worktree and confirmation. |

`verify --remote` and `check --remote` are currently refused; use the supported
registry downloads and local OSV snapshot commands rather than treating these
options as implemented remote verification. See each
command's `--help` for its actual options.

## Integrity and reproducibility

- Registry SRI SHA-512 and tarball SHA-256 are checked before extraction.
- Hardened extraction refuses unsafe paths, links, unsupported members and
  built-in resource-limit violations.
- Offline verification binds actual manifest records, counts and total size to
  `own.lock`, then detects missing, extra or changed files. Both verifiers share
  the installed-file checks.
- Vendoring, license/SBOM state mutations and adoption use the transaction layer's
  exclusive locking, journaled backups and recovery. OSV snapshot replacement
  is not a journaled transaction with the same durability guarantees.
  An interrupted process leaves recovery work for the next writing command;
  this is not an immediate rollback from a signal handler.
- Reproducibility requires identical inputs and clock settings. SBOM creation
  timestamps follow `OWN_NOW`, then `SOURCE_DATE_EPOCH`, then the real clock;
  two real-time runs can legitimately have different timestamps.

Do not hand-edit vendored source in verbatim mode. Use a version update or
explicit adoption when you need to maintain the source yourself.

## Security limits

- **npm provenance is detected, not cryptographically verified.** Advertised
  attestations and registry signatures emit `W_PROVENANCE_UNVERIFIED`; package
  records remain `integrity-only`. This is distinct from verification of the
  tool's signed release archive.
- Integrity is anchored locally. An attacker changing lock, manifests and
  package files together is outside ordinary drift detection.
- Installed-file checks cover discovered materialized copies; they do not
  prove that every package was installed or that the application builds.
- The public OSV npm archive is validated end to end, preserving raw ECOSYSTEM
  tokens such as NocoDB `fixed="2026.04.1"`; non-evaluable constraints are marked
  `OSV_UNEVALUABLE`, never silently reported as clean. A missing or stale snapshot
  still does not establish current advisory coverage.
- Advisory checks cover owned packages, not every dependency or the application.
  Missing hints keep reachability results conservative; no alert is not a
  security guarantee.
- Python/PyPI vendoring is unimplemented; ordinary `add --ecosystem pypi`
  returns `ECOSYSTEM_UNSUPPORTED`. Do not combine unsupported ecosystem flags
  with the special `vendor-all` path or treat that combination as supported.
- Only `vendor-all` has a dedicated diamond-resolution path. Accepted
  `keep-external`/`unify` values do not establish full implementations of those
  strategies; `update --allow-diamond` is not consumed by its implementation.
- `[registry].url`, an explicitly configured `[registry].mirror`, `[net]` client
  limits, `[security]` extraction limits and `[osv].url`/`max_download_mb` are
  validated and used. They do not implement authenticated private-registry login,
  OSV API mode (`check --remote` is refused) or any air-gap bootstrap claim.
- Experimental E2 runs package entry code in a bounded child process; it is not
  a purely static analysis, an application test suite or a certified sandbox.
- Independent dependency audit coverage is incomplete. `cargo vet` is a required
  CI gate; exemptions are not equivalent to external audits and must not be
  added merely to make publishing pass.

See [SECURITY.md](SECURITY.md) for reporting and trust boundaries.

## Repository and verification

The seven-crate workspace contains core records/transactions, policy, networking,
extraction, CLI, minimal verifier and experimental slicing. `schemas/` describes
serialized data, `supply-chain/` holds audit policy, and `fuzz/fuzz_targets/`
contains the fuzz harness sources. `scripts/install-own.sh` and
`scripts/package-release.py` support distribution; `scripts/tests/` protects
installer and packaging behavior.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -v
cargo deny check
cargo vet --locked
```

CI also runs fuzz smoke and a non-empty offline determinism regression. Release
jobs depend on the reusable CI workflow; a failing required gate blocks them.
Test counts and network-dependent measurements are not frozen into documentation.
Opt-in upstream tests are excluded from the ordinary offline suite.

Generated build output, logs, fuzz corpora, caches and exploratory QA scripts are
not part of the publication source tree. The published binary archives contain
only `own` and `own-verify`; repository documentation is not bundled into them.
`SPEC.md` and private design documents are not distributed here. Refer to the
public command contracts and regression tests, and request the normative source
from maintainers when a change needs its section identifiers.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE).
