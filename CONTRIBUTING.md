# Contributing to own

Contributions use the Developer Certificate of Origin: sign off commits with
`git commit -s`. All source, identifiers, messages, serialized keys, commit
messages and repository documentation are in English.

## Development setup

Fork/clone the repository and work on a branch. The pinned Rust toolchain is
1.99.1 with rustfmt and clippy; Python 3 is used for offline packaging/installer
regressions. Opt-in npm integration requires Node, a supported pnpm version,
Git and network access. Fuzzing additionally uses nightly and cargo-fuzz.

## Required checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -v
cargo deny check
cargo vet --locked
```

Run the checks relevant to a change and report exact commands, failures, skipped
network checks and remaining gaps. Required CI also includes fuzz smoke and the
non-empty determinism regression. Release builds depend on the reusable CI gate.
Do not remove validation, suppress tests, weaken warnings or add audit exemptions
merely to make a gate green. Existing audit coverage is incomplete and must be
resolved honestly.

## Changes and evidence

- Reproduce a defect before fixing it and add a regression at the affected seam.
  Retain valid neighboring inputs as well as refusal cases.
- Cite an applicable invariant/error code or command contract. The normative
  `SPEC.md` and private design documents are not distributed here; request them
  when a change depends on section identifiers. Do not claim annex/phase
  conformance without an available acceptance contract.
- Preserve canonical serialization, deterministic ordering, byte identity,
  transaction boundaries and strict error reporting across sibling callers.
- Test non-empty outputs in separate processes. Use a fixed `OWN_NOW` when
  comparing creation timestamps; real-time timestamp changes are legitimate.
- Treat mock/fixture results, real repository integration, external scanners,
  hosted CI and cryptographic verification as distinct evidence.
- Real-world integration uses authentic checkouts with recorded revisions and
  original lock formats. Unsupported-root refusals do not prove vendoring of
  other languages. Exercise the project's original build/test commands before
  and after integration, and disclose any configuration change such as excluding
  third-party `vendor/own/**` from application-style lint.

Open a pull request with its scope, tests and known limits. Changes to
`own.toml`, `own.lock`, `vendor/own/`, `.github/workflows/`, `.gitattributes` or
`.gitignore` require CODEOWNERS review. Security-sensitive reports belong in
private advisories, not public issue attachments.

## Keep the source tree clean

Keep source, regression tests, schemas, audit policy and release helpers.
Do not commit build trees, logs, downloaded repositories/tarballs, generated
fuzz inputs or Python/editor caches. The Git ignore rules must never hide
`vendor/own/**` bytes. Store bulky integration checkouts and pnpm caches on a
filesystem with adequate space/quota; `/tmp` may be a quota-limited tmpfs.

To run the existing fuzz targets explicitly:

```sh
cd fuzz
cargo +nightly fuzz run extract_tarball -- -max_total_time=60
cargo +nightly fuzz run packument -- -max_total_time=20
cargo +nightly fuzz run spdx_expr -- -max_total_time=20
cargo +nightly fuzz run osv_json -- -max_total_time=20
```

Install cargo-fuzz and the nightly toolchain first. Generated `fuzz/corpus/`,
`fuzz/artifacts/` and `fuzz/target/` are disposable and ignored. Installer and
packaging helper sources under `scripts/` are maintained by their offline tests;
one-off research/corpus-generation scripts are not publication inputs.

## Release preparation

A release tag triggers the workflow; it does not itself prove that quality,
building, signing or publishing succeeded. Coordinate the version/tag with
maintainers, verify every required gate and review produced artifacts. Do not
push a tag, publish assets or use signing/audit trust changes without explicit
authorization. The archive packer includes only `own` and `own-verify` and writes
a SHA-256 manifest; documentation is kept in the repository.
