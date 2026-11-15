## Summary

Describe the change, its user impact and the boundaries that remain unchanged
in English. Link the issue or available acceptance contract.

## Coverage and evidence

- [ ] Regression reproduced before the fix; valid neighboring inputs covered.
- [ ] Relevant invariant/error code or command contract identified.
- [ ] Sibling readers/writers preserve integrity, ordering and transaction rules.
- [ ] Exact observed commands/results, skipped checks and known limits listed.
- [ ] Fixture, real-project, scanner, hosted-CI and signature evidence kept distinct.

The normative SPEC/private design documents are not distributed here. Request
needed sections from maintainers; do not claim unavailable annex/phase coverage.

## Checks

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -v`
- [ ] `cargo deny check`
- [ ] `cargo vet --locked` — failures/coverage gaps reported, not bypassed.
- [ ] Relevant fuzz/determinism or opt-in integration checks reported.
- [ ] Documentation and examples match the supported implementation.
- [ ] No logs, build output, caches, downloaded corpora or credentials included.
- [ ] Vendored bytes remain trackable; license notices and policy are preserved.
- [ ] Required CODEOWNERS review obtained for configuration/lock/vendor/workflow
      or ignore/attribute changes.

## DCO and publication scope

- [ ] Signed-off-by trailer present (`git commit -s`).
- [ ] No tag push, publication, signing-trust or audit-exemption change without
      explicit maintainer authorization.

## Remaining risks or verification gaps

List unresolved items instead of presenting them as clean. A local pass is not
proof of hosted CI, a signed release or complete advisory coverage.
