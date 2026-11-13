# Pull request template (English only)

## Summary

## Spec coverage
- [ ] Each normative change cites its spec section / INV-n / error code
      (SPEC.md is not in the published archive; request it from maintainers).
- [ ] Tests named after the covered identifiers exist.

## Checks
- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] No generated artifacts committed (fuzz/corpus/ is gitignored)
- [ ] CODEOWNERS review obtained if touching own.toml / own.lock / vendor/own/ / workflows

## DCO
- [ ] Signed-off-by trailer present (`git commit -s`)
