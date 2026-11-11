# Pull request template (English only)

## Summary

## Spec coverage
- [ ] Each normative change cites its SPEC.md section / INV-n / error code.
- [ ] Tests named after the covered identifiers exist.

## Checks
- [ ] `cargo fmt --check`
- [ ] `cargo clippy -D warnings`
- [ ] `cargo test`
- [ ] CODEOWNERS review obtained if touching own.toml / own.lock / vendor/own/ / workflows

## DCO
- [ ] Signed-off-by trailer present (`git commit -s`)
