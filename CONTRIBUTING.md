# Contributing to own

Contributions are signed off under the Developer Certificate of Origin
(`Signed-off-by` trailer, `git commit -s`).

## Workflow

1. Fork, branch, implement.
2. `cargo fmt --check` and `cargo clippy -D warnings` must pass.
3. Every normative rule in `SPEC.md` must be covered by at least one test whose
   name cites its identifier (`INV-n`, error code from §8.0).
4. Open a PR. Changes to `own.toml`, `own.lock`, `vendor/own/`, `.github/workflows/`,
   `.gitattributes`, `.gitignore` require CODEOWNERS review.

## Code conventions

- All code, identifiers, error messages, TOML/JSON keys, commit messages, and
  documentation are in English.
- `MUST`/`SHOULD`/`MAY` follow RFC 2119.
