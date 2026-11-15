---
name: Bug report
about: Report a reproducible non-security defect in own
labels: bug
---

## Summary

Describe the defect and its impact in English. For an undisclosed vulnerability,
use GitHub Security Advisories instead of a public issue.

## Command and environment

- own version and/or exact commit:
- OS and architecture:
- Node and pnpm versions, if relevant:
- Lockfile format/version and workspace layout:
- Exact command and flags:

## Reproduction

Provide minimal steps and sanitized input or a public repository revision.
Distinguish a supported-format failure from an unsupported-format refusal.
Do not attach credentials, `.env` files, private registry tokens, complete
private repositories or unredacted environment/log dumps.

## Expected and observed behavior

- Expected behavior:
- Actual exit status:
- Relevant stdout/stderr or JSON findings:
- Reproducibility/frequency:

## Checks already performed

State any integrity, installed-file, build/test or CI commands executed. Report
failures and skipped checks explicitly; a planned command is not an observed
result. Note any deliberate clock input, stale/missing-OSV override, pnpm opt-in
or integration configuration change.
