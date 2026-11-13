# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the Security tab of this repository).

- Acknowledgement of receipt: within 3 business days.
- Fix or mitigation plan: within 30 days.

Do not open public issues for undisclosed vulnerabilities.

## Scope

`own` covers only vendored packages (`vendor/own/`). The rest of the dependency
tree is out of scope; keep a generic scanner (osv-scanner, etc.) in parallel.

## Known limits

- `own verify` anchors integrity locally: `own.lock` and the manifests live in
  the same repository, so verification detects drift but not a malicious commit
  that updates lock, manifests and vendored files together. Pair it with
  commit-signature verification (e.g. sigstore/gitsign) for stronger anchoring.
- The transaction layer recovers from `kill -9` but does not fsync on every
  write; durability against power loss depends on the filesystem.
- SPEC.md (threat model) is not part of the published archive; request it from
  the maintainers.
