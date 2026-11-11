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
See `SPEC.md` §3 (threat model) for known limits.
