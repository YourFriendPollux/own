# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through this repository's GitHub Security
Advisories page: **Security → Report a vulnerability**. Do not open a public issue
for an undisclosed vulnerability or attach credentials, private repositories,
full environment dumps or unredacted logs.

Include the affected own version/commit, platform, exact command, a minimal
sanitized reproduction, observed impact and any suggested mitigation.
Maintainers aim to acknowledge reports within three business days and provide a
fix or mitigation plan within thirty days; these are targets, not a service SLA.
Coordinate public disclosure with maintainers.

## Scope and supported state

Security-relevant surfaces include both binaries, registry/archive parsing,
filesystem and transaction handling, policy/OSV evaluation, Git integration,
installer verification and release workflows. Reproduce against current source
or identify the exact affected release; this pre-1.0 project does not promise
indefinite maintenance of older versions.

`own check` evaluates **owned npm packages**, not the rest of the dependency tree
or application. Use an independent dependency/application scanner alongside it.
Python/PyPI vendoring is not implemented.

## Trust boundaries and limitations

- Tarball integrity is checked before extraction. Integrity proves correspondence
  to the fetched registry data, not that a publisher or package is benign.
- Lock and manifests are local anchors. Ordinary verification detects drift, not
  a malicious commit that replaces all anchors and files together. Review and
  authenticate repository changes separately.
- npm attestations and registry signatures are **detected, not verified**.
  `W_PROVENANCE_UNVERIFIED` and `integrity-only` remain explicit; they are not
  `attested` or `registry-signed` trust levels.
- The full public npm OSV archive is structurally validated, but non-evaluable range constraints remain `OSV_UNEVALUABLE`; missing snapshots and stale data must not be interpreted as complete coverage. A clean result is not proof that a package or application is free of vulnerabilities.
- Reachability evidence remains conservative when file/function hints or a
  sound analysis are unavailable. Experimental E1/E2 evidence is not complete
  runtime coverage or permission to suppress an unexplained alert.
- Transaction recovery is tested after process interruption. Physical power
  loss and every filesystem/hardware combination have not been exercised.
  pnpm/project-script side effects are not a general-purpose filesystem rollback.
- OSV snapshot replacement does not use the vendoring transaction journal.
  Its configured local path receives lexical checks, not the shared full
  filesystem-component guard; do not redirect it onto sensitive project state
  or through symlinks. No isolation from concurrent filesystem changes is claimed.
- Generated network/mirror/security TOML sections are not fully connected to
  CLI clients. They must not be assumed to enforce customized security limits
  or authenticated/private-registry routing.
- The installer requires independently trusted `cosign` and `slsa-verifier` and
  binds signatures/provenance to the artifact, repository and tag. Local tool
  doubles establish error handling and argument binding, **not** real hosted
  signing or cryptographic verification.
- Adoption runs project installation/build checks and removes own bookkeeping.
  Treat it as an explicit change in ownership, review the worktree and retain a
  Git recovery point.
- Dependency audit exemptions are not external audits. Incomplete `cargo vet`
  coverage remains a publication gate, not a reason to add unreviewed exemptions.

## Operational precautions

Use supported pnpm lock formats, keep vendored bytes tracked, review version and
license changes, run both integrity and project build/test checks, and preserve
required warnings. Use `update --no-pr` when automatic branch/commit/push/PR
operations are not authorized. Scope filesystem experiments to disposable
checkouts and avoid exposing credentials to third-party project scripts.

The normative threat-model source is not bundled into this repository or binary
archives. Request it from maintainers when needed; the public commands, these
limits and the regression tests remain the available contract.
