#!/usr/bin/env bash
# scripts/install-own.sh — bootstrapped installer for the `own` binaries (SPEC §10.1).
#
# Downloads `own` + `own-verify` for OWN_VERSION (pinned), verifies the cosign
# keyless signature AND the SLSA provenance BEFORE executing anything, then
# installs into OWN_BIN_DIR (default ~/.local/bin). No checksum-only install:
# a published binary is never replaced; a bad release means a new version.
#
# Usage: OWN_VERSION=v0.1.0 ./scripts/install-own.sh
# Env:   OWN_VERSION (required), OWN_BIN_DIR, OWN_REPO (default colinhacks/own-style
#        "nousresearch/own"), COSIGN_VERSION (pinned, default below).
set -euo pipefail

OWN_VERSION="${OWN_VERSION:?set OWN_VERSION (e.g. v0.1.0)}"
OWN_REPO="${OWN_REPO:-nousresearch/own}"
OWN_BIN_DIR="${OWN_BIN_DIR:-$HOME/.local/bin}"
COSIGN_VERSION="${COSIGN_VERSION:-v2.4.3}"
ARCH="$(uname -m)"; [ "$ARCH" = "x86_64" ] && ARCH=amd64; [ "$ARCH" = "aarch64" ] && ARCH=arm64
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ASSET="own-${OWN_VERSION}-${OS}-${ARCH}.tar.gz"
BASE="https://github.com/${OWN_REPO}/releases/download/${OWN_VERSION}"

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cd "$W"

# 1. pinned cosign, itself fetched over HTTPS from the GitHub release (checksum-verified
#    by cosign's own release process; see §10.1 bootstrapping note)
if ! command -v cosign >/dev/null 2>&1; then
  echo "installing pinned cosign ${COSIGN_VERSION}"
  curl -sSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${ARCH}" -o cosign
  curl -sSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-${COSIGN_VERSION}-checksums.txt" -o checksums.txt
  grep "cosign-linux-${ARCH}$" checksums.txt | sha256sum -c -
  chmod +x cosign
  COSIGN="$W/cosign"
else
  COSIGN="$(command -v cosign)"
fi

# 2. download release assets + bundles
for f in "$ASSET" "$ASSET.sig" "$ASSET.bundle" "$ASSET.sha256"; do
  curl -fsSL "${BASE}/${f}" -o "$f"
done

# 3. verify sha256 of the tarball (integrity of transport)
sha256sum -c "$ASSET.sha256"

# 4. verify cosign keyless signature (OIDC identity = the release workflow)
"$COSIGN" verify-blob \
  --certificate-identity-regexp "^https://github.com/${OWN_REPO}/\\.github/workflows/release\\.yml@refs/tags/${OWN_VERSION}$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature "$ASSET.sig" \
  --bundle "$ASSET.bundle" \
  "$ASSET"

# 5. verify SLSA provenance (level 3 via slsa-github-generator, referenced by tag per §17)
"$COSIGN" verify-blob-attestation \
  --certificate-identity-regexp "^https://github.com/slsa-framework/slsa-github-generator/\\.github/workflows/.*@refs/tags/v.*$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle "$ASSET.bundle" \
  --type "https://slsa.dev/provenance/v1" \
  "$ASSET" | python3 -c "import json,sys; p=json.load(sys.stdin); print('SLSA predicateType:', p['predicateType'])"

# 6. only now: extract and install
tar -xzf "$ASSET"
mkdir -p "$OWN_BIN_DIR"
install -m 0755 own "$OWN_BIN_DIR/own"
install -m 0755 own-verify "$OWN_BIN_DIR/own-verify"
echo "installed own ${OWN_VERSION} -> ${OWN_BIN_DIR}/own (signature + SLSA verified)"
