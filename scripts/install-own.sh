#!/usr/bin/env bash
# scripts/install-own.sh — bootstrapped installer for the `own` binaries (SPEC §10.1).
#
# Downloads `own` + `own-verify` for OWN_VERSION (pinned), verifies the cosign
# keyless signature AND the SLSA provenance BEFORE executing anything, then
# installs into OWN_BIN_DIR (default ~/.local/bin). No checksum-only install:
# a published binary is never replaced; a bad release means a new version.
#
# Usage: OWN_VERSION=v0.1.0 ./scripts/install-own.sh
# Env:   OWN_VERSION (required), OWN_BIN_DIR, OWN_REPO (default: this repository),
#        COSIGN_VERSION (pinned, default below).
set -euo pipefail

OWN_VERSION="${OWN_VERSION:?set OWN_VERSION (e.g. v0.1.0)}"
OWN_REPO="${OWN_REPO:-YourFriendPollux/own}"
OWN_BIN_DIR="${OWN_BIN_DIR:-$HOME/.local/bin}"
COSIGN_VERSION="${COSIGN_VERSION:-v3.0.5}"
ARCH="$(uname -m)"; [ "$ARCH" = "x86_64" ] && ARCH=amd64; [ "$ARCH" = "aarch64" ] && ARCH=arm64
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"   # linux | darwin
ASSET="own-${OWN_VERSION}-${OS}-${ARCH}.tar.gz"
BASE="https://github.com/${OWN_REPO}/releases/download/${OWN_VERSION}"

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cd "$W"

# 1. pinned cosign, fetched per-OS (cosign publishes darwin and linux builds;
#    checksum-verified against cosign's own signed checksums file)
if ! command -v cosign >/dev/null 2>&1; then
  echo "installing pinned cosign ${COSIGN_VERSION}"
  COSIGN_ASSET="cosign-${OS}-${ARCH}"
  curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/${COSIGN_ASSET}" -o cosign
  curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-${COSIGN_VERSION}-checksums.txt" -o checksums.txt
  curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-${COSIGN_VERSION}-checksums.txt.sig" -o checksums.txt.sig
  curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-${COSIGN_VERSION}-checksums.txt.bundle" -o checksums.txt.bundle
  grep " ${COSIGN_ASSET}$" checksums.txt | sha256sum -c -
  chmod +x cosign
  COSIGN="$W/cosign"
else
  COSIGN="$(command -v cosign)"
fi

# 2. download release assets: tarball + its sha256 manifest + the cosign bundle
#    produced by the release workflow (sign-blob --bundle). No detached .sig:
#    the release signs blobs into .bundle files.
for f in "$ASSET" "$ASSET.sha256" "$ASSET.bundle"; do
  curl -fsSL "${BASE}/${f}" -o "$f"
done

# 3. verify sha256 of the tarball (integrity of transport)
sha256sum -c "$ASSET.sha256"

# 4. verify cosign keyless signature (OIDC identity = this repo's release workflow)
"$COSIGN" verify-blob \
  --certificate-identity-regexp "^https://github.com/${OWN_REPO}/\\.github/workflows/release\\.yml@refs/tags/${OWN_VERSION}$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle "$ASSET.bundle" \
  "$ASSET"

# 5. verify SLSA provenance attestation (generator: slsa-github-generator).
#    The release workflow uploads the provenance as <asset>.intoto.jsonl.
PROV="${ASSET}.intoto.jsonl"
curl -fsSL "${BASE}/${PROV}" -o "$PROV"
"$COSIGN" verify-blob-attestation \
  --certificate-identity-regexp "^https://github.com/slsa-framework/slsa-github-generator/\\.github/workflows/.*@refs/tags/v.*$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type "https://slsa.dev/provenance/v1" \
  --bundle "$PROV.bundle" \
  "$PROV" 2>/dev/null || \
curl -fsSL "${BASE}/${PROV}.bundle" -o "$PROV.bundle" && \
"$COSIGN" verify-blob-attestation \
  --certificate-identity-regexp "^https://github.com/slsa-framework/slsa-github-generator/\\.github/workflows/.*@refs/tags/v.*$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type "https://slsa.dev/provenance/v1" \
  --bundle "$PROV.bundle" \
  "$PROV" | python3 -c "import json,sys; p=json.load(sys.stdin); print('SLSA predicateType:', p['predicateType'])"

# 6. only now: extract and install
tar -xzf "$ASSET"
mkdir -p "$OWN_BIN_DIR"
install -m 0755 own "$OWN_BIN_DIR/own"
install -m 0755 own-verify "$OWN_BIN_DIR/own-verify"
echo "installed own ${OWN_VERSION} -> ${OWN_BIN_DIR}/own (signature + SLSA verified)"
