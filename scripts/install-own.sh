#!/usr/bin/env bash
# scripts/install-own.sh — bootstrapped installer for the `own` binaries (SPEC §10.1).
#
# Downloads `own` + `own-verify` for OWN_VERSION (pinned), verifies the cosign
# keyless signature AND the SLSA provenance BEFORE executing anything, then
# installs into OWN_BIN_DIR (default ~/.local/bin). No checksum-only install:
# a published binary is never replaced; a bad release means a new version.
#
# Usage: OWN_VERSION=v0.1.0 ./scripts/install-own.sh
# Requires trusted, preinstalled cosign and slsa-verifier. Never bootstrap a
# verifier from the same untrusted downloads it is supposed to authenticate.
set -euo pipefail

OWN_VERSION="${OWN_VERSION:?set OWN_VERSION (e.g. v0.1.0)}"
OWN_REPO="${OWN_REPO:-YourFriendPollux/own}"
OWN_BIN_DIR="${OWN_BIN_DIR:-$HOME/.local/bin}"
PROV="${OWN_PROVENANCE_ASSET:-multiple.intoto.jsonl}"
refuse() { echo "install-own: $*" >&2; exit 2; }
[[ "$OWN_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || refuse "invalid OWN_VERSION"
[[ "$OWN_REPO" =~ ^[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+$ ]] || refuse "invalid OWN_REPO"
[[ "$PROV" =~ ^[0-9A-Za-z_-][0-9A-Za-z_.-]*\.intoto\.jsonl$ ]] || refuse "invalid OWN_PROVENANCE_ASSET"
ARCH="$(uname -m)"; [ "$ARCH" = "x86_64" ] && ARCH=amd64; [ "$ARCH" = "aarch64" ] && ARCH=arm64
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"   # linux | darwin
case "$OS-$ARCH" in linux-amd64|linux-arm64|darwin-arm64) ;; *) refuse "unsupported platform: $OS-$ARCH";; esac
COSIGN="$(command -v cosign)" || refuse "install a trusted cosign on PATH first"
SLSA="$(command -v slsa-verifier)" || refuse "install a trusted slsa-verifier on PATH first"
if command -v sha256sum >/dev/null; then
  CHECKSUM=(sha256sum)
elif command -v shasum >/dev/null; then
  CHECKSUM=(shasum -a 256)
else
  refuse "missing prerequisite: sha256sum or shasum"
fi
for cmd in curl tar install; do
  command -v "$cmd" >/dev/null || refuse "missing prerequisite: $cmd"
done
ASSET="own-${OWN_VERSION}-${OS}-${ARCH}.tar.gz"
BASE="https://github.com/${OWN_REPO}/releases/download/${OWN_VERSION}"

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cd "$W"


# 2. download release assets: tarball + its sha256 manifest + the cosign bundle
#    produced by the release workflow (sign-blob --bundle). No detached .sig:
#    the release signs blobs into .bundle files.
for f in "$ASSET" "$ASSET.sha256" "$ASSET.bundle"; do
  curl -fsSL "${BASE}/${f}" -o "$f"
done

# 3. Check exactly this tarball, not arbitrary paths in an untrusted manifest.
read -r EXPECTED NAME EXTRA < "$ASSET.sha256"
[[ "$EXPECTED" =~ ^[0-9a-f]{64}$ && "$NAME" = "$ASSET" && -z "$EXTRA" ]] || refuse "invalid checksum manifest"
ACTUAL="$("${CHECKSUM[@]}" "$ASSET")"
[[ "${ACTUAL%% *}" = "$EXPECTED" ]] || refuse "checksum mismatch"

# 4. verify cosign keyless signature (OIDC identity = this repo's release workflow)
"$COSIGN" verify-blob \
  --certificate-identity "https://github.com/${OWN_REPO}/.github/workflows/release.yml@refs/tags/${OWN_VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle "$ASSET.bundle" \
  "$ASSET"

# 5. verify SLSA provenance attestation (generator: slsa-github-generator).
#    The generator signs ONE attestation for all release subjects, so its default
#    asset name is `multiple.intoto.jsonl` — not `<asset>.intoto.jsonl`, which the
#    previous version of this script asked for and could never find. Override with
#    OWN_PROVENANCE_ASSET when a release renames it.
fetch() { # $1 = asset name; never leaves a half-written file behind
  curl -fsSL "${BASE}/$1" -o "$1" || {
    echo "install-own: release ${OWN_VERSION} does not publish '$1'" >&2
    echo "install-own: set OWN_PROVENANCE_ASSET to the attestation asset name" >&2
    exit 2
  }
}
fetch "$PROV"
# The generic generator publishes a signed DSSE .intoto.jsonl, not a separate
# cosign bundle. Verify its signature AND its subject/source/ref binding.
"$SLSA" verify-artifact "$ASSET" \
  --provenance-path "$PROV" \
  --source-uri "github.com/${OWN_REPO}" \
  --source-tag "$OWN_VERSION" \
  --builder-id "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"

# 6. only now: extract and install
tar -xzf "$ASSET" own own-verify
for binary in own own-verify; do
  [ -f "$binary" ] && [ ! -L "$binary" ] || refuse "invalid or missing binary: $binary"
done
mkdir -p "$OWN_BIN_DIR"
install -m 0755 own "$OWN_BIN_DIR/own"
install -m 0755 own-verify "$OWN_BIN_DIR/own-verify"
echo "installed own ${OWN_VERSION} -> ${OWN_BIN_DIR}/own (signature + SLSA verified)"
