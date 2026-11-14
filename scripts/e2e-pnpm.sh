#!/usr/bin/env bash
# End-to-end: own add + real pnpm install, pnpm major 9 and 10 (SPEC §8.1, §13).
# Real registry, real installs. Every line is an observed result: PASS/FAIL/NOTE.
set -uo pipefail

SB=$(cd "$(dirname "$0")/.." && pwd)
OWN=$SB/target/release/own
OWNV=$SB/target/release/own-verify
W=$(mktemp -d /tmp/e2e.XXXXXX)
FAILS=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS+1)); }
note() { echo "NOTE  $*"; }

echo "workdir: $W"
$OWN --version

# SPEC §5: git >= 2.30 is a prerequisite of add. A project outside a work tree
# must fail loudly with an actionable GIT_ERROR, never vendor silently.
mkdir -p "$W/nogit"; cd "$W/nogit"
printf '{"name":"nogit","version":"0.0.0","private":true}\n' > package.json
npx --yes pnpm@10 add zod@3.22.4 >/dev/null 2>&1
"$OWN" init --root . >/dev/null 2>&1
"$OWN" add zod@3.22.4 --root . > nogit.out 2>&1; RC=$?
if [ $RC -eq 2 ] && grep -q 'GIT_ERROR' nogit.out && grep -q 'git init' nogit.out; then
  pass "no work tree: add refuses with an actionable GIT_ERROR (exit 2)"
else
  fail "no work tree: expected exit 2 + GIT_ERROR + 'git init', got exit $RC"; tail -3 nogit.out
fi
# `own init` creates the vendor/own layout, so the check is on the package dir.
[ -d "vendor/own/zod@3.22.4" ] && fail "no work tree: a package was vendored anyway" \
  || pass "no work tree: no package vendored"

for V in 9 10; do
  D=$W/pnpm$V; mkdir -p "$D"; cd "$D"
  # SPEC §: `pnpm --version` is authoritative for own, so the whole iteration
  # must see a single pnpm major: pin it with a shim first on PATH instead of
  # mixing npx pnpm@9 for the project with the host's pnpm on own's side.
  mkdir -p "$W/bin$V"
  printf '#!/bin/sh\nexec npx --yes pnpm@%s "$@"\n' "$V" > "$W/bin$V/pnpm"
  chmod +x "$W/bin$V/pnpm"
  export PATH="$W/bin$V:$PATH"
  PNPM=(pnpm)
  echo
  echo "=== pnpm@$V ($("${PNPM[@]}" --version 2>/dev/null)) ==="
  printf '{"name":"e2e","version":"0.0.0","private":true}\n' > package.json
  git init -q

  "${PNPM[@]}" add zod@3.22.4 >/dev/null 2>&1 && pass "pnpm@$V: add zod@3.22.4 (registry)" \
    || fail "pnpm@$V: add zod@3.22.4 (registry)"
  [ -f pnpm-lock.yaml ] && pass "pnpm@$V: pnpm-lock.yaml written" || fail "pnpm@$V: no pnpm-lock.yaml"

  "$OWN" init --root . > init.out 2>&1 && pass "own init" \
    || { fail "own init"; sed -n '1,5p' init.out; }
  [ -f own.toml ] && [ -f own.lock ] && pass "own.toml + own.lock created" || fail "own init files missing"

  "$OWN" add zod@3.22.4 --root . > add.out 2>&1 && pass "own add zod@3.22.4" \
    || { fail "own add zod@3.22.4"; sed -n '1,5p' add.out; }
  [ -d vendor/own/zod@3.22.4 ] && pass "vendor/own/zod@3.22.4 exists" || fail "vendor dir missing"
  jq -e '.pnpm.overrides.zod' package.json >/dev/null 2>&1 \
    && note "override: $(jq -c '.pnpm.overrides.zod' package.json)" \
    || fail "no zod override in package.json"

  "$OWN" verify --root . > verify1.out 2>&1 && pass "own verify (fresh)" \
    || { fail "own verify (fresh)"; sed -n '1,5p' verify1.out; }

  "${PNPM[@]}" install > install.out 2>&1 && pass "pnpm@$V: install" \
    || { fail "pnpm@$V: install"; tail -5 install.out; }
  "${PNPM[@]}" install --frozen-lockfile > frozen.out 2>&1 && pass "pnpm@$V: install --frozen-lockfile stable" \
    || { fail "pnpm@$V: install --frozen-lockfile"; tail -5 frozen.out; }

  node -e "const z=require('zod'); process.exit(z.z||z.string?0:1)" 2>/dev/null && pass "pnpm@$V: require('zod') works" \
    || fail "pnpm@$V: require('zod') failed"

  INST=$(find node_modules/.pnpm -maxdepth 3 -path '*/node_modules/zod' -not -path '*/zod/*' | head -n1)
  if [ -z "$INST" ]; then fail "pnpm@$V: installed zod copy not found"; else
    if [ -L "$INST" ]; then note "pnpm@$V: installed as SYMLINK -> $(readlink -f "$INST")"
    elif diff -r "$INST" vendor/own/zod@3.22.4 > inst.diff 2>&1; then pass "pnpm@$V: installed bytes == vendor"
    else note "pnpm@$V: installed != vendor ($(grep -c '^' inst.diff) diff lines) — see $D/inst.diff"; fi
  fi
  "$OWN" verify --root . --installed > verify2.out 2>&1 && pass "own verify --installed" \
    || { fail "own verify --installed"; sed -n '1,6p' verify2.out; }

  # lifecycle: a dependency script must not run; the detector must see the probe if it does
  mkdir -p probe
  jq -n '{name:"probe",version:"1.0.0",main:"index.js",scripts:{postinstall:"node -e \"require(\\\"fs\\\").writeFileSync(process.env.INIT_CWD + \\\"/LIFECYCLE_RAN\\\",\\\"x\\\")\""}}' > probe/package.json
  echo 'module.exports = 1;' > probe/index.js
  if "${PNPM[@]}" add file:probe > probe.out 2>&1; then
    if [ -e LIFECYCLE_RAN ]; then note "pnpm@$V: a file: dependency's postinstall DID run"
    else pass "pnpm@$V: file: dependency postinstall did not run"; fi
  else
    fail "pnpm@$V: pnpm add file:probe failed"; tail -4 probe.out
  fi
  grep -q 'Ignored build scripts' probe.out && note "pnpm@$V: pnpm reported ignored build scripts" || true
  rm -f LIFECYCLE_RAN
  N=$("${PNPM[@]}" install --force --reporter=ndjson 2>/dev/null | grep -c 'pnpm:lifecycle')
  note "pnpm@$V: pnpm:lifecycle events observed = $N (detector needs >= 1 when a script runs)"

  # tamper a file the manifest lists (zod's root has no index.js: main is lib/index.js)
  TARGET=vendor/own/zod@3.22.4/lib/index.js
  cp "$TARGET" tamper.bak
  echo '// tampered' >> "$TARGET"
  "$OWN" verify --root . > verify3.out 2>&1; RC=$?
  if [ $RC -eq 1 ] && grep -q 'DRIFT_MODIFIED.*lib/index.js' verify3.out; then pass "pnpm@$V: modified vendor file -> DRIFT_MODIFIED (exit 1)"
  else fail "pnpm@$V: modified vendor file not reported as DRIFT_MODIFIED (exit $RC)"; sed -n '1,6p' verify3.out; fi

  # independent verifier agrees with the same lock
  "$OWNV" --root . > verify4.out 2>&1; RC=$?
  if [ $RC -eq 1 ] && grep -q 'DRIFT_MODIFIED.*lib/index.js' verify4.out; then pass "own-verify: same drift detected (exit 1)"
  else fail "own-verify: drift not reported as DRIFT_MODIFIED (exit $RC)"; sed -n '1,6p' verify4.out; fi

  # an unlisted file is extra, not silently ignored
  echo 'module.exports = 2;' > vendor/own/zod@3.22.4/extra.js
  "$OWN" verify --root . > verify5.out 2>&1; RC=$?
  if [ $RC -eq 1 ] && grep -q 'DRIFT_EXTRA.*extra.js' verify5.out; then pass "pnpm@$V: unlisted file -> DRIFT_EXTRA (exit 1)"
  else fail "pnpm@$V: unlisted file not reported as DRIFT_EXTRA (exit $RC)"; sed -n '1,6p' verify5.out; fi
  rm -f vendor/own/zod@3.22.4/extra.js
  mv tamper.bak "$TARGET"
  "$OWN" verify --root . > verify6.out 2>&1 && pass "pnpm@$V: restored tree verifies clean again" \
    || { fail "pnpm@$V: restored tree still reports findings"; sed -n '1,6p' verify6.out; }
done

echo
echo "FAILS=$FAILS  (workdir kept: $W)"
exit $([ "$FAILS" -eq 0 ] && echo 0 || echo 1)