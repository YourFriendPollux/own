#!/usr/bin/env bash
# scripts/day1.sh — Go/No-Go Jour 1. Exit 0 = GO, 1 = NO-GO, 2 = prérequis manquant.
# NON EXÉCUTÉ À CE JOUR : à lancer, observer, corriger. Les sorties "NOTE" documentent un comportement
# (elles ne font pas échouer) ; les sorties "FAIL" font échouer. Réseau requis (npm registry).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PNPM_VERSIONS=${PNPM_VERSIONS:-"9 10"}
THRESHOLD=${THRESHOLD:-15}
for c in jq npm npx node tar diff; do
  command -v "$c" >/dev/null || { echo "missing prerequisite: $c" >&2; exit 2; }
done
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
FAILS=0
fail() { echo "FAIL: $*" >&2; FAILS=$((FAILS+1)); }
note() { echo "NOTE: $*"; }

# 1. Éligibilité mesurée sur le corpus versionné scripts/corpus.txt (≥ 100 paquets ; un nom par ligne ;
#    '#' = commentaire ; en-tête = date + source du classement). Critères = §9.1 (sans types ni taille).
: > "$W/eligibility.jsonl"
while read -r pkg; do
  if ! npm view "$pkg@latest" --json 2>/dev/null | jq -c --arg p "$pkg" '{
      name: $p,
      deps: ((.dependencies // {}) | length),
      peer: ((.peerDependencies // {}) | length),
      opt: ((.optionalDependencies // {}) | length),
      bundled: ((.bundleDependencies // .bundledDependencies // []) | if type == "array" then length else 1 end),
      bin: ((.bin != null) or (.directories.bin != null)),
      native: ((.os != null) or (.cpu != null) or (.gypfile == true)),
      install_scripts: ([(.scripts // {}) | keys[] | select(IN("preinstall","install","postinstall","prepare"))] | length),
      license: (.license | if type == "string" then . else null end)
    }' >> "$W/eligibility.jsonl"; then
    note "skipped (npm view failed): $pkg"
  fi
done < <(grep -Ev '^(#|$)' "$ROOT/scripts/corpus.txt")
TOTAL=$(wc -l < "$W/eligibility.jsonl")
ELIGIBLE=$(jq -s '[.[] | select(.deps==0 and .peer==0 and .opt==0 and .bundled==0
    and (.bin|not) and (.native|not) and .install_scripts==0
    and (.license | IN("MIT","BSD-2-Clause","BSD-3-Clause","Apache-2.0","ISC")))] | length' "$W/eligibility.jsonl")
echo "eligible: $ELIGIBLE / $TOTAL (seuil: $THRESHOLD)"
[ "$TOTAL" -ge 100 ] || fail "corpus trop petit ($TOTAL < 100)"
[ "$ELIGIBLE" -ge "$THRESHOLD" ] || fail "éligibles insuffisants"

# 2. Intégration réelle, pour chaque version majeure de pnpm supportée.
set_override() { # $1=clé $2=valeur (écrit dans package.json racine)
  jq --arg k "$1" --arg v "$2" '.pnpm.overrides[$k] = $v' package.json > package.json.tmp && mv package.json.tmp package.json
}
make_probe() { # $1=dossier $2=nom $3=scripts-json : paquet synthétique local
  mkdir -p "$1"
  jq -n --arg n "$2" --argjson s "$3" '{name:$n, version:"1.0.0", main:"index.js", scripts:$s}' > "$1/package.json"
  echo "module.exports = 1;" > "$1/index.js"
}
run_case() {
  local V=$1 D="$W/pnpm-$1"; local P=(npx --yes "pnpm@$V")
  mkdir -p "$D/tarballs" "$D/vendor/own"; cd "$D"
  echo "== pnpm@$V ($("${P[@]}" --version))"
  printf '{"name":"day1","version":"0.0.0","private":true}\n' > package.json

  # 2a. Cas nominal : zod@3.22.4 depuis un vrai tarball
  (cd tarballs && npm pack zod@3.22.4 >/dev/null)
  mkdir -p "vendor/own/zod@3.22.4"
  tar -xzf tarballs/zod-3.22.4.tgz -C "vendor/own/zod@3.22.4" --strip-components=1
  "${P[@]}" add "file:vendor/own/zod@3.22.4"      || fail "pnpm@$V: add file:"  # [À VALIDER] forme exacte ; tester aussi "zod@file:..."
  set_override zod "file:vendor/own/zod@3.22.4"   # [À VALIDER] override seul vs override + dépendance file:
  "${P[@]}" install                               || fail "pnpm@$V: install"
  "${P[@]}" install --frozen-lockfile             || fail "pnpm@$V: frozen-lockfile instable"
  node -e "process.exit(require('zod').z ? 0 : 1)" || fail "pnpm@$V: require('zod')"
  local INST
  INST=$(find node_modules/.pnpm -maxdepth 3 -path '*/node_modules/zod' | head -n1 || true)
  if [ -z "$INST" ]; then fail "pnpm@$V: copie installée introuvable"; else
    if [ -L "$INST" ]; then note "pnpm@$V: SYMLINK -> $(readlink -f "$INST")"; else note "pnpm@$V: copie/hardlink ($INST)"; fi
    if diff -r "$INST" "vendor/own/zod@3.22.4" > "$D/installed.diff"; then note "pnpm@$V: installé == vendor (octets)";
    else note "pnpm@$V: installé != vendor, voir $D/installed.diff (sous-ensemble toléré par §8.1 ?)"; head -n 20 "$D/installed.diff"; fi
  fi
  grep -n -A3 '^overrides:' pnpm-lock.yaml || note "pnpm@$V: pas de section overrides: dans pnpm-lock.yaml"

  # 2b. Scripts lifecycle : sonde synthétique (postinstall qui écrit un marqueur) ; détection via ndjson
  make_probe "vendor/own/probe@1.0.0" probe '{"postinstall":"node -e \"require(\\\"fs\\\").writeFileSync(process.env.INIT_CWD + \\\"/LIFECYCLE_RAN\\\", \\\"x\\\")\""}'
  "${P[@]}" add "file:vendor/own/probe@1.0.0" >/dev/null || fail "pnpm@$V: sonde lifecycle (add)"
  [ -e LIFECYCLE_RAN ] && note "pnpm@$V: le postinstall d'un file: dossier S'EXÉCUTE" || note "pnpm@$V: postinstall NON exécuté pour file:"
  rm -f LIFECYCLE_RAN
  local N; N=$("${P[@]}" install --force --reporter=ndjson 2>/dev/null | grep -c 'pnpm:lifecycle' || true)
  note "pnpm@$V: événements pnpm:lifecycle observés = $N (la détection §5 exige que la sonde en produise ≥ 1 quand le script s'exécute)"

  # 2c. Paquet scopé : dossier @scope+name@version
  make_probe "vendor/own/@day1+scoped@1.0.0" "@day1/scoped" '{}'
  "${P[@]}" add "file:vendor/own/@day1+scoped@1.0.0" || fail "pnpm@$V: scopé (add)"
  set_override "@day1/scoped" "file:vendor/own/@day1+scoped@1.0.0"
  "${P[@]}" install --frozen-lockfile >/dev/null 2>&1 || "${P[@]}" install || fail "pnpm@$V: scopé (install)"
  node -e "require('@day1/scoped')" || fail "pnpm@$V: require('@day1/scoped')"

  # 2d. Workspace à 2 importers ; chemin file: relatif à l'importer ; override à la racine
  local WS="$W/ws-$V"; mkdir -p "$WS/packages/a" "$WS/packages/b" "$WS/vendor/own"; cd "$WS"
  cp -r "$D/vendor/own/zod@3.22.4" "vendor/own/"
  printf 'packages:\n  - "packages/*"\n' > pnpm-workspace.yaml
  printf '{"name":"ws","version":"0.0.0","private":true}\n' > package.json
  printf '{"name":"a","version":"0.0.0","dependencies":{"zod":"file:../../vendor/own/zod@3.22.4"}}\n' > packages/a/package.json
  printf '{"name":"b","version":"0.0.0","dependencies":{"zod":"file:../../vendor/own/zod@3.22.4"}}\n' > packages/b/package.json
  set_override zod "file:vendor/own/zod@3.22.4"
  "${P[@]}" install                   || fail "pnpm@$V: workspace install"
  "${P[@]}" install --frozen-lockfile || fail "pnpm@$V: workspace frozen-lockfile"
  (cd packages/a && node -e "process.exit(require('zod').z ? 0 : 1)") || fail "pnpm@$V: workspace require"
  # Variante pnpm ≥ 10 : override dans pnpm-workspace.yaml (information, non bloquant)
  if [ "$V" -ge 10 ]; then
    jq 'del(.pnpm)' package.json > package.json.tmp && mv package.json.tmp package.json
    printf 'overrides:\n  zod: "file:vendor/own/zod@3.22.4"\n' >> pnpm-workspace.yaml
    if "${P[@]}" install >/dev/null 2>&1 && "${P[@]}" install --frozen-lockfile >/dev/null 2>&1; then
      note "pnpm@$V: override dans pnpm-workspace.yaml FONCTIONNE"; else note "pnpm@$V: override dans pnpm-workspace.yaml ne fonctionne pas"; fi
  fi
  cd "$W"
}
for V in $PNPM_VERSIONS; do run_case "$V"; done

if [ "$FAILS" -eq 0 ]; then echo GO; else echo "NO-GO ($FAILS échec(s))"; exit 1; fi
