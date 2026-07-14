#!/usr/bin/env bash
# Fail if the default runtime root `Unicode` transitively imports proof-heavy
# assurance or full-conformance modules. This is a static import-graph check; it
# does not invoke Lean.
#
# Portable to bash 3.x (macOS default) — no associative arrays, no bash-4-only
# features. Uses a temp queue and plain text matching.

set -euo pipefail

cd "$(dirname "$0")/.."

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

queue="$tmpdir/queue"
seen="$tmpdir/seen"
imports="$tmpdir/imports"
violations="$tmpdir/violations"

: > "$seen"
: > "$violations"
echo "Unicode" > "$queue"

is_forbidden_module() {
  case "$1" in
    Unicode.Assurance|Unicode.Assurance.*) return 0 ;;
    Unicode.FullConformance|Unicode.FullConformance.*) return 0 ;;
    Unicode.Conformance|Unicode.Conformance.*) return 0 ;;

    Unicode.Normalization.ToNFDAppend|Unicode.Normalization.ToNFDAppend*) return 0 ;;
    Unicode.Normalization.ComposeInversion|Unicode.Normalization.ComposeInversion*) return 0 ;;
    Unicode.Normalization.ComposeBufferStructure|Unicode.Normalization.ComposeBufferStructure.*) return 0 ;;
    Unicode.Normalization.ComposeBlockAdditive|Unicode.Normalization.ComposeBlockAdditive.*) return 0 ;;
    Unicode.Normalization.ComposeKernelSupport|Unicode.Normalization.ComposeKernelSupport.*) return 0 ;;
    Unicode.Normalization.QuickCheckSoundness|Unicode.Normalization.QuickCheckSoundness*) return 0 ;;

    Unicode.CaseFoldCommutation|Unicode.CaseFoldCommutation.*) return 0 ;;
    Unicode.CaseFoldRoundtrip|Unicode.CaseFoldRoundtrip.*) return 0 ;;

    Unicode.Precis.Preparation|Unicode.Precis.Preparation.*) return 0 ;;
    Unicode.Precis.OpaqueString|Unicode.Precis.OpaqueString.*) return 0 ;;
    Unicode.Precis.ZsPreservation|Unicode.Precis.ZsPreservation.*) return 0 ;;
  esac
  return 1
}

while [ -s "$queue" ]; do
  current="$(head -n 1 "$queue")"
  tail -n +2 "$queue" > "$queue.next" && mv "$queue.next" "$queue"

  if grep -qxF "$current" "$seen"; then
    continue
  fi
  echo "$current" >> "$seen"

  if is_forbidden_module "$current"; then
    echo "$current" >> "$violations"
  fi

  module_path="$(echo "$current" | tr '.' '/').lean"
  [ -f "$module_path" ] || continue

  grep -hE '^import[[:space:]]+[A-Za-z_][A-Za-z0-9_.]*' "$module_path" \
    | awk '{print $2}' \
    | grep -E '^(Unicode|Unicode\.)' \
    > "$imports" || true
  while IFS= read -r imp; do
    [ -n "$imp" ] || continue
    if ! grep -qxF "$imp" "$seen"; then
      echo "$imp" >> "$queue"
    fi
  done < "$imports"
done

if [ -s "$violations" ]; then
  LC_ALL=C sort -u "$violations" > "$violations.sorted"
  count="$(wc -l < "$violations.sorted" | tr -d ' ')"
  echo "FATAL: default runtime root imports $count proof-heavy module(s):"
  sed 's/^/  /' "$violations.sorted"
  echo
  echo "Move the dependency behind Unicode.Assurance or a more specific opt-in proof root."
  exit 1
fi

echo "clean: Unicode runtime root does not import proof-heavy assurance modules"
