#!/usr/bin/env bash
# Independent kernel re-check of the built `.olean` artifacts. Builds the
# standalone `lean4checker` proof checker from a commit-pinned source
# checkout, then replays, module by module, every declaration in the
# audited root's import closure through the Lean kernel. This is the
# proof-checking path the trusted-computing-base document names: the
# artifacts count as verified only when a checker built outside this
# repository re-derives every kernel judgment. Requires a completed
# `lake build` — the checker reads the built `.olean` artifacts.

set -euo pipefail

cd "$(dirname "$0")/.."

# lean4checker source, pinned by full commit SHA. The checkout builds under
# this repository's own `lean-toolchain` pin, so the checker and the
# library always agree on the olean format.
LEAN4CHECKER_REPO="https://github.com/leanprover/lean4checker"
LEAN4CHECKER_COMMIT="91a7f0e8e9dffe927089f5a6edcfeeb8a0e07709"
LEAN4CHECKER_SRC="${LEAN4CHECKER_SRC:-.lake/lean4checker}"

if [ ! -d "$LEAN4CHECKER_SRC" ]; then
  git clone --quiet "$LEAN4CHECKER_REPO" "$LEAN4CHECKER_SRC"
fi
git -C "$LEAN4CHECKER_SRC" -c advice.detachedHead=false checkout --quiet \
  "$LEAN4CHECKER_COMMIT"
cp lean-toolchain "$LEAN4CHECKER_SRC/lean-toolchain"

( cd "$LEAN4CHECKER_SRC" && lake build lean4checker )

# Worker count bounds peak memory: each worker loads a near-complete
# environment while it replays one module's declarations.
lake env "$LEAN4CHECKER_SRC/.lake/build/bin/lean4checker" \
  --num-workers="${LEAN4CHECKER_WORKERS:-2}" Unicode

echo "clean: independent kernel re-check of the audited root succeeded"
