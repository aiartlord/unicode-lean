#!/usr/bin/env bash
# Independent kernel re-check of the built `.olean` artifacts. The Lean
# toolchain's bundled `leanchecker` replays every declaration in the audited
# root's import closure through the kernel, module by module. This is the
# proof-checking path the trusted-computing-base document names: the artifacts
# count as verified only when a checker the repository does not itself define
# re-derives every kernel judgment. Requires a completed `lake build` — the
# checker reads the built `.olean` artifacts.

set -euo pipefail

cd "$(dirname "$0")/.."

# Worker count bounds peak memory: each worker loads a near-complete
# environment while it replays one module's declarations.
lake env leanchecker --num-workers="${LEAN4CHECKER_WORKERS:-2}" Unicode

echo "clean: independent kernel re-check of the audited root succeeded"
