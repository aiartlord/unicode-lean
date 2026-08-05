#!/usr/bin/env bash
# Fail if any declaration in a `Unicode` module transitively depends on an
# axiom other than the Lean-core `propext`, `Quot.sound`, and
# `Classical.choice`. The source-level guard
# (`check-no-axiom.sh`) rejects the `axiom` keyword in the tree; this gate
# checks the elaborated artifacts themselves, so an axiom smuggled in
# through any path the text scan cannot see still fails CI. Requires a
# completed `lake build` — the probe imports the built `.olean` artifacts.

set -euo pipefail

cd "$(dirname "$0")/.."

lake env lean scripts/check-axiom-footprint.lean
