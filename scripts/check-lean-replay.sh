#!/usr/bin/env bash
# Replay the shared security verdict fixtures through the Lean `scan` and fail
# on any recorded verdict the Lean does not reproduce.
#
# The reference recorded the fixtures and every port is held to them byte for
# byte; this gate holds the fixtures, and so every port, to the spec. Each case
# is re-derived through `Unicode.Security.Policy.scan` and its wire projection
# (action, findings: code, family, severity, positions, sub-threat, detail) is
# compared with the recorded one. A difference is decided on the tracker as a
# spec change (proofs re-run) or a reference change (fixtures regenerated and
# every port following), never by editing the recorded verdict to match.
#
# Runs the native `corpus_differential` executable declared in `lakefile.lean`:
# the interpreted `lean --run` form costs ~0.3 s per case, too slow for the
# 5000-case corpus on a per-push path. The executable exits with the mismatch
# count (capped at 255), so a single divergence fails the gate.

set -euo pipefail

cd "$(dirname "$0")/.."

lake build corpus_differential

lake exe corpus_differential \
  fixtures/security/verdict_contract.json \
  fixtures/security/differential_corpus.json
