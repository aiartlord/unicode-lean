# Trusted Computing Base — unicode-lean

This document states precisely what must be trusted for the correctness
claims of `unicode-lean` to hold, and — equally important — what does **not**
have to be trusted. It is the answer to the two questions a serious reviewer
asks first: *"what exactly is in the TCB?"* and *"what is the Thompson-attack
terminus?"*

## What IS in the trusted computing base

1. **The Lean 4 kernel** as implemented in `lean4checker`, the independent
   proof-checking binary — a small, fixed type-checker for the Lean 4
   dependent type theory, shared across the entire Lean ecosystem and subject
   to community audit. Pinned toolchain: `leanprover/lean4:v4.32.0`. Every
   `.olean` this project produces re-checks independently under `lean4checker`;
   the correctness argument depends only on that re-check succeeding.

2. **The pinned Unicode Character Database, version 17.0.0**, byte-for-byte
   identical to the tables published at unicode.org. This is not an assumed
   equivalence: `Unicode/UCD.lean` computes the real SHA-256 of every pinned
   file at build time (via `Unicode/Sha256.lean`, a from-scratch FIPS-180-4
   implementation) and aborts the build on any mismatch; `Unicode/Ucd/
   SHA256SUMS` pins the digests (e.g. `UnicodeData.txt` =
   `2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c`); and
   `scripts/check-ucd-upstream.sh` (run in CI) verifies those bytes are
   byte-identical to the official unicode.org 17.0.0 publication, not merely
   to what was committed. The chain grounds out at the Unicode Consortium.

3. **The C++ compiler used by the reviewer to build `lean4checker`.** See the
   Thompson-attack terminus below.

## What is explicitly NOT in the trusted computing base

- **The Lean elaborator.** Any elaboration bug produces a proof term that
  either type-checks under `lean4checker` — in which case it is valid — or
  does not, in which case the build fails. Elaboration is untrusted.

- **The Lean compiler used to build the `.olean` artifacts.** The artifacts
  re-check independently under the kernel; a miscompilation cannot forge a
  kernel-accepted proof.

- **The Lean runtime / compiled evaluation.** `native_decide` and `bv_decide`
  are banned throughout the tree — **zero occurrences** — so no proof depends
  on running compiled code. Every decision procedure is discharged by the
  kernel itself (`decide` / `decide +kernel`), at whatever cost in check time
  that entails. This is the discipline that distinguishes the artifact; it is
  enforced, not aspirational.

- **`sorry` and axioms.** Zero `sorry` in any proof and zero `axiom`
  declarations across the tree. (A text search for "sorry" finds exactly one
  hit — the string `"sorry"` as a valid BIP-39 mnemonic word in a bundled
  wordlist — which is data, not a proof.)

- **Any test suite.** Tests exercise the code but are not part of the
  correctness argument; the proofs are.

- **Any vendor-supplied library.** The project is self-contained against the
  Lean 4 core toolchain. No Mathlib dependency.

## The Thompson-attack terminus

The C++ compiler used to build `lean4checker` is the Ken-Thompson-attack
terminus of this trust chain. This is named honestly rather than hidden:

- Reviewers who accept this residual risk can obtain a pre-built
  `lean4checker` from the official Lean 4 release channel.
- Reviewers who require diverse compilation (Wheeler 2009, "Countering Trusting
  Trust through Diverse Double-Compiling") can build `lean4checker` from source
  under any two compliant C++ compilers of their choice and compare the
  resulting binaries.
- Straylight's related Continuity work extends this chain further via
  cryptographic build triangulation; `unicode-lean` itself does not depend on
  that mechanism, so no additional trust is imported here.

That converts the Thompson-attack question from a gotcha into a stated,
mitigable assumption — which is the whole point of writing the TCB down.
