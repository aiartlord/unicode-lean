/-
  Unicode.Security.Identity.IdentifierTokens

  The identifier-shaped tokens of running text.

  A source file or a message is not one identifier, and the identifier
  detectors — mixed-script admissibility, homoglyph confusables — judge a
  whole document wrongly when handed one: a bilingual file mixes scripts as
  content, so every such file is reported.  Switching those detectors off for
  running text is wrong the other way: `scоpe` with a Cyrillic о inside a
  source file is exactly the homograph they exist to catch.

  The reading that is right for both is per token.  A token is a maximal run
  of codepoints with the UAX #31 `XID_Continue` property — the codepoints
  that may continue an identifier — and every such run in a file is judged
  as the identifier it is.  `scоpe` is one token mixing Latin and Cyrillic
  and fires; `مرحبا` is one single-script token and clears; `δ`, `α` and `β`
  in `δ = α − β` are three single-script tokens and clear.

  This is not source-region grammar.  No language is assumed and no region
  is exempt: an identifier run inside a string literal or a comment is a
  token like any other, and is judged the same way.
-/

import Unicode.Identifier

namespace Unicode.Security.Identity.IdentifierTokens

/-- True iff `cp` may continue an identifier: UAX #31 `XID_Continue`. -/
@[inline]
def isTokenChar (cp : Nat) : Bool :=
  Unicode.Identifier.isXIDContinue cp

/-- One token: where it starts in the input, and its codepoints. -/
structure Token where
  start : Nat
  cps   : List Nat
  deriving DecidableEq, Repr, Inhabited

/-- Walk the remaining input at index `idx`.  `current` is the open token's
    start and codepoints in reverse, or `none` between tokens; `acc` holds the
    finished tokens in reverse. -/
def walk : List Nat → Nat → Option (Nat × List Nat) → List Token → List Token
  | [], idx, current, acc =>
    Function.const Nat
      (match current with
       | none => acc.reverse
       | some (start, revCps) => ({ start := start, cps := revCps.reverse } :: acc).reverse)
      idx
  | cp :: rest, idx, current, acc =>
    if isTokenChar cp then
      match current with
      | none => walk rest (idx + 1) (some (idx, [cp])) acc
      | some (start, revCps) => walk rest (idx + 1) (some (start, cp :: revCps)) acc
    else
      match current with
      | none => walk rest (idx + 1) none acc
      | some (start, revCps) =>
        walk rest (idx + 1) none ({ start := start, cps := revCps.reverse } :: acc)

/-- The identifier-shaped tokens of `input`, in input order: maximal runs of
    `XID_Continue` codepoints, each with the position it starts at. -/
def tokens (input : List Nat) : List Token :=
  walk input 0 none []

/-- Shift a position list from token-relative to input-relative. -/
def shiftPositions (start : Nat) (positions : List Nat) : List Nat :=
  positions.map (fun p => p + start)

-- ═══════════════════════════════════════════════════════════════════════════════
-- Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

theorem tokens_empty : tokens [] = [] := by decide +kernel

/-- `ab cd` splits at the space into two tokens at 0 and 3. -/
theorem tokens_two_words :
    tokens [0x61, 0x62, 0x20, 0x63, 0x64] =
      [{ start := 0, cps := [0x61, 0x62] }, { start := 3, cps := [0x63, 0x64] }] := by
  decide +kernel

/-- `x = scоpe;` yields `x` and the mixed-script `scоpe` at 4; the operator,
    spaces and semicolon are not token characters. -/
theorem tokens_source_line :
    tokens [0x78, 0x20, 0x3D, 0x20, 0x73, 0x63, 0x043E, 0x70, 0x65, 0x3B] =
      [{ start := 0, cps := [0x78] }, { start := 4, cps := [0x73, 0x63, 0x043E, 0x70, 0x65] }] := by
  decide +kernel

/-- Greek variables in `δ = α − β` are three single-letter tokens. -/
theorem tokens_greek_math :
    tokens [0x03B4, 0x20, 0x3D, 0x20, 0x03B1, 0x20, 0x2212, 0x20, 0x03B2] =
      [{ start := 0, cps := [0x03B4] }, { start := 4, cps := [0x03B1] },
       { start := 8, cps := [0x03B2] }] := by
  decide +kernel

/-- A token that runs to the end of input is closed there. -/
theorem tokens_trailing :
    tokens [0x20, 0x61] = [{ start := 1, cps := [0x61] }] := by decide +kernel

end Unicode.Security.Identity.IdentifierTokens
