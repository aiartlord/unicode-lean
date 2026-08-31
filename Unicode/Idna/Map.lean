/-
  Unicode.Idna.Map

  UTS #46 §4 step 1: codepoint mapping. For each codepoint in the
  input, apply the disposition's mapping target sequence:

    * Valid       → keep as-is
    * Mapped      → replace with the row's mapping target
    * Deviation   → replace (non-transitional) or keep (transitional)
    * Ignored     → drop
    * Disallowed  → keep as-is, record a P1 error
    * Out-of-table → keep as-is, record a P1 error

  The implementation always returns a `Result` carrying the mapped
  output plus an `hasErrors` flag. Codepoints with `Disallowed`
  disposition (or absent from the table) are preserved in the output
  per UTS #46 §4 step 1 ("leave the code point unchanged in the
  string, and record that there was an error").
-/

import Unicode.Idna.Disposition

namespace Unicode.Idna.Map

set_option maxRecDepth 1000000

open Unicode.Generated.IdnaMapping
open Unicode.Idna.Disposition

/-- A UTS #46 / IDNA2008 status code, as `IdnaTestV2.txt` names them in its
    bracketed status columns. The twenty constructors are exactly the codes that
    file publishes.

    `A` codes come from the toASCII output stage, `X` from toUnicode's, `B` from
    the RFC 5893 Bidi rule, `C` from CONTEXTJ, `P` from Punycode, `U` from STD3,
    and `V` from label validity. -/
inductive Status where
  | A3 | A4_1 | A4_2
  | B1 | B2 | B3 | B4 | B5 | B6
  | C1 | C2
  | P4
  | U1
  | V1 | V2 | V3 | V4 | V6 | V7
  | X4_2
  deriving Repr, Inhabited, DecidableEq, Ord

/-- The tag `IdnaTestV2.txt` writes for a status. -/
def Status.tag : Status → String
  | .A3 => "A3"   | .A4_1 => "A4_1" | .A4_2 => "A4_2"
  | .B1 => "B1"   | .B2 => "B2"     | .B3 => "B3"
  | .B4 => "B4"   | .B5 => "B5"     | .B6 => "B6"
  | .C1 => "C1"   | .C2 => "C2"
  | .P4 => "P4"
  | .U1 => "U1"
  | .V1 => "V1"   | .V2 => "V2"     | .V3 => "V3"
  | .V4 => "V4"   | .V6 => "V6"     | .V7 => "V7"
  | .X4_2 => "X4_2"

/-- The output of an IDNA processing stage: the produced codepoint sequence, a
    flag indicating whether any UTS #46 error was recorded, and the status codes
    that were raised.

    `hasErrors` and `statuses` answer different questions. A conformance
    comparison against `IdnaTestV2.txt` needs the codes, because the file states
    which ones a row raises; a caller deciding whether to accept a name needs
    only the flag. -/
structure Result where
  output    : List Nat
  hasErrors : Bool
  statuses  : List Status := []
  deriving Repr, Inhabited, DecidableEq

instance : ToString Result where
  toString r :=
    s!"\{ output := {r.output}, hasErrors := {r.hasErrors}, " ++
    s!"statuses := {r.statuses.map Status.tag} }"

/-- Apply the UTS #46 mapping pass to `input` under non-transitional
    processing. Disallowed and out-of-table codepoints are preserved
    in the output and contribute a P1 error. Deviation codepoints are
    kept as-is. -/
def mapNonTransitional (input : List Nat) : Result := Id.run do
  let mut acc  : List Nat := []
  let mut errs : Bool      := false
  for cp in input do
    match lookupRow? cp with
    | none =>
      acc  := acc ++ [cp]
      errs := true
    | some row =>
      match row.disposition with
      | .Valid      => acc := acc ++ [cp]
      | .Mapped     => acc := acc ++ row.mapping
      | .Deviation  => acc := acc ++ [cp]
      | .Ignored    => pure ()
      | .Disallowed =>
        acc  := acc ++ [cp]
        errs := true
  return { output := acc, hasErrors := errs }

/-- Apply the UTS #46 mapping pass to `input` under transitional
    processing. Identical to `mapNonTransitional` except Deviation
    codepoints are mapped (matching IDNA2003 behaviour). The second
    pass resolves any Deviation codepoint introduced by the first
    pass's `Mapped` rows whose target is itself a Deviation
    (e.g. U+1E9E LATIN CAPITAL LETTER SHARP S maps to U+00DF, which
    is itself a Deviation): the transitional caller expects the
    chain to fully resolve. -/
def mapTransitional (input : List Nat) : Result := Id.run do
  let mut acc  : List Nat := []
  let mut errs : Bool      := false
  for cp in input do
    match lookupRow? cp with
    | none =>
      acc  := acc ++ [cp]
      errs := true
    | some row =>
      match row.disposition with
      | .Valid      => acc := acc ++ [cp]
      | .Mapped     => acc := acc ++ row.mapping
      | .Deviation  => acc := acc ++ row.mapping
      | .Ignored    => pure ()
      | .Disallowed =>
        acc  := acc ++ [cp]
        errs := true
  let mut result : List Nat := []
  for cp in acc do
    match lookupRow? cp with
    | none     => result := result ++ [cp]
    | some row =>
      match row.disposition with
      | .Valid      => result := result ++ [cp]
      | .Mapped     => result := result ++ [cp]
      | .Deviation  => result := result ++ row.mapping
      | .Ignored    => result := result ++ [cp]
      | .Disallowed => result := result ++ [cp]
  return { output := result, hasErrors := errs }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 EXAMPLES — the four UTS #46 §2.3 deviations + ASCII case folding
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "Faß" → "faß" non-transitionally (capital F mapped to f, sharp s preserved). -/
theorem mapNT_faß :
    mapNonTransitional [0x0046, 0x0061, 0x00DF]
      = { output := [0x0066, 0x0061, 0x00DF], hasErrors := false } := by
  decide +kernel

/-- "Faß" → "fass" transitionally (capital F mapped to f, sharp s → ss). -/
theorem mapTr_fass :
    mapTransitional [0x0046, 0x0061, 0x00DF]
      = { output := [0x0066, 0x0061, 0x0073, 0x0073], hasErrors := false } := by
  decide +kernel

/-- "FAẞ" → "fass" transitionally — exercises the chain
    U+1E9E → U+00DF → "ss" through the two-pass deviation resolution. -/
theorem mapTr_capital_sharp_s_chain :
    mapTransitional [0x0046, 0x0041, 0x1E9E]
      = { output := [0x0066, 0x0061, 0x0073, 0x0073], hasErrors := false } := by
  decide +kernel

/-- "EXAMPLE" → "example" (mapped) — pure case folding under either mode. -/
theorem mapNT_EXAMPLE :
    mapNonTransitional
      [0x0045, 0x0058, 0x0041, 0x004D, 0x0050, 0x004C, 0x0045]
      = { output := [0x0065, 0x0078, 0x0061, 0x006D, 0x0070, 0x006C, 0x0065],
          hasErrors := false } := by
  decide +kernel

/-- Soft hyphen U+00AD is dropped between letters. -/
theorem mapNT_soft_hyphen :
    mapNonTransitional [0x0061, 0x00AD, 0x0062]
      = { output := [0x0061, 0x0062], hasErrors := false } := by
  decide +kernel

/-- A Disallowed codepoint (C1 control U+0080) is preserved in the
    output with `hasErrors = true`. -/
theorem mapNT_flags_C1 :
    mapNonTransitional [0x0061, 0x0080, 0x0062]
      = { output := [0x0061, 0x0080, 0x0062], hasErrors := true } := by
  decide +kernel

/-- The empty string maps to the empty string under either mode. -/
theorem mapNT_empty :
    mapNonTransitional [] = { output := [], hasErrors := false } := by
  decide +kernel
theorem mapTr_empty :
    mapTransitional   [] = { output := [], hasErrors := false } := by
  decide +kernel

end Unicode.Idna.Map
