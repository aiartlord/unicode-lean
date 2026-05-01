/-
  Unicode.Idna.Map

  UTS #46 §4 step 1: codepoint mapping. For each codepoint in the
  input, apply the disposition's mapping target sequence:

    * Valid       → keep as-is
    * Mapped      → replace with the row's mapping target
    * Deviation   → replace (non-transitional) or keep (transitional)
    * Ignored     → drop
    * Disallowed  → reject the input string

  The output is the concatenation of every codepoint's mapping
  target, or `none` if any codepoint had a Disallowed disposition
  or fell outside the table.
-/

import Unicode.Idna.Disposition

namespace Unicode.Idna.Map

open Unicode.Generated.IdnaMapping
open Unicode.Idna.Disposition

/-- Apply the UTS #46 mapping pass to `input` under non-transitional
    processing. Returns `none` on any Disallowed (or out-of-table)
    codepoint; otherwise the concatenation of mapped sequences.
    Deviation codepoints are kept as-is. -/
def mapNonTransitional (input : Array Nat) : Option (Array Nat) := Id.run do
  let mut acc : Array Nat := #[]
  let mut ok  : Bool      := true
  for cp in input do
    match lookupRow? cp with
    | none     => ok := false
    | some row =>
      match row.disposition with
      | .Valid      => acc := acc.push cp
      | .Mapped     => acc := acc ++ row.mapping
      | .Deviation  => acc := acc.push cp
      | .Ignored    => pure ()
      | .Disallowed => ok := false
  return if ok then some acc else none

/-- Apply the UTS #46 mapping pass to `input` under transitional
    processing. Identical to `mapNonTransitional` except Deviation
    codepoints are mapped (matching IDNA2003 behaviour). -/
def mapTransitional (input : Array Nat) : Option (Array Nat) := Id.run do
  let mut acc : Array Nat := #[]
  let mut ok  : Bool      := true
  for cp in input do
    match lookupRow? cp with
    | none     => ok := false
    | some row =>
      match row.disposition with
      | .Valid      => acc := acc.push cp
      | .Mapped     => acc := acc ++ row.mapping
      | .Deviation  => acc := acc ++ row.mapping
      | .Ignored    => pure ()
      | .Disallowed => ok := false
  return if ok then some acc else none

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 EXAMPLES — the four UTS #46 §2.3 deviations + ASCII case folding
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "Faß" → "faß" non-transitionally (capital F mapped to f, sharp s preserved). -/
theorem mapNT_faß :
    mapNonTransitional #[0x0046, 0x0061, 0x00DF]
      = some #[0x0066, 0x0061, 0x00DF] := by native_decide

/-- "Faß" → "fass" transitionally (capital F mapped to f, sharp s → ss). -/
theorem mapTr_fass :
    mapTransitional #[0x0046, 0x0061, 0x00DF]
      = some #[0x0066, 0x0061, 0x0073, 0x0073] := by native_decide

/-- "EXAMPLE" → "example" (mapped) — pure case folding under either mode. -/
theorem mapNT_EXAMPLE :
    mapNonTransitional
      #[0x0045, 0x0058, 0x0041, 0x004D, 0x0050, 0x004C, 0x0045]
      = some #[0x0065, 0x0078, 0x0061, 0x006D, 0x0070, 0x006C, 0x0065] := by
  native_decide

/-- Soft hyphen U+00AD is dropped between letters. -/
theorem mapNT_soft_hyphen :
    mapNonTransitional #[0x0061, 0x00AD, 0x0062]
      = some #[0x0061, 0x0062] := by native_decide

/-- A Disallowed codepoint (C1 control U+0080) rejects the whole input. -/
theorem mapNT_rejects_C1 :
    mapNonTransitional #[0x0061, 0x0080, 0x0062] = none := by native_decide

/-- The empty string maps to the empty string under either mode. -/
theorem mapNT_empty : mapNonTransitional #[] = some #[] := by native_decide
theorem mapTr_empty : mapTransitional   #[] = some #[] := by native_decide

end Unicode.Idna.Map
