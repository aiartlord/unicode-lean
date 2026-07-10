/-
  Unicode.Idna.Disposition

  UTS #46 §5: per-codepoint disposition lookup against the IDNA
  Mapping Table. Each codepoint receives one of five dispositions —
  Valid, Mapped, Ignored, Deviation, Disallowed — together with a
  mapping target sequence for `Mapped` and `Deviation` rows.

  This module exposes both the row-level lookup and the two
  variants of UTS #46 mapping defined by the spec: non-transitional
  (the default) and transitional. The two differ only on the four
  Deviation codepoints — U+00DF, U+03C2, U+200C, U+200D — which are
  mapped non-transitionally and kept as-is transitionally.
-/

import Unicode.Generated.IdnaMapping

namespace Unicode.Idna.Disposition

set_option maxRecDepth 1000000

open Unicode.Generated.IdnaMapping

/-- Look up the disposition row for codepoint `cp`. Returns `none`
    only for codepoints outside the IDNA mapping table coverage
    (e.g. some reserved blocks beyond the published ranges). -/
def lookupRow? (cp : Nat) : Option IdnaRow :=
  Unicode.Generated.IdnaMapping.lookupRowList? cp

/-- Disposition of `cp`, defaulting to `Disallowed` for codepoints
    outside the table. -/
def disposition (cp : Nat) : IdnaDisposition :=
  match lookupRow? cp with
  | some row => row.disposition
  | none     => .Disallowed

/-- Mapping target for `cp` under non-transitional UTS #46
    processing (the recommended mode for new applications):

      * Valid       → singleton `#[cp]`
      * Mapped      → row's mapping sequence
      * Deviation   → singleton `#[cp]` (kept as-is per UTS #46 §5;
                      under non-transitional these match IDNA2008)
      * Ignored     → empty
      * Disallowed  → empty (the caller must reject the input)
-/
def mapNonTransitional (cp : Nat) : Array Nat :=
  match lookupRow? cp with
  | none     => #[]
  | some row =>
    match row.disposition with
    | .Valid      => #[cp]
    | .Mapped     => row.mapping
    | .Deviation  => #[cp]
    | .Ignored    => #[]
    | .Disallowed => #[]

/-- Mapping target for `cp` under transitional UTS #46 processing,
    where Deviation codepoints are mapped (matching IDNA2003
    behaviour). Otherwise identical to the non-transitional mapping. -/
def mapTransitional (cp : Nat) : Array Nat :=
  match lookupRow? cp with
  | none     => #[]
  | some row =>
    match row.disposition with
    | .Valid      => #[cp]
    | .Mapped     => row.mapping
    | .Deviation  => row.mapping
    | .Ignored    => #[]
    | .Disallowed => #[]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 KNOWN-CODEPOINT DISPOSITIONS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Lowercase ASCII letters are valid. -/
theorem disposition_a   : disposition 0x0061 = .Valid := by decide +kernel
theorem disposition_z   : disposition 0x007A = .Valid := by decide +kernel
theorem disposition_d0  : disposition 0x0030 = .Valid := by decide +kernel
theorem disposition_d9  : disposition 0x0039 = .Valid := by decide +kernel

/-- Hyphen-minus and full stop are valid (the latter is the label separator). -/
theorem disposition_hyphen : disposition 0x002D = .Valid := by decide +kernel
theorem disposition_dot    : disposition 0x002E = .Valid := by decide +kernel

/-- Uppercase ASCII letters are mapped to lowercase. -/
theorem disposition_A : disposition 0x0041 = .Mapped := by decide +kernel
theorem disposition_Z : disposition 0x005A = .Mapped := by decide +kernel

theorem mapNT_A : mapNonTransitional 0x0041 = #[0x0061] := by decide +kernel
theorem mapNT_Z : mapNonTransitional 0x005A = #[0x007A] := by decide +kernel

/-- Soft hyphen U+00AD is ignored (dropped from the processed string). -/
theorem disposition_softhyphen : disposition 0x00AD = .Ignored := by decide +kernel
theorem mapNT_softhyphen       : mapNonTransitional 0x00AD = #[] := by decide +kernel

/-- The four Deviation codepoints from UTS #46 §2.3. -/
theorem disposition_sharp_s : disposition 0x00DF = .Deviation := by decide +kernel
theorem disposition_finalσ  : disposition 0x03C2 = .Deviation := by decide +kernel
theorem disposition_zwnj    : disposition 0x200C = .Deviation := by decide +kernel
theorem disposition_zwj     : disposition 0x200D = .Deviation := by decide +kernel

/-- SHARP S is kept as-is non-transitionally; mapped to "ss" transitionally. -/
theorem mapNT_sharp_s : mapNonTransitional 0x00DF = #[0x00DF]         := by decide +kernel
theorem mapTr_sharp_s : mapTransitional   0x00DF = #[0x0073, 0x0073] := by decide +kernel

/-- GREEK SMALL LETTER FINAL SIGMA is kept as-is non-transitionally;
    mapped to σ (U+03C3) transitionally. -/
theorem mapNT_finalσ : mapNonTransitional 0x03C2 = #[0x03C2] := by decide +kernel
theorem mapTr_finalσ : mapTransitional   0x03C2 = #[0x03C3] := by decide +kernel

/-- C1 controls U+0080..U+009F are disallowed. -/
theorem disposition_C1 : disposition 0x0080 = .Disallowed := by decide +kernel

/-- Disallowed codepoints map to the empty sequence (caller must reject). -/
theorem mapNT_C1 : mapNonTransitional 0x0080 = #[] := by decide +kernel

end Unicode.Idna.Disposition
