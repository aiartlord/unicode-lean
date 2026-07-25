/-
  Unicode.Security.Crypto.Bip39CanonicalVectorsDetect

  Spot-check conformance vectors for `detect` (BIP-39 canonicalisation hazard
  detection). Split out of `Bip39Canonical` so the pipeline reductions do not
  accumulate in one compilation unit.
-/

import Unicode.Security.Crypto.Bip39Canonical

namespace Unicode.Security.Crypto.Bip39Canonical

set_option maxRecDepth 100000

/-- Trailing single space fires `trailingWhitespace`. -/
theorem detect_trailing_space :
    let input : List Nat :=
      [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20]
    (detect input).classify.tag = some "TrailingWhitespace" := by decide +kernel

/-- Title-case "Abandon" fires `mixedCase`. -/
theorem detect_mixed_case :
    let input : List Nat := [0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
    (detect input).classify.tag = some "MixedCase" := by decide +kernel

/-- Double-space between words fires `whitespaceAnomaly`. -/
theorem detect_double_space :
    let input : List Nat :=
      [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20, 0x20,
        0x61, 0x62, 0x6F, 0x75, 0x74]
    (detect input).classify.tag = some "WhitespaceAnomaly" := by decide +kernel

/-- Leading space fires `whitespaceAnomaly`. -/
theorem detect_leading_space :
    let input : List Nat := [0x20, 0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
    (detect input).classify.tag = some "WhitespaceAnomaly" := by decide +kernel

/-- Compatibility ligature U+FB00 ("ﬀ") decomposes under NFKD; fires `nonNFKD`. -/
theorem detect_non_nfkd_ligature :
    let input : List Nat := [0xFB00]
    (detect input).classify.tag = some "NonNFKD" := by decide +kernel

/-- No-break space U+00A0 decomposes under NFKD to U+0020; fires `nonNFKD`. -/
theorem detect_non_nfkd_nbsp :
    let input : List Nat := [0x61, 0x00A0, 0x62]
    (detect input).classify.tag = some "NonNFKD" := by decide +kernel

/-- Position is reported correctly: trailing space at index 7. -/
theorem detect_trailing_space_position :
    let input : List Nat :=
      [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20]
    (detect input).classify.positions = [7] := by decide +kernel

/-- Position is reported correctly: uppercase A at index 0. -/
theorem detect_mixed_case_position :
    let input : List Nat := [0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
    (detect input).classify.positions = [0] := by decide +kernel

/-- Empty input is clear: vacuously canonical, with `uniqueLanguage`
    defaulting to English on the empty word set. -/
theorem detect_empty_clear :
    (detect []).classify.isClear = true := by decide +kernel

end Unicode.Security.Crypto.Bip39Canonical
