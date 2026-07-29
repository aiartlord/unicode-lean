/-
  Unicode.Conformance.NormalizationTest

  UAX #15 normalization conformance.

  §1 states the UAX #15 §5 stability and cross-form identities — NFC/NFD idempotence
  and `NFD ∘ NFC = NFD` — as properties holding for every input, discharged by the
  algorithm-correctness proofs in `Unicode.Normalization`. §2 pins representative
  entries of the canonical and compatibility mappings, checking that `toNFC`/`toNFD`/
  `toNFKC`/`toNFKD` reproduce the codepoint sequences Unicode publishes for those
  cases.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.NFKC
import Unicode.Normalization.NFKD
import Unicode.Normalization.NFD
import Unicode.Normalization.ComposeInversion

namespace Unicode.Conformance.NormalizationTest

open Unicode.Normalization

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 UAX #15 §5 stability — all inputs, by theorem
-- ═══════════════════════════════════════════════════════════════════════════════

/-- NFC is idempotent: normalizing an already-NFC string is a no-op (UAX #15 §5). -/
theorem nfc_stable (input : List Nat) :
    NFC.toNFC (NFC.toNFC input) = NFC.toNFC input :=
  ComposeInversion.toNFC_idempotent input

/-- NFD is idempotent: normalizing an already-NFD string is a no-op (UAX #15 §5). -/
theorem nfd_stable (input : List Nat) :
    NFC.toNFD (NFC.toNFD input) = NFC.toNFD input :=
  NFD.toNFD_idempotent input

/-- Cross-form cancellation: NFD ∘ NFC = NFD. Composing first and then decomposing
    yields the same canonical decomposition as decomposing directly — the identity
    that ties column c2 (NFC) to column c3 (NFD) in the conformance format. -/
theorem nfd_of_nfc (input : List Nat) :
    NFC.toNFD (NFC.toNFC input) = NFC.toNFD input :=
  ComposeInversion.toNFD_toNFC_eq_toNFD input

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Representative published columns — our algorithm reproduces Unicode's answers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Canonical composition: decomposed é (U+0065 U+0301) composes to U+00E9. -/
theorem vector_e_acute_compose : NFC.toNFC [0x0065, 0x0301] = [0x00E9] := by decide +kernel

/-- Canonical decomposition: precomposed é (U+00E9) decomposes to U+0065 U+0301. -/
theorem vector_e_acute_decompose : NFC.toNFD [0x00E9] = [0x0065, 0x0301] := by decide +kernel

/-- Hangul algorithmic decomposition: 가 (U+AC00) → U+1100 U+1161. -/
theorem vector_hangul_decompose : NFC.toNFD [0xAC00] = [0x1100, 0x1161] := by decide +kernel

/-- Singleton canonical composition: Å ANGSTROM SIGN (U+212B) → U+00C5. -/
theorem vector_angstrom_compose : NFC.toNFC [0x212B] = [0x00C5] := by decide +kernel

/-- Compatibility decomposition (NFKC): the ﬁ ligature (U+FB01) → "fi". -/
theorem vector_fi_ligature_nfkc : NFKC.toNFKC [0xFB01] = [0x0066, 0x0069] := by decide +kernel

/-- Compatibility decomposition (NFKD): the ﬁ ligature (U+FB01) → "fi". -/
theorem vector_fi_ligature_nfkd : NFKD.toNFKD [0xFB01] = [0x0066, 0x0069] := by decide +kernel

/-- The ﬁ ligature is unchanged under canonical NFC (compatibility only). -/
theorem vector_fi_ligature_nfc : NFC.toNFC [0xFB01] = [0xFB01] := by decide +kernel

end Unicode.Conformance.NormalizationTest
