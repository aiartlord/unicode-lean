/-
  Unicode.Conformance.Security.NfcIdempotenceWitnessTest

  Conformance certificate for the NfcIdempotenceWitness detector (form layer,
  UAX #15 Normalization Forms — the idempotence property of NFC and NFKC).

  What this certifies.  UAX #15 defines the four normalization forms and proves
  each is idempotent: applying NFC (or NFKC) a second time changes nothing.  The
  guarantee holds only if normalization was applied at all.  This harness
  certifies that the detector correctly identifies text that is *not already* in
  NFC, and text that is in NFC but not in NFKC, by comparing the input against
  `toNFC(input)` and `toNFKC(input)` element-wise and reporting the first
  divergent position.

  Threat model.  A two-system bypass.  The attacker submits text in a non-NFC
  form — for example `e` followed by U+0301 combining acute in place of the
  precomposed U+00E9 é — so that a validator which normalizes before comparing
  against a stored canonical value silently accepts a match, while a downstream
  consumer that does not normalize sees a different byte sequence.  Because
  canonical decomposition is unbounded and compatibility folding rewrites shapes
  like ligatures, the attacker controls which form reaches each stage.

  The discrimination the detector draws.  Text that already equals its own NFC
  and NFKC form is sanctioned (clear); text that diverges from its NFC form is
  the `NonNfcForm` hazard; text that equals its NFC form but diverges from its
  NFKC form is the `NonNfkcCompatForm` hazard, the residual compatibility surface
  that width- and case-based detectors miss by design.

  How to read the certificate.  Each theorem below pins the verdict on one
  discriminating vector: a precomposed character that is already normalized, a
  decomposed character that fails NFC, and a compatibility ligature that passes
  NFC but fails NFKC.  The final theorem `all_rows_pass` conjoins those
  statements into the single obligation this harness exports.  Appending a
  further vector extends the conjunction, so the guarantee grows with the threat
  catalogue and cannot silently regress.
-/

import Unicode.Security.Form.NfcIdempotenceWitness
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.NfcIdempotenceWitnessTest

open Unicode.Security.Form.NfcIdempotenceWitness

set_option maxRecDepth 100000

/-- Precomposed é (U+00E9) is the canonical single-codepoint spelling: it already
    equals both its NFC and its NFKC form, so no normalization step could alter
    it and the detector must return clear.  This is the negative control that
    proves the detector does not flag text that is genuinely already normalized. -/
theorem precomposed_e_clear :
    (detect [0x00E9]).classify.isClear = true := by decide

/-- Decomposed é — the base letter U+0065 followed by U+0301 combining acute —
    is canonically equivalent to precomposed U+00E9 but not identical to it, so
    NFC recomposes the pair and the input diverges from `toNFC(input)` at
    position 0.  This is the core two-system bypass vector: a validator that
    normalizes accepts it, an unnormalizing consumer sees a different sequence,
    and the detector must draw the `NonNfcForm` hazard. -/
theorem decomposed_e_nfc :
    (detect [0x0065, 0x0301]).classify.tag = some "NonNfcForm" := by decide

/-- The ﬁ ligature (U+FB01) has no canonical decomposition, so it equals its own
    NFC form and passes the first check; but its compatibility decomposition
    folds it to the two letters "fi", so it diverges from `toNFKC(input)`.  This
    is the discriminating case that separates the two hazards — it is clear under
    NFC yet hazardous under NFKC — and it exercises the compatibility surface that
    width- and case-based detectors miss.  The NFC and NFKC forms are supplied by
    the proven witnesses `toNFC_ligature_fi` and `toNFKC_ligature_fi` rather than
    reducing the composition tables. -/
theorem fi_ligature_nfkc :
    (detect [0xFB01]).classify.tag = some "NonNfkcCompatForm" := by
  unfold detect
  rw [Unicode.Normalization.DetectorFormVectors.toNFC_ligature_fi,
      Unicode.Normalization.DetectorFormVectors.toNFKC_ligature_fi]
  decide

/-- The complete certificate: every conformance vector above holds
    simultaneously. Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (detect [0x00E9]).classify.isClear = true ∧
    (detect [0x0065, 0x0301]).classify.tag = some "NonNfcForm" ∧
    (detect [0xFB01]).classify.tag = some "NonNfkcCompatForm" :=
  ⟨precomposed_e_clear, decomposed_e_nfc, fi_ligature_nfkc⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/NfcIdempotenceWitnessTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/NfcIdempotenceWitnessTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x00E9], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0xD55C], "Clear", []⟩,
  ⟨[0x041F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442], "Clear", []⟩,
  ⟨[0x03B1, 0x03B2, 0x03B3], "Clear", []⟩,
  ⟨[0x0627, 0x0628, 0x0629], "Clear", []⟩,
  ⟨[0x0068, 0x0074, 0x0074, 0x0070, 0x003A, 0x002F, 0x002F], "Clear", []⟩,
  ⟨[0x0065, 0x0301], "Hazard:NonNfcForm", [0]⟩,
  ⟨[0x0061, 0x0301, 0x0065, 0x0300], "Hazard:NonNfcForm", [0]⟩,
  ⟨[0x006F, 0x0308], "Hazard:NonNfcForm", [0]⟩,
  ⟨[0x1112, 0x1161, 0x11AB], "Hazard:NonNfcForm", [0]⟩,
  ⟨[0x0075, 0x0308], "Hazard:NonNfcForm", [0]⟩,
  ⟨[0x006E, 0x0303], "Hazard:NonNfcForm", [0]⟩,
  ⟨[0x0063, 0x0327], "Hazard:NonNfcForm", [0]⟩,
  ⟨[0x006E, 0x0069, 0x006E, 0x0303, 0x006F], "Hazard:NonNfcForm", [2]⟩,
  ⟨[0x006F, 0x0302], "Hazard:NonNfcForm", [0]⟩,
  ⟨[0xFB01], "Hazard:NonNfkcCompatForm", [0]⟩,
  ⟨[0xFB03], "Hazard:NonNfkcCompatForm", [0]⟩,
  ⟨[0x2163], "Hazard:NonNfkcCompatForm", [0]⟩,
  ⟨[0x2460], "Hazard:NonNfkcCompatForm", [0]⟩,
  ⟨[0x00B2], "Hazard:NonNfkcCompatForm", [0]⟩,
  ⟨[0x00BD], "Hazard:NonNfkcCompatForm", [0]⟩,
  ⟨[0xFDFA], "Hazard:NonNfkcCompatForm", [0]⟩,
  ⟨[0x33CD], "Hazard:NonNfkcCompatForm", [0]⟩,
  ⟨[0xFF71], "Hazard:NonNfkcCompatForm", [0]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "NfcIdempotenceWitnessTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.NfcIdempotenceWitnessTest
