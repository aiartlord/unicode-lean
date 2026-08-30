/-
  Unicode.Conformance.Security.IdentifierFormDriftTest

  Conformance certificate for the IdentifierFormDrift detector (boundary layer:
  the disagreement between an identifier validator and a form normaliser).

  Threat model.  UTS #39 assigns every codepoint an Identifier_Status of
  Allowed or Restricted, and UAX #15 defines the compatibility decomposition
  NFKD.  An adversary crafts an identifier out of Restricted compatibility
  characters — Mathematical Italic letters, fullwidth Latin, ligatures, Roman
  numerals — whose NFKD heads are ordinary Allowed characters.  A gateway that
  screens the raw text rejects the identifier, but a gateway that normalises
  first and then screens accepts it; the attacker steers the input to whichever
  order lets a spoofed identifier through.  The hazard is not any single form of
  the input but the transition between forms, which every single-form detector
  misses by construction.

  What the detector draws.  For each input codepoint it compares the
  Identifier_Status of the codepoint against the Identifier_Status of the first
  codepoint of its NFKD form.  A character with identity decomposition, or one
  whose status is unchanged across decomposition, is sanctioned and passes
  clear; a character whose verdict flips under normalisation is a hazard tagged
  `IdentifierStatusShift`, carrying the offending position for downstream policy.

  How to read the certificate.  Each `Row` pairs a representative input with the
  classification `tag` its verdict must carry, where `none` records a clear
  verdict (`isClear` holds exactly when the tag is absent, so the tag alone
  captures both outcomes).  `verifyRow` recomputes `detect` and compares the
  projected tag against the row; `all_rows_pass` discharges the whole table at
  once.  Appending a vector enlarges the proof obligation, so coverage grows
  with the threat catalogue and cannot silently regress.
-/

import Unicode.Security.Boundary.IdentifierFormDrift
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.IdentifierFormDriftTest

open Unicode.Security.Boundary.IdentifierFormDrift

set_option maxRecDepth 100000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence and the classification `tag` its
    verdict must carry (`none` for a clear verdict, since `isClear` holds exactly
    when no tag is present). -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative hazard — and clear — vectors this harness certifies. -/
def rows : List Row :=
  [ -- Greek lowercase α: Allowed with an identity NFKD, so no status can shift —
    -- the sanctioned baseline that must not be flagged.
    { input := [0x03B1], tag := none },
    -- Mathematical Italic Small A: Restricted, but its NFKD head U+0061 'a' is
    -- Allowed — the canonical accept-after-normalise bypass the detector exists
    -- to catch.
    { input := [0x1D44E], tag := some "IdentifierStatusShift" },
    -- Fullwidth Capital A: a compatibility form that is Restricted, while its
    -- NFKD head U+0041 'A' is Allowed — a second decomposition family exhibiting
    -- the same status flip, guarding against a decomposition-specific fix.
    { input := [0xFF21], tag := some "IdentifierStatusShift" } ]

/-- A row passes when `detect` reproduces the classification tag the row
    prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the identifier-status verdict UTS #39
    and NFKD together demand. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/IdentifierFormDriftTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/IdentifierFormDriftTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x0061, 0x0064, 0x006D, 0x0069, 0x006E], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x03B1, 0x03B2, 0x03B3], "Clear", []⟩,
  ⟨[0x041F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442], "Clear", []⟩,
  ⟨[0x0641, 0x0644, 0x062F], "Clear", []⟩,
  ⟨[0x3042, 0x3044, 0x3046], "Clear", []⟩,
  ⟨[0x0066, 0x006F, 0x006F, 0x005F, 0x0062, 0x0061, 0x0072], "Clear", []⟩,
  ⟨[0x1D44E], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0x1D44E, 0x1D451, 0x1D45A, 0x1D456, 0x1D45B], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0xFF21], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0x24B6], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0xFB01], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0x2163], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0x0061, 0x0062, 0x0063, 0x1D44E], "Hazard:IdentifierStatusShift", [3]⟩,
  ⟨[0xD55C], "Clear", []⟩,
  ⟨[0x1D400], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0x1D5BA], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0x1D504], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0x216D], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0x2460], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0xFF50, 0xFF41, 0xFF53, 0xFF53], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0xFF10, 0xFF11, 0xFF12, 0xFF13], "Hazard:IdentifierStatusShift", [0]⟩,
  ⟨[0x0075, 0x0073, 0x0065, 0x0072, 0xFF11], "Hazard:IdentifierStatusShift", [4]⟩,
  ⟨[0x1D45D, 0x1D44E, 0x1D460, 0x1D460, 0x1D464, 0x1D45C, 0x1D45F, 0x1D451], "Hazard:IdentifierStatusShift", [0]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "IdentifierFormDriftTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

-- The vector rows reach deeper than the curated set, so the obligation needs
-- the detector module's own recursion budget.
set_option maxRecDepth 1000000 in
/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.IdentifierFormDriftTest
