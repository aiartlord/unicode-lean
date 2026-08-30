/-
  Unicode.Conformance.Security.RendererDivergenceTest

  What this harness certifies.  It fixes the verdicts of the RendererDivergence
  detector, which flags the "fingerprint stability" family of UTS #39 (Unicode
  Security Mechanisms) spoofing hazards — content whose glyph shape is not stable
  across the renderer cohort (font, terminal, browser) the Standard documents as
  consistent.  The detector's variance modes each trace to a Standard-documented
  ambiguity: variation-selector presentation (UTS #51 emoji variation sequences),
  combining-mark stacking (UAX #15 canonical ordering with no run bound),
  registered-versus-ad-hoc ZWJ shaping (the RGI set of UTS #51), fullwidth /
  halfwidth display equivalence (UAX #11 East Asian Width), and mixed strong
  directionality (UAX #9 Bidirectional Algorithm).

  Threat model.  An adversary crafts a string that renders as one thing in the
  auditor's engine — a benign or empty glyph — and as something misleading in the
  consumer's engine, defeating any review that trusts a single rendering.  The
  detector's job is to name the variance class before that content is trusted, so
  a divergence is caught at admission rather than after the deceiving glyph has
  been shown to a human.

  The discrimination drawn.  Input that renders identically across the documented
  cohort is `clear`; input carrying one of the variance triggers above is a
  `hazard` tagged with the specific sub-threat and the field counts (variation
  selectors, combining marks, fullwidth codepoints) that justify it.  A fullwidth
  Latin letter is hazardous because it is glyph-equivalent to its ASCII twin under
  East Asian Width folding; plain ASCII is clear because it carries no such
  ambiguity.

  How to read the certificate.  Each theorem below pins the full verdict — the
  sub-threat tag together with the rich count fields — for one discriminating
  vector, so the guarantee is over the verdict record and not merely a boolean.
  `all_rows_pass` conjoins every vector theorem into the single obligation this
  harness exports.  Appending a vector adds a conjunct, so the certificate grows
  with the threat catalogue and coverage cannot silently regress.
-/

import Unicode.Security.Display.RendererDivergence
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.RendererDivergenceTest

open Unicode.Security.Display.RendererDivergence

set_option maxRecDepth 1000000

/-- Fullwidth Latin 'A' (U+FF21) is the discriminating case for East Asian Width
    display equivalence: it is glyph-indistinguishable from ASCII 'A' after a
    fullwidth-to-halfwidth fold, so an auditor reading it as the wide form and a
    consumer reading it as the narrow form see the same text differently.  The
    detector must draw `FullwidthVariance` and count exactly the one fullwidth
    codepoint that carries the ambiguity. -/
theorem fullwidth_variance_verdict :
    let v := detect [0xFF21]
    v.classify.tag = some "FullwidthVariance" ∧ v.fullwidthCount = 1 := by decide +kernel

/-- Plain ASCII "Hello" is the sanctioned baseline: it carries no variation
    selector, no combining mark, and no fullwidth codepoint, so it renders
    identically across the documented cohort.  The detector must return `clear`
    with every variance count at zero — the negative control that proves the
    detector does not raise a hazard on ordinary text. -/
theorem ascii_clear_verdict :
    let v := detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
    v.classify.isClear = true
      ∧ v.vsCount = 0 ∧ v.combiningCount = 0 ∧ v.fullwidthCount = 0 := by decide +kernel

/-- The complete certificate: every conformance vector above holds
    simultaneously. Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (let v := detect [0xFF21]
     v.classify.tag = some "FullwidthVariance" ∧ v.fullwidthCount = 1) ∧
    (let v := detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
     v.classify.isClear = true
       ∧ v.vsCount = 0 ∧ v.combiningCount = 0 ∧ v.fullwidthCount = 0) :=
  ⟨fullwidth_variance_verdict, ascii_clear_verdict⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/RendererDivergenceTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/RendererDivergenceTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x043F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442], "Clear", []⟩,
  ⟨[0x05D0, 0x05D1, 0x05D2], "Clear", []⟩,
  ⟨[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466], "Clear", []⟩,
  ⟨[0x1F600], "Clear", []⟩,
  ⟨[0x03B1, 0x03B2, 0x03B3], "Clear", []⟩,
  ⟨[0x0628, 0x062A, 0x062B], "Clear", []⟩,
  ⟨[0x1F600, 0xFE0F], "Hazard:VariationSelectorVariance", [1]⟩,
  ⟨[0x2764, 0xFE0F], "Hazard:VariationSelectorVariance", [1]⟩,
  ⟨[0x0030, 0xFE00], "Hazard:VariationSelectorVariance", [1]⟩,
  ⟨[0x1F600, 0xFE0E], "Hazard:VariationSelectorVariance", [1]⟩,
  ⟨[0x4E2D, 0xE0100], "Hazard:VariationSelectorVariance", [1]⟩,
  ⟨[0x1F468, 0x200D, 0x1F469], "Hazard:UnregisteredZwjVariance", [1]⟩,
  ⟨[0x1F469, 0x200D, 0x1F469], "Hazard:UnregisteredZwjVariance", [1]⟩,
  ⟨[0x1F600, 0x200D, 0x1F601, 0x200D, 0x1F602], "Hazard:UnregisteredZwjVariance", [1]⟩,
  ⟨[0x0061, 0x0301, 0x0302, 0x0303, 0x0304], "Hazard:CombiningStackOverflow", [0]⟩,
  ⟨[0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0x0305], "Hazard:CombiningStackOverflow", [0]⟩,
  ⟨[0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0x0305, 0x0306], "Hazard:CombiningStackOverflow", [0]⟩,
  ⟨[0x4E2D, 0x0301, 0x0302, 0x0303, 0x0304], "Hazard:CombiningStackOverflow", [0]⟩,
  ⟨[0xFF21], "Hazard:FullwidthVariance", [0]⟩,
  ⟨[0xFF02], "Hazard:FullwidthVariance", [0]⟩,
  ⟨[0xFF10], "Hazard:FullwidthVariance", [0]⟩,
  ⟨[0xFF71], "Hazard:FullwidthVariance", [0]⟩,
  ⟨[0x0041, 0x0042, 0x05D0, 0x05D1], "Hazard:MixedDirectionVariance", []⟩,
  ⟨[0x4E2D, 0x0627], "Hazard:MixedDirectionVariance", []⟩,
  ⟨[0x043F, 0x05D0, 0x05D1], "Hazard:MixedDirectionVariance", []⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "RendererDivergenceTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.RendererDivergenceTest
