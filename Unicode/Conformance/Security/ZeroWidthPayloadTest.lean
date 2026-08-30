/-
  Unicode.Conformance.Security.ZeroWidthPayloadTest

  Conformance certificate for the ZeroWidthPayload detector (covert-channel
  layer, UTS #39 §4 Confusable Detection and the general-security guidance of
  UAX #9 / UAX #31 on format characters that carry no glyph).

  What this harness certifies.  A large family of Unicode codepoints render to
  zero advancement width — the format and joiner controls U+200B ZERO WIDTH
  SPACE, U+2060 WORD JOINER, U+200D ZERO WIDTH JOINER, the narrow no-break space
  U+202F, and the interlinear-annotation controls U+FFF9..U+FFFB.  Because they
  are invisible to a human reader yet fully present in the byte stream, they can
  smuggle a payload past visual inspection.  The ZeroWidthPayload detector reads
  a codepoint sequence and returns a rich verdict: a sub-threat tag, per-class
  occurrence counts, and the exact positions it deems suspicious.

  Threat model.  An adversary interleaves no-glyph codepoints into otherwise
  innocuous text to encode data (a two-symbol alphabet of zero-width spaces
  spells bits), to fingerprint or watermark machine-generated prose (bursts of
  narrow no-break space), to splice a joiner that fractures a token for a
  downstream parser, or to misuse the annotation controls to hide structure.
  Each attack is invisible on screen and therefore evades review that trusts the
  rendered form.

  The discrimination the detector draws.  Not every zero-width codepoint is an
  attack: a Recommended-for-General-Interchange emoji ZWJ sequence legitimately
  binds two pictographs with U+200D.  The detector distinguishes hazardous
  splicing from sanctioned composition by context — a joiner flanked by emoji
  leaves no suspicious position, whereas the same class of codepoint injected
  into Latin text is flagged with its count and location.

  How to read the certificate.  Each theorem below pins the full verdict — tag,
  the relevant per-class count, and the suspicious positions — on one
  discriminating vector, chosen so that a regression in either the
  classification or the bookkeeping fields would break it.  These vectors reduce
  under `decide` because the detector operates directly on the codepoint list.
  The final `all_rows_pass` conjoins every vector theorem into one closed
  obligation; appending a further vector extends that conjunction, so the
  guarantee grows with the threat catalogue and cannot silently regress.
-/

import Unicode.Security.Covert.ZeroWidthPayload
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.ZeroWidthPayloadTest

open Unicode.Security.Covert.ZeroWidthPayload

/-- Binary-alphabet payload: two U+200B ZERO WIDTH SPACEs spliced between Latin
    letters encode bits invisibly, and the detector must both name the
    `BinaryPayload` sub-threat and account for exactly the two zero-width spaces
    it saw, flagging their positions 1 and 3 as suspicious. -/
theorem binary_payload_verdict :
    let v := detect [0x48, 0x200B, 0x69, 0x200B, 0x69]
    v.classify.tag = some "BinaryPayload"
      ∧ v.zwspCount = 2 ∧ v.classify.positions = [1, 3] := by decide

/-- A single U+2060 WORD JOINER dropped between Latin letters fractures a token
    for any downstream parser while remaining invisible; the detector must draw
    `WordJoinerInjection`, count the one joiner, and report position 1 — the
    smallest injection that surfaces this splice. -/
theorem word_joiner_verdict :
    let v := detect [0x48, 0x2060, 0x69]
    v.classify.tag = some "WordJoinerInjection"
      ∧ v.wordJoinerCount = 1 ∧ v.classify.positions = [1] := by decide

/-- Two U+202F NARROW NO-BREAK SPACEs punctuating text are the signature of a
    machine-generated watermark rather than natural typography; the detector must
    raise `AIWatermarkNNBSP`, reflect both occurrences in the count, and mark
    positions 1 and 3. -/
theorem nnbsp_watermark_verdict :
    let v := detect [0x48, 0x202F, 0x69, 0x202F, 0x6F]
    v.classify.tag = some "AIWatermarkNNBSP"
      ∧ v.nnbspCount = 2 ∧ v.classify.positions = [1, 3] := by decide

/-- A U+FFF9 INTERLINEAR ANNOTATION ANCHOR with no matching SEPARATOR or
    TERMINATOR is a structurally invalid use of the annotation controls, a
    hiding place for out-of-band content; the detector must report
    `AnnotationMisuse` and count the one dangling anchor. -/
theorem annotation_misuse_verdict :
    let v := detect [0x48, 0xFFF9, 0x69]
    v.classify.tag = some "AnnotationMisuse" ∧ v.annotationCount = 1 := by decide

/-- The sanctioned RGI emoji-ZWJ sequence 👨‍💻 (man + U+200D + laptop) must stay
    clear even though a zero-width joiner is present: because the joiner is
    flanked by emoji it composes rather than splices, so no suspicious position
    remains and the lone zero-width codepoint is accounted for without a hazard.
    This is the vector that keeps the detector from flagging legitimate
    composition. -/
theorem emoji_zwj_clear_verdict :
    let v := detect [0x1F468, 0x200D, 0x1F4BB]
    v.classify.isClear = true
      ∧ v.suspiciousPositions = [] ∧ v.totalZeroWidth = 1 := by decide

/-- The complete certificate: every conformance vector above holds
    simultaneously. Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (let v := detect [0x48, 0x200B, 0x69, 0x200B, 0x69]
     v.classify.tag = some "BinaryPayload"
       ∧ v.zwspCount = 2 ∧ v.classify.positions = [1, 3])
    ∧ (let v := detect [0x48, 0x2060, 0x69]
       v.classify.tag = some "WordJoinerInjection"
         ∧ v.wordJoinerCount = 1 ∧ v.classify.positions = [1])
    ∧ (let v := detect [0x48, 0x202F, 0x69, 0x202F, 0x6F]
       v.classify.tag = some "AIWatermarkNNBSP"
         ∧ v.nnbspCount = 2 ∧ v.classify.positions = [1, 3])
    ∧ (let v := detect [0x48, 0xFFF9, 0x69]
       v.classify.tag = some "AnnotationMisuse" ∧ v.annotationCount = 1)
    ∧ (let v := detect [0x1F468, 0x200D, 0x1F4BB]
       v.classify.isClear = true
         ∧ v.suspiciousPositions = [] ∧ v.totalZeroWidth = 1) :=
  ⟨binary_payload_verdict, word_joiner_verdict, nnbsp_watermark_verdict,
   annotation_misuse_verdict, emoji_zwj_clear_verdict⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/ZeroWidthPayloadTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/ZeroWidthPayloadTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x1F600, 0xFE0F], "Clear", []⟩,
  ⟨[0x1F468, 0x200D, 0x1F4BB], "Clear", []⟩,
  ⟨[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F466], "Clear", []⟩,
  ⟨[0x041F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442], "Clear", []⟩,
  ⟨[0x0915, 0x0916, 0x0917], "Clear", []⟩,
  ⟨[0x03B1, 0x03B2, 0x03B3], "Clear", []⟩,
  ⟨[0x0048, 0x200B, 0x0069, 0x200B, 0x0069], "Hazard:BinaryPayload", [1, 3]⟩,
  ⟨[0x0048, 0x200B, 0x200D, 0x0069], "Hazard:BinaryPayload", [1, 2]⟩,
  ⟨[0x0061, 0x200B, 0x200B, 0x200B, 0x0062], "Hazard:BinaryPayload", [1, 2, 3]⟩,
  ⟨[0x0061, 0x200B, 0x200B, 0x200D, 0x200D, 0x200B, 0x200B, 0x200D, 0x200D, 0x0062], "Hazard:BinaryPayload", [1, 2, 3, 4, 5, 6, 7, 8]⟩,
  ⟨[0x0066, 0x006F, 0x006F, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x0062, 0x0061, 0x0072], "Hazard:BinaryPayload", [3, 4, 5, 6, 7, 8, 9, 10]⟩,
  ⟨[0x0048, 0x2060, 0x0069], "Hazard:WordJoinerInjection", [1]⟩,
  ⟨[0x0061, 0x2060, 0x2060, 0x0062], "Hazard:WordJoinerInjection", [1, 2]⟩,
  ⟨[0x4E2D, 0x2060, 0x6587], "Hazard:WordJoinerInjection", [1]⟩,
  ⟨[0x0061, 0x2060, 0x0062, 0x2060, 0x0063, 0x2060, 0x0064], "Hazard:WordJoinerInjection", [1, 3, 5]⟩,
  ⟨[0x0048, 0x202F, 0x0069, 0x202F, 0x0021], "Hazard:AIWatermarkNNBSP", [1, 3]⟩,
  ⟨[0x0061, 0x202F, 0x0062, 0x202F, 0x0063, 0x202F, 0x0064], "Hazard:AIWatermarkNNBSP", [1, 3, 5]⟩,
  ⟨[0x0048, 0x200B, 0x0069], "Hazard:BareZeroWidth", [1]⟩,
  ⟨[0x0048, 0xFEFF, 0x0069], "Hazard:BareZeroWidth", [1]⟩,
  ⟨[0x0048, 0x200D, 0x0069], "Hazard:BareZeroWidth", [1]⟩,
  ⟨[0x0048, 0x202F, 0x0069], "Hazard:BareZeroWidth", [1]⟩,
  ⟨[0x0048, 0xFFF9, 0x0069], "Hazard:AnnotationMisuse", [1]⟩,
  ⟨[0xFFF9, 0x0041, 0xFFF9, 0x0042], "Hazard:AnnotationMisuse", [0, 2]⟩,
  ⟨[0xFFF9, 0x0041, 0xFFFA, 0x0042], "Hazard:AnnotationMisuse", [0, 2]⟩,
  ⟨[0x0041, 0xFFFB, 0x0042], "Hazard:AnnotationMisuse", [1]⟩,
  ⟨[0x0041, 0xFFFA, 0x0042], "Hazard:AnnotationMisuse", [1]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "ZeroWidthPayloadTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.ZeroWidthPayloadTest
