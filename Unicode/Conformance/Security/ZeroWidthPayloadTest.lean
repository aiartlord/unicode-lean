/-
  Unicode.Conformance.Security.ZeroWidthPayloadTest

  Conformance for the ZeroWidthPayload detector (covert payloads in zero-width /
  no-glyph codepoints).

  Each theorem checks the full verdict — sub-threat tag together with the per-class
  counts and suspicious positions — on a representative vector: a binary payload, a
  word-joiner injection, an AI-watermark NNBSP burst, an annotation misuse, and a
  sanctioned RGI emoji-ZWJ sequence.
-/

import Unicode.Security.Covert.ZeroWidthPayload

namespace Unicode.Conformance.Security.ZeroWidthPayloadTest

open Unicode.Security.Covert.ZeroWidthPayload

/-- Binary-alphabet payload: two ZWSPs spliced into Latin text — `BinaryPayload`,
    two ZWSPs counted, suspicious at their positions. -/
theorem binary_payload_verdict :
    let v := detect [0x48, 0x200B, 0x69, 0x200B, 0x69]
    v.classify.tag = some "BinaryPayload"
      ∧ v.zwspCount = 2 ∧ v.classify.positions = [1, 3] := by decide

/-- WORD JOINER injected into Latin text — `WordJoinerInjection`, one WJ, position 1. -/
theorem word_joiner_verdict :
    let v := detect [0x48, 0x2060, 0x69]
    v.classify.tag = some "WordJoinerInjection"
      ∧ v.wordJoinerCount = 1 ∧ v.classify.positions = [1] := by decide

/-- Two NNBSPs — suspected AI-watermark burst; count reflects both occurrences. -/
theorem nnbsp_watermark_verdict :
    let v := detect [0x48, 0x202F, 0x69, 0x202F, 0x6F]
    v.classify.tag = some "AIWatermarkNNBSP"
      ∧ v.nnbspCount = 2 ∧ v.classify.positions = [1, 3] := by decide

/-- Annotation ANCHOR with no SEPARATOR/TERMINATOR — structural misuse. -/
theorem annotation_misuse_verdict :
    let v := detect [0x48, 0xFFF9, 0x69]
    v.classify.tag = some "AnnotationMisuse" ∧ v.annotationCount = 1 := by decide

/-- Sanctioned RGI emoji-ZWJ sequence 👨‍💻 is clear even though a zero-width is
    present: the ZWJ is flanked by emoji, so no suspicious position remains. -/
theorem emoji_zwj_clear_verdict :
    let v := detect [0x1F468, 0x200D, 0x1F4BB]
    v.classify.isClear = true
      ∧ v.suspiciousPositions = [] ∧ v.totalZeroWidth = 1 := by decide

end Unicode.Conformance.Security.ZeroWidthPayloadTest
