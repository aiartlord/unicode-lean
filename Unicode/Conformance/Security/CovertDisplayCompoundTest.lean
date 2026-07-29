/-
  Unicode.Conformance.Security.CovertDisplayCompoundTest

  Conformance for the CovertDisplayCompound detector: it flags a compound covert-
  display hazard when a bidi control co-occurs with a suspicious variation selector or
  a tag-block codepoint — two hiding channels combined.

  Each theorem checks the verdict on a documented case: a lone bidi control stays
  clear (the bidi detector covers it), while an RLO paired with an unregistered VS or
  a tag-block codepoint fires the compound.
-/

import Unicode.Security.Boundary.CovertDisplayCompound

namespace Unicode.Conformance.Security.CovertDisplayCompoundTest

open Unicode.Security.Boundary.CovertDisplayCompound

set_option maxRecDepth 1000000

/-- A lone RLO (U+202E) with no second channel is not a compound — clear. -/
theorem bidi_only_clear :
    (detect [0x202E]).classify.isClear = true := by decide +kernel

/-- RLO + ASCII A + VS1 (unregistered variation on A) — bidi plus unregistered VS. -/
theorem compound_bidi_vs :
    (detect [0x202E, 0x0041, 0xFE00]).classify.tag
      = some "BidiPlusUnregisteredVs" := by decide +kernel

/-- RLO + ASCII A + LANGUAGE TAG (U+E0001) — bidi plus tag block. -/
theorem compound_bidi_tag :
    (detect [0x202E, 0x0041, 0xE0001]).classify.tag
      = some "BidiPlusTagBlock" := by decide +kernel

end Unicode.Conformance.Security.CovertDisplayCompoundTest
