/-
  Unicode.Conformance.Security.WidthClassConfusionTest

  Conformance for the WidthClassConfusion detector: it reports a hazard when a
  fullwidth or halfwidth compatibility form NFKD-folds to a narrower or wider class —
  a width-confusion hazard.

  Each theorem checks the verdict on a documented case: precomposed Hangul stays
  clear, while fullwidth 'A' and halfwidth katakana 'ｱ' fold to their canonical width.
-/

import Unicode.Security.Form.WidthClassConfusion

namespace Unicode.Conformance.Security.WidthClassConfusionTest

open Unicode.Security.Form.WidthClassConfusion

set_option maxRecDepth 100000

/-- Precomposed Hangul 한 (U+D55C) has no width fold — clear. -/
theorem hangul_clear :
    (detect [0xD55C]).classify.isClear = true := by decide

/-- Fullwidth A (U+FF21) folds to ASCII 'A' — a fullwidth fold. -/
theorem fullwidth_A :
    (detect [0xFF21]).classify.tag = some "FullwidthFold" := by decide

/-- Halfwidth katakana ｱ (U+FF71) folds to fullwidth ア — a halfwidth fold. -/
theorem halfwidth_ka_A :
    (detect [0xFF71]).classify.tag = some "HalfwidthFold" := by decide

end Unicode.Conformance.Security.WidthClassConfusionTest
