/-
  Unicode.Conformance.Security.ConfusableBidiCompoundTest

  Conformance for the ConfusableBidiCompound detector: it flags a compound spoofing
  hazard when a confusable codepoint co-occurs with a bidi override or isolate —
  stronger than either signal alone.

  Each theorem checks the verdict on a documented case: a lone Cyrillic 'а' stays
  clear (the plain homoglyph detector covers it), while the same confusable under an
  RLO override or an LRI isolate fires the compound.
-/

import Unicode.Security.Boundary.ConfusableBidiCompound

namespace Unicode.Conformance.Security.ConfusableBidiCompoundTest

open Unicode.Security.Boundary.ConfusableBidiCompound

/-- A lone Cyrillic 'а' (U+0430) with no bidi control is not a compound — clear. -/
theorem cyrillic_a_alone_clear :
    (detect [0x0430]).classify.isClear = true := by decide

/-- RLO override + Cyrillic 'а' — a Trojan-Source / IDN-homograph compound. -/
theorem rlo_cyrillic_compound :
    (detect [0x202E, 0x0430]).classify.tag = some "ConfusableInOverride" := by decide

/-- LRI isolate + Greek 'ο' — confusable inside a bidi isolate. -/
theorem lri_greek_compound :
    (detect [0x2066, 0x03BF]).classify.tag = some "ConfusableInIsolate" := by decide

end Unicode.Conformance.Security.ConfusableBidiCompoundTest
