/-
  Unicode.Conformance.Security.HomoglyphConfusableTest

  Conformance for the HomoglyphConfusable detector (UTS-39 confusable-skeleton
  homoglyph spoofing — target-name matches, mathematical-alphanumeric look-alikes,
  cross-script mixes, and low restriction level).

  Each theorem checks the detector's verdict on a representative vector — a
  mathematical-alphanumeric look-alike and a single-script clear — with the confusable
  skeleton and restriction level reduced in the kernel.
-/

import Unicode.Security.Identity.HomoglyphConfusable

namespace Unicode.Conformance.Security.HomoglyphConfusableTest

open Unicode.Security.Identity.HomoglyphConfusable

set_option maxRecDepth 100000
set_option maxHeartbeats 8000000

/-- Mathematical Bold Capital A (U+1D400) is a math-alphanumeric homoglyph of ASCII
    'A' — flagged as a MathAlpha confusable. -/
theorem math_alpha_verdict :
    (detect [0x1D400]).classify.tag = some "MathAlpha" := by decide +kernel

/-- Plain ASCII "Hello" is a single-script Latin identifier — clear. -/
theorem ascii_clear_verdict :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by decide +kernel

end Unicode.Conformance.Security.HomoglyphConfusableTest
