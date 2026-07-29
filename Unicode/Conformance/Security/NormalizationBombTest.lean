/-
  Unicode.Conformance.Security.NormalizationBombTest

  Conformance for the NormalizationBomb detector: it reports a hazard when the input
  expands explosively under normalization — a decompression-bomb / DoS hazard — by a
  fixed priority (per-codepoint blow-up, then NFKD ratio, then NFD ratio).

  Each theorem checks the verdict on a documented case: precomposed Hangul and a
  circled digit stay within bound, while the Arabic ligature U+FDFA decomposes to 18
  codepoints and fires the single-codepoint blow-up.
-/

import Unicode.Security.Form.NormalizationBomb

namespace Unicode.Conformance.Security.NormalizationBombTest

open Unicode.Security.Form.NormalizationBomb

set_option maxRecDepth 100000

/-- Precomposed Hangul 한 (U+D55C) decomposes to 3 jamos, within the per-codepoint
    bound of 4 — clear. -/
theorem korean_within_bound :
    (detect [0xD55C]).classify.isClear = true := by decide

/-- The Arabic ligature U+FDFA decomposes to 18 codepoints under NFKD — a single-
    codepoint blow-up. -/
theorem arabic_ligature_blowup :
    (detect [0xFDFA]).classify.tag = some "SingleCpBlowup" := by decide

/-- Circled digit one (U+2460) has a compatibility decomposition of length 1, so it
    triggers no blow-up — clear. -/
theorem circled_one_clear :
    (detect [0x2460]).classify.isClear = true := by decide

end Unicode.Conformance.Security.NormalizationBombTest
