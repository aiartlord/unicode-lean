import Unicode.Width

namespace Unicode.Width

set_option maxRecDepth 100000

/-- VARIATION SELECTOR-15 (text presentation) is width 0. -/
theorem width_vs15 : codepointWidth .narrow 0xFE0E = 0 := by decide +kernel

/-- VARIATION SELECTOR-16 (emoji presentation) is width 0. -/
theorem width_vs16 : codepointWidth .narrow 0xFE0F = 0 := by decide +kernel

/-- CJK ideograph U+4E00 is width 2 (EAW = W). -/
theorem width_cjk_yi : codepointWidth .narrow 0x4E00 = 2 := by decide +kernel

/-- HIRAGANA SMALL A (U+3041) is width 2 (EAW = W). -/
theorem width_hiragana_a : codepointWidth .narrow 0x3041 = 2 := by decide +kernel

/-- FULLWIDTH LATIN A (U+FF21) is width 2 (EAW = F). -/
theorem width_fullwidth_A : codepointWidth .narrow 0xFF21 = 2 := by decide +kernel

/-- HALFWIDTH KATAKANA A (U+FF71) is width 1 (EAW = H). -/
theorem width_halfwidth_a : codepointWidth .narrow 0xFF71 = 1 := by decide +kernel

/-- INVERTED EXCLAMATION MARK (U+00A1, EAW = A) is width 1 under
    narrow, width 2 under wide. -/
theorem width_inverted_excl_narrow : codepointWidth .narrow 0x00A1 = 1 := by decide +kernel
theorem width_inverted_excl_wide   : codepointWidth .wide   0x00A1 = 2 := by decide +kernel

/-- WAVING HAND SIGN (U+1F44B, EAW = W) is width 2. -/
theorem width_emoji_wave : codepointWidth .narrow 0x1F44B = 2 := by decide +kernel

end Unicode.Width
