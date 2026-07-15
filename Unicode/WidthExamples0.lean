import Unicode.Width

namespace Unicode.Width

set_option maxRecDepth 100000

/-- ASCII letters are width 1. -/
theorem width_ascii_a_narrow : codepointWidth .narrow 0x0061 = 1 := by decide +kernel
theorem width_ascii_a_wide   : codepointWidth .wide   0x0061 = 1 := by decide +kernel

/-- ASCII digits are width 1. -/
theorem width_ascii_0 : codepointWidth .narrow 0x0030 = 1 := by decide +kernel

/-- ASCII space is width 1 (general category Zs, EAW = N). -/
theorem width_ascii_space : codepointWidth .narrow 0x0020 = 1 := by decide +kernel

/-- ASCII NUL is width 0 (control). -/
theorem width_ascii_nul : codepointWidth .narrow 0x0000 = 0 := by decide +kernel

/-- ASCII DEL is width 0 (control). -/
theorem width_ascii_del : codepointWidth .narrow 0x007F = 0 := by decide +kernel

/-- C1 control U+0080 is width 0. -/
theorem width_c1_80 : codepointWidth .narrow 0x0080 = 0 := by decide +kernel

/-- COMBINING ACUTE ACCENT (U+0301) is width 0. -/
theorem width_combining_acute : codepointWidth .narrow 0x0301 = 0 := by decide +kernel

/-- COMBINING DIAERESIS (U+0308) is width 0. -/
theorem width_combining_diaeresis : codepointWidth .narrow 0x0308 = 0 := by decide +kernel

/-- ENCLOSING CIRCLE (U+20DD) is width 0 (Me). -/
theorem width_enclosing_circle : codepointWidth .narrow 0x20DD = 0 := by decide +kernel

/-- ZERO WIDTH JOINER is width 0. -/
theorem width_zwj : codepointWidth .narrow 0x200D = 0 := by decide +kernel

/-- ZERO WIDTH NON-JOINER is width 0. -/
theorem width_zwnj : codepointWidth .narrow 0x200C = 0 := by decide +kernel

end Unicode.Width
