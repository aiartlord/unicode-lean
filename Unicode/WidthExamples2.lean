import Unicode.Width

namespace Unicode.Width

set_option maxRecDepth 100000

/-- "hello" is width 5. -/
theorem dw_hello :
    displayWidth .narrow #[0x68, 0x65, 0x6C, 0x6C, 0x6F] = 5 := by decide +kernel

/-- The empty array is width 0. -/
theorem dw_empty : displayWidth .narrow #[] = 0 := by decide +kernel

/-- "cafe" with COMBINING ACUTE ACCENT renders as 4 columns. -/
theorem dw_cafe_decomposed :
    displayWidth .narrow #[0x63, 0x61, 0x66, 0x65, 0x0301] = 4 := by decide +kernel

/-- "cafe" with precomposed U+00E9 also renders as 4 columns. -/
theorem dw_cafe_precomposed :
    displayWidth .narrow #[0x63, 0x61, 0x66, 0x00E9] = 4 := by decide +kernel

/-- Two CJK ideographs render as 4 columns. -/
theorem dw_nihao :
    displayWidth .narrow #[0x4F60, 0x597D] = 4 := by decide +kernel

/-- A control-only string is width 0. -/
theorem dw_controls :
    displayWidth .narrow #[0x0000, 0x0001, 0x0009, 0x000A] = 0 := by decide +kernel

/-- Mixed ASCII + CJK: h, i, space, and two wide ideographs. -/
theorem dw_mixed :
    displayWidth .narrow #[0x68, 0x69, 0x20, 0x4F60, 0x597D] = 7 := by decide +kernel

end Unicode.Width
