import Unicode.Width

namespace Unicode.Width

set_option maxRecDepth 100000

/-- Decomposed a + COMBINING DIAERESIS is one width-1 cluster. -/
theorem dwc_a_diaeresis :
    displayWidthClusters .narrow [0x61, 0x0308] = 1 := by decide +kernel

/-- A family ZWJ sequence is one width-2 cluster, not 6. -/
theorem dwc_family_zwj :
    displayWidthClusters .narrow
      [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467] = 2 := by decide +kernel

/-- A waving hand with skin tone modifier is one width-2 cluster. -/
theorem dwc_wave_modifier :
    displayWidthClusters .narrow [0x1F44B, 0x1F3FD] = 2 := by decide +kernel

/-- A flag sequence is one width-2 cluster, not 4. -/
theorem dwc_flag_us :
    displayWidthClusters .narrow [0x1F1FA, 0x1F1F8] = 2 := by decide +kernel

/-- "hi" is two clusters of width 1 each, total 2. -/
theorem dwc_hi :
    displayWidthClusters .narrow [0x68, 0x69] = 2 := by decide +kernel

/-- The empty array is width 0. -/
theorem dwc_empty :
    displayWidthClusters .narrow [] = 0 := by decide +kernel

/-- Two CJK clusters of width 2 each total 4. -/
theorem dwc_nihao :
    displayWidthClusters .narrow [0x4F60, 0x597D] = 4 := by decide +kernel

end Unicode.Width
