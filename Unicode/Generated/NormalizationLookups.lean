/-
  Unicode.Generated.NormalizationLookups

  Generated normalization lookup primitives extracted from UCD 17.0.0.
-/

import Unicode.Generated.UnicodeData
import Unicode.Generated.WidthCompatMappings
import Unicode.Normalization.Lookup

namespace Unicode.Generated.NormalizationLookups

open Unicode.Normalization

set_option maxRecDepth 100000

/-- Fast Canonical_Combining_Class lookup. Unlisted codepoints have CCC 0. -/
def canonicalCombiningClass (cp : Nat) : Nat :=
  if cp < 0x0300 then 0
  else if decide (0xAC00 ≤ cp ∧ cp < 0xAC00 + 11172) then 0
  else if decide (0x0300 ≤ cp ∧ cp ≤ 0x0314) then 230
  else if cp = 0x0315 then 232
  else if decide (0x0316 ≤ cp ∧ cp ≤ 0x0319) then 220
  else if cp = 0x031A then 232
  else if cp = 0x031B then 216
  else if decide (0x031C ≤ cp ∧ cp ≤ 0x0320) then 220
  else if decide (0x0321 ≤ cp ∧ cp ≤ 0x0322) then 202
  else if decide (0x0323 ≤ cp ∧ cp ≤ 0x0326) then 220
  else if decide (0x0327 ≤ cp ∧ cp ≤ 0x0328) then 202
  else if decide (0x0329 ≤ cp ∧ cp ≤ 0x0333) then 220
  else if decide (0x0334 ≤ cp ∧ cp ≤ 0x0338) then 1
  else if decide (0x0339 ≤ cp ∧ cp ≤ 0x033C) then 220
  else if decide (0x033D ≤ cp ∧ cp ≤ 0x0344) then 230
  else if cp = 0x0345 then 240
  else if cp = 0x0346 then 230
  else if decide (0x0347 ≤ cp ∧ cp ≤ 0x0349) then 220
  else if decide (0x034A ≤ cp ∧ cp ≤ 0x034C) then 230
  else if decide (0x034D ≤ cp ∧ cp ≤ 0x034E) then 220
  else if decide (0x0350 ≤ cp ∧ cp ≤ 0x0352) then 230
  else if decide (0x0353 ≤ cp ∧ cp ≤ 0x0356) then 220
  else if cp = 0x0357 then 230
  else if cp = 0x0358 then 232
  else if decide (0x0359 ≤ cp ∧ cp ≤ 0x035A) then 220
  else if cp = 0x035B then 230
  else if cp = 0x035C then 233
  else if decide (0x035D ≤ cp ∧ cp ≤ 0x035E) then 234
  else if cp = 0x035F then 233
  else if decide (0x0360 ≤ cp ∧ cp ≤ 0x0361) then 234
  else if cp = 0x0362 then 233
  else if decide (0x0363 ≤ cp ∧ cp ≤ 0x036F) then 230
  else if decide (0x0483 ≤ cp ∧ cp ≤ 0x0487) then 230
  else if cp = 0x0591 then 220
  else if decide (0x0592 ≤ cp ∧ cp ≤ 0x0595) then 230
  else if cp = 0x0596 then 220
  else if decide (0x0597 ≤ cp ∧ cp ≤ 0x0599) then 230
  else if cp = 0x059A then 222
  else if cp = 0x059B then 220
  else if decide (0x059C ≤ cp ∧ cp ≤ 0x05A1) then 230
  else if decide (0x05A2 ≤ cp ∧ cp ≤ 0x05A7) then 220
  else if decide (0x05A8 ≤ cp ∧ cp ≤ 0x05A9) then 230
  else if cp = 0x05AA then 220
  else if decide (0x05AB ≤ cp ∧ cp ≤ 0x05AC) then 230
  else if cp = 0x05AD then 222
  else if cp = 0x05AE then 228
  else if cp = 0x05AF then 230
  else if cp = 0x05B0 then 10
  else if cp = 0x05B1 then 11
  else if cp = 0x05B2 then 12
  else if cp = 0x05B3 then 13
  else if cp = 0x05B4 then 14
  else if cp = 0x05B5 then 15
  else if cp = 0x05B6 then 16
  else if cp = 0x05B7 then 17
  else if cp = 0x05B8 then 18
  else if decide (0x05B9 ≤ cp ∧ cp ≤ 0x05BA) then 19
  else if cp = 0x05BB then 20
  else if cp = 0x05BC then 21
  else if cp = 0x05BD then 22
  else if cp = 0x05BF then 23
  else if cp = 0x05C1 then 24
  else if cp = 0x05C2 then 25
  else if cp = 0x05C4 then 230
  else if cp = 0x05C5 then 220
  else if cp = 0x05C7 then 18
  else if decide (0x0610 ≤ cp ∧ cp ≤ 0x0617) then 230
  else if cp = 0x0618 then 30
  else if cp = 0x0619 then 31
  else if cp = 0x061A then 32
  else if cp = 0x064B then 27
  else if cp = 0x064C then 28
  else if cp = 0x064D then 29
  else if cp = 0x064E then 30
  else if cp = 0x064F then 31
  else if cp = 0x0650 then 32
  else if cp = 0x0651 then 33
  else if cp = 0x0652 then 34
  else if decide (0x0653 ≤ cp ∧ cp ≤ 0x0654) then 230
  else if decide (0x0655 ≤ cp ∧ cp ≤ 0x0656) then 220
  else if decide (0x0657 ≤ cp ∧ cp ≤ 0x065B) then 230
  else if cp = 0x065C then 220
  else if decide (0x065D ≤ cp ∧ cp ≤ 0x065E) then 230
  else if cp = 0x065F then 220
  else if cp = 0x0670 then 35
  else if decide (0x06D6 ≤ cp ∧ cp ≤ 0x06DC) then 230
  else if decide (0x06DF ≤ cp ∧ cp ≤ 0x06E2) then 230
  else if cp = 0x06E3 then 220
  else if cp = 0x06E4 then 230
  else if decide (0x06E7 ≤ cp ∧ cp ≤ 0x06E8) then 230
  else if cp = 0x06EA then 220
  else if decide (0x06EB ≤ cp ∧ cp ≤ 0x06EC) then 230
  else if cp = 0x06ED then 220
  else if cp = 0x0711 then 36
  else if cp = 0x0730 then 230
  else if cp = 0x0731 then 220
  else if decide (0x0732 ≤ cp ∧ cp ≤ 0x0733) then 230
  else if cp = 0x0734 then 220
  else if decide (0x0735 ≤ cp ∧ cp ≤ 0x0736) then 230
  else if decide (0x0737 ≤ cp ∧ cp ≤ 0x0739) then 220
  else if cp = 0x073A then 230
  else if decide (0x073B ≤ cp ∧ cp ≤ 0x073C) then 220
  else if cp = 0x073D then 230
  else if cp = 0x073E then 220
  else if decide (0x073F ≤ cp ∧ cp ≤ 0x0741) then 230
  else if cp = 0x0742 then 220
  else if cp = 0x0743 then 230
  else if cp = 0x0744 then 220
  else if cp = 0x0745 then 230
  else if cp = 0x0746 then 220
  else if cp = 0x0747 then 230
  else if cp = 0x0748 then 220
  else if decide (0x0749 ≤ cp ∧ cp ≤ 0x074A) then 230
  else if decide (0x07EB ≤ cp ∧ cp ≤ 0x07F1) then 230
  else if cp = 0x07F2 then 220
  else if cp = 0x07F3 then 230
  else if cp = 0x07FD then 220
  else if decide (0x0816 ≤ cp ∧ cp ≤ 0x0819) then 230
  else if decide (0x081B ≤ cp ∧ cp ≤ 0x0823) then 230
  else if decide (0x0825 ≤ cp ∧ cp ≤ 0x0827) then 230
  else if decide (0x0829 ≤ cp ∧ cp ≤ 0x082D) then 230
  else if decide (0x0859 ≤ cp ∧ cp ≤ 0x085B) then 220
  else if decide (0x0897 ≤ cp ∧ cp ≤ 0x0898) then 230
  else if decide (0x0899 ≤ cp ∧ cp ≤ 0x089B) then 220
  else if decide (0x089C ≤ cp ∧ cp ≤ 0x089F) then 230
  else if decide (0x08CA ≤ cp ∧ cp ≤ 0x08CE) then 230
  else if decide (0x08CF ≤ cp ∧ cp ≤ 0x08D3) then 220
  else if decide (0x08D4 ≤ cp ∧ cp ≤ 0x08E1) then 230
  else if cp = 0x08E3 then 220
  else if decide (0x08E4 ≤ cp ∧ cp ≤ 0x08E5) then 230
  else if cp = 0x08E6 then 220
  else if decide (0x08E7 ≤ cp ∧ cp ≤ 0x08E8) then 230
  else if cp = 0x08E9 then 220
  else if decide (0x08EA ≤ cp ∧ cp ≤ 0x08EC) then 230
  else if decide (0x08ED ≤ cp ∧ cp ≤ 0x08EF) then 220
  else if cp = 0x08F0 then 27
  else if cp = 0x08F1 then 28
  else if cp = 0x08F2 then 29
  else if decide (0x08F3 ≤ cp ∧ cp ≤ 0x08F5) then 230
  else if cp = 0x08F6 then 220
  else if decide (0x08F7 ≤ cp ∧ cp ≤ 0x08F8) then 230
  else if decide (0x08F9 ≤ cp ∧ cp ≤ 0x08FA) then 220
  else if decide (0x08FB ≤ cp ∧ cp ≤ 0x08FF) then 230
  else if cp = 0x093C then 7
  else if cp = 0x094D then 9
  else if cp = 0x0951 then 230
  else if cp = 0x0952 then 220
  else if decide (0x0953 ≤ cp ∧ cp ≤ 0x0954) then 230
  else if cp = 0x09BC then 7
  else if cp = 0x09CD then 9
  else if cp = 0x09FE then 230
  else if cp = 0x0A3C then 7
  else if cp = 0x0A4D then 9
  else if cp = 0x0ABC then 7
  else if cp = 0x0ACD then 9
  else if cp = 0x0B3C then 7
  else if cp = 0x0B4D then 9
  else if cp = 0x0BCD then 9
  else if cp = 0x0C3C then 7
  else if cp = 0x0C4D then 9
  else if cp = 0x0C55 then 84
  else if cp = 0x0C56 then 91
  else if cp = 0x0CBC then 7
  else if cp = 0x0CCD then 9
  else if decide (0x0D3B ≤ cp ∧ cp ≤ 0x0D3C) then 9
  else if cp = 0x0D4D then 9
  else if cp = 0x0DCA then 9
  else if decide (0x0E38 ≤ cp ∧ cp ≤ 0x0E39) then 103
  else if cp = 0x0E3A then 9
  else if decide (0x0E48 ≤ cp ∧ cp ≤ 0x0E4B) then 107
  else if decide (0x0EB8 ≤ cp ∧ cp ≤ 0x0EB9) then 118
  else if cp = 0x0EBA then 9
  else if decide (0x0EC8 ≤ cp ∧ cp ≤ 0x0ECB) then 122
  else if decide (0x0F18 ≤ cp ∧ cp ≤ 0x0F19) then 220
  else if cp = 0x0F35 then 220
  else if cp = 0x0F37 then 220
  else if cp = 0x0F39 then 216
  else if cp = 0x0F71 then 129
  else if cp = 0x0F72 then 130
  else if cp = 0x0F74 then 132
  else if decide (0x0F7A ≤ cp ∧ cp ≤ 0x0F7D) then 130
  else if cp = 0x0F80 then 130
  else if decide (0x0F82 ≤ cp ∧ cp ≤ 0x0F83) then 230
  else if cp = 0x0F84 then 9
  else if decide (0x0F86 ≤ cp ∧ cp ≤ 0x0F87) then 230
  else if cp = 0x0FC6 then 220
  else if cp = 0x1037 then 7
  else if decide (0x1039 ≤ cp ∧ cp ≤ 0x103A) then 9
  else if cp = 0x108D then 220
  else if decide (0x135D ≤ cp ∧ cp ≤ 0x135F) then 230
  else if decide (0x1714 ≤ cp ∧ cp ≤ 0x1715) then 9
  else if cp = 0x1734 then 9
  else if cp = 0x17D2 then 9
  else if cp = 0x17DD then 230
  else if cp = 0x18A9 then 228
  else if cp = 0x1939 then 222
  else if cp = 0x193A then 230
  else if cp = 0x193B then 220
  else if cp = 0x1A17 then 230
  else if cp = 0x1A18 then 220
  else if cp = 0x1A60 then 9
  else if decide (0x1A75 ≤ cp ∧ cp ≤ 0x1A7C) then 230
  else if cp = 0x1A7F then 220
  else if decide (0x1AB0 ≤ cp ∧ cp ≤ 0x1AB4) then 230
  else if decide (0x1AB5 ≤ cp ∧ cp ≤ 0x1ABA) then 220
  else if decide (0x1ABB ≤ cp ∧ cp ≤ 0x1ABC) then 230
  else if cp = 0x1ABD then 220
  else if decide (0x1ABF ≤ cp ∧ cp ≤ 0x1AC0) then 220
  else if decide (0x1AC1 ≤ cp ∧ cp ≤ 0x1AC2) then 230
  else if decide (0x1AC3 ≤ cp ∧ cp ≤ 0x1AC4) then 220
  else if decide (0x1AC5 ≤ cp ∧ cp ≤ 0x1AC9) then 230
  else if cp = 0x1ACA then 220
  else if decide (0x1ACB ≤ cp ∧ cp ≤ 0x1ADC) then 230
  else if cp = 0x1ADD then 220
  else if decide (0x1AE0 ≤ cp ∧ cp ≤ 0x1AE5) then 230
  else if cp = 0x1AE6 then 220
  else if decide (0x1AE7 ≤ cp ∧ cp ≤ 0x1AEA) then 230
  else if cp = 0x1AEB then 234
  else if cp = 0x1B34 then 7
  else if cp = 0x1B44 then 9
  else if cp = 0x1B6B then 230
  else if cp = 0x1B6C then 220
  else if decide (0x1B6D ≤ cp ∧ cp ≤ 0x1B73) then 230
  else if decide (0x1BAA ≤ cp ∧ cp ≤ 0x1BAB) then 9
  else if cp = 0x1BE6 then 7
  else if decide (0x1BF2 ≤ cp ∧ cp ≤ 0x1BF3) then 9
  else if cp = 0x1C37 then 7
  else if decide (0x1CD0 ≤ cp ∧ cp ≤ 0x1CD2) then 230
  else if cp = 0x1CD4 then 1
  else if decide (0x1CD5 ≤ cp ∧ cp ≤ 0x1CD9) then 220
  else if decide (0x1CDA ≤ cp ∧ cp ≤ 0x1CDB) then 230
  else if decide (0x1CDC ≤ cp ∧ cp ≤ 0x1CDF) then 220
  else if cp = 0x1CE0 then 230
  else if decide (0x1CE2 ≤ cp ∧ cp ≤ 0x1CE8) then 1
  else if cp = 0x1CED then 220
  else if cp = 0x1CF4 then 230
  else if decide (0x1CF8 ≤ cp ∧ cp ≤ 0x1CF9) then 230
  else if decide (0x1DC0 ≤ cp ∧ cp ≤ 0x1DC1) then 230
  else if cp = 0x1DC2 then 220
  else if decide (0x1DC3 ≤ cp ∧ cp ≤ 0x1DC9) then 230
  else if cp = 0x1DCA then 220
  else if decide (0x1DCB ≤ cp ∧ cp ≤ 0x1DCC) then 230
  else if cp = 0x1DCD then 234
  else if cp = 0x1DCE then 214
  else if cp = 0x1DCF then 220
  else if cp = 0x1DD0 then 202
  else if decide (0x1DD1 ≤ cp ∧ cp ≤ 0x1DF5) then 230
  else if cp = 0x1DF6 then 232
  else if decide (0x1DF7 ≤ cp ∧ cp ≤ 0x1DF8) then 228
  else if cp = 0x1DF9 then 220
  else if cp = 0x1DFA then 218
  else if cp = 0x1DFB then 230
  else if cp = 0x1DFC then 233
  else if cp = 0x1DFD then 220
  else if cp = 0x1DFE then 230
  else if cp = 0x1DFF then 220
  else if decide (0x20D0 ≤ cp ∧ cp ≤ 0x20D1) then 230
  else if decide (0x20D2 ≤ cp ∧ cp ≤ 0x20D3) then 1
  else if decide (0x20D4 ≤ cp ∧ cp ≤ 0x20D7) then 230
  else if decide (0x20D8 ≤ cp ∧ cp ≤ 0x20DA) then 1
  else if decide (0x20DB ≤ cp ∧ cp ≤ 0x20DC) then 230
  else if cp = 0x20E1 then 230
  else if decide (0x20E5 ≤ cp ∧ cp ≤ 0x20E6) then 1
  else if cp = 0x20E7 then 230
  else if cp = 0x20E8 then 220
  else if cp = 0x20E9 then 230
  else if decide (0x20EA ≤ cp ∧ cp ≤ 0x20EB) then 1
  else if decide (0x20EC ≤ cp ∧ cp ≤ 0x20EF) then 220
  else if cp = 0x20F0 then 230
  else if decide (0x2CEF ≤ cp ∧ cp ≤ 0x2CF1) then 230
  else if cp = 0x2D7F then 9
  else if decide (0x2DE0 ≤ cp ∧ cp ≤ 0x2DFF) then 230
  else if cp = 0x302A then 218
  else if cp = 0x302B then 228
  else if cp = 0x302C then 232
  else if cp = 0x302D then 222
  else if decide (0x302E ≤ cp ∧ cp ≤ 0x302F) then 224
  else if decide (0x3099 ≤ cp ∧ cp ≤ 0x309A) then 8
  else if cp = 0xA66F then 230
  else if decide (0xA674 ≤ cp ∧ cp ≤ 0xA67D) then 230
  else if decide (0xA69E ≤ cp ∧ cp ≤ 0xA69F) then 230
  else if decide (0xA6F0 ≤ cp ∧ cp ≤ 0xA6F1) then 230
  else if cp = 0xA806 then 9
  else if cp = 0xA82C then 9
  else if cp = 0xA8C4 then 9
  else if decide (0xA8E0 ≤ cp ∧ cp ≤ 0xA8F1) then 230
  else if decide (0xA92B ≤ cp ∧ cp ≤ 0xA92D) then 220
  else if cp = 0xA953 then 9
  else if cp = 0xA9B3 then 7
  else if cp = 0xA9C0 then 9
  else if cp = 0xAAB0 then 230
  else if decide (0xAAB2 ≤ cp ∧ cp ≤ 0xAAB3) then 230
  else if cp = 0xAAB4 then 220
  else if decide (0xAAB7 ≤ cp ∧ cp ≤ 0xAAB8) then 230
  else if decide (0xAABE ≤ cp ∧ cp ≤ 0xAABF) then 230
  else if cp = 0xAAC1 then 230
  else if cp = 0xAAF6 then 9
  else if cp = 0xABED then 9
  else if cp = 0xFB1E then 26
  else if decide (0xFE20 ≤ cp ∧ cp ≤ 0xFE26) then 230
  else if decide (0xFE27 ≤ cp ∧ cp ≤ 0xFE2D) then 220
  else if decide (0xFE2E ≤ cp ∧ cp ≤ 0xFE2F) then 230
  else if cp = 0x0101FD then 220
  else if cp = 0x0102E0 then 220
  else if decide (0x010376 ≤ cp ∧ cp ≤ 0x01037A) then 230
  else if cp = 0x010A0D then 220
  else if cp = 0x010A0F then 230
  else if cp = 0x010A38 then 230
  else if cp = 0x010A39 then 1
  else if cp = 0x010A3A then 220
  else if cp = 0x010A3F then 9
  else if cp = 0x010AE5 then 230
  else if cp = 0x010AE6 then 220
  else if decide (0x010D24 ≤ cp ∧ cp ≤ 0x010D27) then 230
  else if decide (0x010D69 ≤ cp ∧ cp ≤ 0x010D6D) then 230
  else if decide (0x010EAB ≤ cp ∧ cp ≤ 0x010EAC) then 230
  else if decide (0x010EFA ≤ cp ∧ cp ≤ 0x010EFB) then 220
  else if decide (0x010EFD ≤ cp ∧ cp ≤ 0x010EFF) then 220
  else if decide (0x010F46 ≤ cp ∧ cp ≤ 0x010F47) then 220
  else if decide (0x010F48 ≤ cp ∧ cp ≤ 0x010F4A) then 230
  else if cp = 0x010F4B then 220
  else if cp = 0x010F4C then 230
  else if decide (0x010F4D ≤ cp ∧ cp ≤ 0x010F50) then 220
  else if cp = 0x010F82 then 230
  else if cp = 0x010F83 then 220
  else if cp = 0x010F84 then 230
  else if cp = 0x010F85 then 220
  else if cp = 0x011046 then 9
  else if cp = 0x011070 then 9
  else if cp = 0x01107F then 9
  else if cp = 0x0110B9 then 9
  else if cp = 0x0110BA then 7
  else if decide (0x011100 ≤ cp ∧ cp ≤ 0x011102) then 230
  else if decide (0x011133 ≤ cp ∧ cp ≤ 0x011134) then 9
  else if cp = 0x011173 then 7
  else if cp = 0x0111C0 then 9
  else if cp = 0x0111CA then 7
  else if cp = 0x011235 then 9
  else if cp = 0x011236 then 7
  else if cp = 0x0112E9 then 7
  else if cp = 0x0112EA then 9
  else if decide (0x01133B ≤ cp ∧ cp ≤ 0x01133C) then 7
  else if cp = 0x01134D then 9
  else if decide (0x011366 ≤ cp ∧ cp ≤ 0x01136C) then 230
  else if decide (0x011370 ≤ cp ∧ cp ≤ 0x011374) then 230
  else if decide (0x0113CE ≤ cp ∧ cp ≤ 0x0113D0) then 9
  else if cp = 0x011442 then 9
  else if cp = 0x011446 then 7
  else if cp = 0x01145E then 230
  else if cp = 0x0114C2 then 9
  else if cp = 0x0114C3 then 7
  else if cp = 0x0115BF then 9
  else if cp = 0x0115C0 then 7
  else if cp = 0x01163F then 9
  else if cp = 0x0116B6 then 9
  else if cp = 0x0116B7 then 7
  else if cp = 0x01172B then 9
  else if cp = 0x011839 then 9
  else if cp = 0x01183A then 7
  else if decide (0x01193D ≤ cp ∧ cp ≤ 0x01193E) then 9
  else if cp = 0x011943 then 7
  else if cp = 0x0119E0 then 9
  else if cp = 0x011A34 then 9
  else if cp = 0x011A47 then 9
  else if cp = 0x011A99 then 9
  else if cp = 0x011C3F then 9
  else if cp = 0x011D42 then 7
  else if decide (0x011D44 ≤ cp ∧ cp ≤ 0x011D45) then 9
  else if cp = 0x011D97 then 9
  else if decide (0x011F41 ≤ cp ∧ cp ≤ 0x011F42) then 9
  else if cp = 0x01612F then 9
  else if decide (0x016AF0 ≤ cp ∧ cp ≤ 0x016AF4) then 1
  else if decide (0x016B30 ≤ cp ∧ cp ≤ 0x016B36) then 230
  else if decide (0x016FF0 ≤ cp ∧ cp ≤ 0x016FF1) then 6
  else if cp = 0x01BC9E then 1
  else if decide (0x01D165 ≤ cp ∧ cp ≤ 0x01D166) then 216
  else if decide (0x01D167 ≤ cp ∧ cp ≤ 0x01D169) then 1
  else if cp = 0x01D16D then 226
  else if decide (0x01D16E ≤ cp ∧ cp ≤ 0x01D172) then 216
  else if decide (0x01D17B ≤ cp ∧ cp ≤ 0x01D182) then 220
  else if decide (0x01D185 ≤ cp ∧ cp ≤ 0x01D189) then 230
  else if decide (0x01D18A ≤ cp ∧ cp ≤ 0x01D18B) then 220
  else if decide (0x01D1AA ≤ cp ∧ cp ≤ 0x01D1AD) then 230
  else if decide (0x01D242 ≤ cp ∧ cp ≤ 0x01D244) then 230
  else if decide (0x01E000 ≤ cp ∧ cp ≤ 0x01E006) then 230
  else if decide (0x01E008 ≤ cp ∧ cp ≤ 0x01E018) then 230
  else if decide (0x01E01B ≤ cp ∧ cp ≤ 0x01E021) then 230
  else if decide (0x01E023 ≤ cp ∧ cp ≤ 0x01E024) then 230
  else if decide (0x01E026 ≤ cp ∧ cp ≤ 0x01E02A) then 230
  else if cp = 0x01E08F then 230
  else if decide (0x01E130 ≤ cp ∧ cp ≤ 0x01E136) then 230
  else if cp = 0x01E2AE then 230
  else if decide (0x01E2EC ≤ cp ∧ cp ≤ 0x01E2EF) then 230
  else if decide (0x01E4EC ≤ cp ∧ cp ≤ 0x01E4ED) then 232
  else if cp = 0x01E4EE then 220
  else if cp = 0x01E4EF then 230
  else if cp = 0x01E5EE then 230
  else if cp = 0x01E5EF then 220
  else if cp = 0x01E6E3 then 230
  else if cp = 0x01E6E6 then 230
  else if decide (0x01E6EE ≤ cp ∧ cp ≤ 0x01E6EF) then 230
  else if cp = 0x01E6F5 then 230
  else if decide (0x01E8D0 ≤ cp ∧ cp ≤ 0x01E8D6) then 220
  else if decide (0x01E944 ≤ cp ∧ cp ≤ 0x01E949) then 230
  else if cp = 0x01E94A then 7
  else 0

theorem canonicalCombiningClass_hangul_syllable
    (cp : Nat) (h : 0xAC00 ≤ cp ∧ cp < 0xAC00 + 11172) :
    canonicalCombiningClass cp = 0 := by
  unfold canonicalCombiningClass
  have hNotLow : ¬ cp < 0x0300 := by omega
  have hRange : decide (0xAC00 ≤ cp ∧ cp < 0xAC00 + 11172) = true :=
    decide_eq_true h
  simp [hNotLow, hRange]

-- ═══════════════════════════════════════════════════════════════════════════════
-- WIDTH-COMPAT-SOURCE STABILITY OF DECOMPOSITION / COMPOSITION OUTPUTS
--
-- The width-compatibility mapping (UAX #11 fullwidth/halfwidth forms) is the one
-- canonical operation whose source set could overlap the codomain of canonical
-- decomposition and composition. The two whole-table invariants below pin that
-- no decomposition element, and no codepoint carrying a decomposition, is a
-- width-compatibility source — so neither normalization output ever requires a
-- further width pass.
--
-- Both close by kernel reduction over the `List` view of `UnicodeData.rows`:
-- `Array` traversal reduces in O(n²) (the rows are a push-built `++` chain), so
-- we drop to `List` via `Array.all_toList` plus the symbolic `toList` rewrites,
-- where reduction is linear.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every element of every row's canonical decomposition is not a
    width-compatibility source. -/
theorem rows_decompositionTargets_nonSource :
    UnicodeData.rows.all (fun r =>
      r.canonicalDecomposition.all (fun t =>
        ! WidthCompatMappings.isSource t)) = true := by
  rw [← Array.all_toList]
  simp only [UnicodeData.rows, List.toList_toArray]
  decide +kernel

/-- Every row that carries a canonical decomposition is itself not a
    width-compatibility source. A primary composite is exactly the codepoint of
    such a row, so composites are non-sources. -/
theorem rows_decomposed_nonSource :
    UnicodeData.rows.all (fun r =>
      decide (r.canonicalDecomposition.size = 0) ||
      ! WidthCompatMappings.isSource r.codepoint) = true := by
  rw [← Array.all_toList]
  simp only [UnicodeData.rows, List.toList_toArray]
  decide +kernel

/-- A canonical-decomposition element is never a width-compatibility source.
    Lifted from `rows_decompositionTargets_nonSource` through the row lookup
    backing `Lookup.canonicalDecomposition`. -/
theorem canonicalDecomposition_target_non_source
    (cp j : Nat) (hj : j ∈ Lookup.canonicalDecomposition cp) :
    WidthCompatMappings.isSource j = false := by
  cases hrow : Lookup.lookupRow cp with
  | none =>
      have hcd : Lookup.canonicalDecomposition cp = #[] := by
        unfold Lookup.canonicalDecomposition
        rw [hrow]
      rw [hcd] at hj
      simp at hj
  | some row =>
      have hcd : Lookup.canonicalDecomposition cp = row.canonicalDecomposition := by
        unfold Lookup.canonicalDecomposition
        rw [hrow]
      rw [hcd] at hj
      have hmem : row ∈ UnicodeData.rows := Array.mem_of_find?_eq_some hrow
      have hAll := rows_decompositionTargets_nonSource
      rw [Array.all_eq_true] at hAll
      rcases Array.getElem_of_mem hmem with ⟨i, hi, hiEq⟩
      have hRow := hAll i hi
      rw [hiEq] at hRow
      rw [Array.all_eq_true] at hRow
      rcases Array.getElem_of_mem hj with ⟨k, hk, hkEq⟩
      have hElem := hRow k hk
      rw [hkEq] at hElem
      simpa using hElem

/-- A non-Hangul primary composite — the codepoint a row with two-element
    canonical decomposition `#[d, c]` recomposes to — is never a
    width-compatibility source. Lifted from `rows_decomposed_nonSource`; the
    hypothesis is the `findSome?` scan that `Compose.primaryComposite?` reduces
    to on its non-Hangul branch. -/
theorem primaryComposite_target_non_source
    (d c p : Nat)
    (h : UnicodeData.rows.findSome? (fun r =>
           if r.canonicalDecomposition = #[d, c] ∧
              ¬ Lookup.isFullCompositionExclusion r.codepoint then
             some r.codepoint
           else
             none) = some p) :
    WidthCompatMappings.isSource p = false := by
  obtain ⟨row, hmem, hf⟩ := Array.exists_of_findSome?_eq_some h
  split at hf
  · next hcond =>
      simp only [Option.some.injEq] at hf
      have hdecomp : row.canonicalDecomposition = #[d, c] := hcond.1
      have hAll := rows_decomposed_nonSource
      rw [Array.all_eq_true] at hAll
      rcases Array.getElem_of_mem hmem with ⟨i, hi, hiEq⟩
      have hRow := hAll i hi
      rw [hiEq, hdecomp, hf] at hRow
      simpa using hRow
  · next hcond =>
      simp at hf

-- ═══════════════════════════════════════════════════════════════════════════════
-- INTEGRITY GATE — the `canonicalCombiningClass` function must agree with column 3
-- of the pinned UnicodeData.txt for every assigned code point. This is a functional
-- gate: it checks the hand-written range table against the source rather than a
-- literal, and aborts the build on any disagreement.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Raw text of `UnicodeData.txt`, embedded at compile time. -/
def unicodeDataRawNL : String := include_str "../Ucd/UnicodeData.txt"

def nlHexVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30
  else if n ≥ 0x61 ∧ n ≤ 0x66 then n - 0x61 + 10
  else if n ≥ 0x41 ∧ n ≤ 0x46 then n - 0x41 + 10
  else 0
def nlHex (s : String) : Nat := s.foldl (fun acc c => acc * 16 + nlHexVal c) 0
def nlTrim (s : String) : String := (String.trimAscii s).toString
def nlDec (s : String) : Nat := (nlTrim s).foldl (fun acc c => acc * 10 + (c.toNat - 0x30)) 0

#eval show IO Unit from do
  for line in unicodeDataRawNL.splitOn "\n" do
    let f := (line.splitOn ";").toArray
    if f.size < 4 then continue
    let cp := nlHex (nlTrim f[0]!)
    let ccc := nlDec (nlTrim f[3]!)
    unless canonicalCombiningClass cp == ccc do
      throw (IO.userError
        s!"NormalizationLookups drift: canonicalCombiningClass {cp} = {canonicalCombiningClass cp} ≠ {ccc} (UnicodeData.txt)")

end Unicode.Generated.NormalizationLookups
