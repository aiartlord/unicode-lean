/-
  Unicode.Generated.UnicodeDataIndexFacts

  Aggregated soundness/completeness facts for the low-byte UnicodeData index.
-/

import Unicode.Generated.UnicodeDataIndexFacts0
import Unicode.Generated.UnicodeDataIndexFacts1
import Unicode.Generated.UnicodeDataIndexFacts2
import Unicode.Generated.UnicodeDataIndexFacts3
import Unicode.Generated.UnicodeDataIndexFacts4
import Unicode.Generated.UnicodeDataIndexFacts5
import Unicode.Generated.UnicodeDataIndexFacts6
import Unicode.Generated.UnicodeDataIndexFacts7
import Unicode.Generated.UnicodeDataIndexFacts8
import Unicode.Generated.UnicodeDataIndexFacts9
import Unicode.Generated.UnicodeDataIndexFacts10
import Unicode.Generated.UnicodeDataIndexFacts11
import Unicode.Generated.UnicodeDataIndexFacts12
import Unicode.Generated.UnicodeDataIndexFacts13
import Unicode.Generated.UnicodeDataIndexFacts14
import Unicode.Generated.UnicodeDataIndexFacts15
import Unicode.Generated.UnicodeDataIndexFacts16
import Unicode.Generated.UnicodeDataIndexFacts17
import Unicode.Generated.UnicodeDataIndexFacts18
import Unicode.Generated.UnicodeDataIndexFacts19
import Unicode.Generated.UnicodeDataIndexFacts20
import Unicode.Generated.UnicodeDataIndexFacts21
import Unicode.Generated.UnicodeDataIndexFacts22
import Unicode.Generated.UnicodeDataIndexFacts23
import Unicode.Generated.UnicodeDataIndexFacts24
import Unicode.Generated.UnicodeDataIndexFacts25
import Unicode.Generated.UnicodeDataIndexFacts26
import Unicode.Generated.UnicodeDataIndexFacts27
import Unicode.Generated.UnicodeDataIndexFacts28
import Unicode.Generated.UnicodeDataIndexFacts29
import Unicode.Generated.UnicodeDataIndexFacts30
import Unicode.Generated.UnicodeDataIndexFacts31
import Unicode.Generated.UnicodeDataIndexFacts32
import Unicode.Generated.UnicodeDataIndexFacts33
import Unicode.Generated.UnicodeDataIndexFacts34
import Unicode.Generated.UnicodeDataIndexFacts35
import Unicode.Generated.UnicodeDataIndexFacts36
import Unicode.Generated.UnicodeDataIndexFacts37
import Unicode.Generated.UnicodeDataIndexFacts38
import Unicode.Generated.UnicodeDataIndexFacts39
import Unicode.Generated.UnicodeDataIndexFacts40
import Unicode.Generated.UnicodeDataIndexFacts41
import Unicode.Generated.UnicodeDataIndexFacts42
import Unicode.Generated.UnicodeDataIndexFacts43
import Unicode.Generated.UnicodeDataIndexFacts44
import Unicode.Generated.UnicodeDataIndexFacts45
import Unicode.Generated.UnicodeDataIndexFacts46
import Unicode.Generated.UnicodeDataIndexFacts47
import Unicode.Generated.UnicodeDataIndexFacts48
import Unicode.Generated.UnicodeDataIndexFacts49
import Unicode.Generated.UnicodeDataIndexFacts50
import Unicode.Generated.UnicodeDataIndexFacts51
import Unicode.Generated.UnicodeDataIndexFacts52
import Unicode.Generated.UnicodeDataIndexFacts53
import Unicode.Generated.UnicodeDataIndexFacts54
import Unicode.Generated.UnicodeDataIndexFacts55
import Unicode.Generated.UnicodeDataIndexFacts56
import Unicode.Generated.UnicodeDataIndexFacts57
import Unicode.Generated.UnicodeDataIndexFacts58
import Unicode.Generated.UnicodeDataIndexFacts59
import Unicode.Generated.UnicodeDataIndexFacts60
import Unicode.Generated.UnicodeDataIndexFacts61
import Unicode.Generated.UnicodeDataIndexFacts62
import Unicode.Generated.UnicodeDataIndexFacts63

namespace Unicode.Generated.UnicodeDataIndex

open Unicode.Generated
open Unicode.Generated.UnicodeData
open Unicode.Generated.UnicodeDataIndexFacts0
open Unicode.Generated.UnicodeDataIndexFacts1
open Unicode.Generated.UnicodeDataIndexFacts2
open Unicode.Generated.UnicodeDataIndexFacts3
open Unicode.Generated.UnicodeDataIndexFacts4
open Unicode.Generated.UnicodeDataIndexFacts5
open Unicode.Generated.UnicodeDataIndexFacts6
open Unicode.Generated.UnicodeDataIndexFacts7
open Unicode.Generated.UnicodeDataIndexFacts8
open Unicode.Generated.UnicodeDataIndexFacts9
open Unicode.Generated.UnicodeDataIndexFacts10
open Unicode.Generated.UnicodeDataIndexFacts11
open Unicode.Generated.UnicodeDataIndexFacts12
open Unicode.Generated.UnicodeDataIndexFacts13
open Unicode.Generated.UnicodeDataIndexFacts14
open Unicode.Generated.UnicodeDataIndexFacts15
open Unicode.Generated.UnicodeDataIndexFacts16
open Unicode.Generated.UnicodeDataIndexFacts17
open Unicode.Generated.UnicodeDataIndexFacts18
open Unicode.Generated.UnicodeDataIndexFacts19
open Unicode.Generated.UnicodeDataIndexFacts20
open Unicode.Generated.UnicodeDataIndexFacts21
open Unicode.Generated.UnicodeDataIndexFacts22
open Unicode.Generated.UnicodeDataIndexFacts23
open Unicode.Generated.UnicodeDataIndexFacts24
open Unicode.Generated.UnicodeDataIndexFacts25
open Unicode.Generated.UnicodeDataIndexFacts26
open Unicode.Generated.UnicodeDataIndexFacts27
open Unicode.Generated.UnicodeDataIndexFacts28
open Unicode.Generated.UnicodeDataIndexFacts29
open Unicode.Generated.UnicodeDataIndexFacts30
open Unicode.Generated.UnicodeDataIndexFacts31
open Unicode.Generated.UnicodeDataIndexFacts32
open Unicode.Generated.UnicodeDataIndexFacts33
open Unicode.Generated.UnicodeDataIndexFacts34
open Unicode.Generated.UnicodeDataIndexFacts35
open Unicode.Generated.UnicodeDataIndexFacts36
open Unicode.Generated.UnicodeDataIndexFacts37
open Unicode.Generated.UnicodeDataIndexFacts38
open Unicode.Generated.UnicodeDataIndexFacts39
open Unicode.Generated.UnicodeDataIndexFacts40
open Unicode.Generated.UnicodeDataIndexFacts41
open Unicode.Generated.UnicodeDataIndexFacts42
open Unicode.Generated.UnicodeDataIndexFacts43
open Unicode.Generated.UnicodeDataIndexFacts44
open Unicode.Generated.UnicodeDataIndexFacts45
open Unicode.Generated.UnicodeDataIndexFacts46
open Unicode.Generated.UnicodeDataIndexFacts47
open Unicode.Generated.UnicodeDataIndexFacts48
open Unicode.Generated.UnicodeDataIndexFacts49
open Unicode.Generated.UnicodeDataIndexFacts50
open Unicode.Generated.UnicodeDataIndexFacts51
open Unicode.Generated.UnicodeDataIndexFacts52
open Unicode.Generated.UnicodeDataIndexFacts53
open Unicode.Generated.UnicodeDataIndexFacts54
open Unicode.Generated.UnicodeDataIndexFacts55
open Unicode.Generated.UnicodeDataIndexFacts56
open Unicode.Generated.UnicodeDataIndexFacts57
open Unicode.Generated.UnicodeDataIndexFacts58
open Unicode.Generated.UnicodeDataIndexFacts59
open Unicode.Generated.UnicodeDataIndexFacts60
open Unicode.Generated.UnicodeDataIndexFacts61
open Unicode.Generated.UnicodeDataIndexFacts62
open Unicode.Generated.UnicodeDataIndexFacts63

set_option maxRecDepth 100000

theorem rowBucket_all_supported_rowsList : ∀ low : Nat,
    (rowBucketByLowByte low).all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true
  | 0x00 => rowsLowByte00_all_supported_rowsList
  | 0x01 => rowsLowByte01_all_supported_rowsList
  | 0x02 => rowsLowByte02_all_supported_rowsList
  | 0x03 => rowsLowByte03_all_supported_rowsList
  | 0x04 => rowsLowByte04_all_supported_rowsList
  | 0x05 => rowsLowByte05_all_supported_rowsList
  | 0x06 => rowsLowByte06_all_supported_rowsList
  | 0x07 => rowsLowByte07_all_supported_rowsList
  | 0x08 => rowsLowByte08_all_supported_rowsList
  | 0x09 => rowsLowByte09_all_supported_rowsList
  | 0x0A => rowsLowByte0A_all_supported_rowsList
  | 0x0B => rowsLowByte0B_all_supported_rowsList
  | 0x0C => rowsLowByte0C_all_supported_rowsList
  | 0x0D => rowsLowByte0D_all_supported_rowsList
  | 0x0E => rowsLowByte0E_all_supported_rowsList
  | 0x0F => rowsLowByte0F_all_supported_rowsList
  | 0x10 => rowsLowByte10_all_supported_rowsList
  | 0x11 => rowsLowByte11_all_supported_rowsList
  | 0x12 => rowsLowByte12_all_supported_rowsList
  | 0x13 => rowsLowByte13_all_supported_rowsList
  | 0x14 => rowsLowByte14_all_supported_rowsList
  | 0x15 => rowsLowByte15_all_supported_rowsList
  | 0x16 => rowsLowByte16_all_supported_rowsList
  | 0x17 => rowsLowByte17_all_supported_rowsList
  | 0x18 => rowsLowByte18_all_supported_rowsList
  | 0x19 => rowsLowByte19_all_supported_rowsList
  | 0x1A => rowsLowByte1A_all_supported_rowsList
  | 0x1B => rowsLowByte1B_all_supported_rowsList
  | 0x1C => rowsLowByte1C_all_supported_rowsList
  | 0x1D => rowsLowByte1D_all_supported_rowsList
  | 0x1E => rowsLowByte1E_all_supported_rowsList
  | 0x1F => rowsLowByte1F_all_supported_rowsList
  | 0x20 => rowsLowByte20_all_supported_rowsList
  | 0x21 => rowsLowByte21_all_supported_rowsList
  | 0x22 => rowsLowByte22_all_supported_rowsList
  | 0x23 => rowsLowByte23_all_supported_rowsList
  | 0x24 => rowsLowByte24_all_supported_rowsList
  | 0x25 => rowsLowByte25_all_supported_rowsList
  | 0x26 => rowsLowByte26_all_supported_rowsList
  | 0x27 => rowsLowByte27_all_supported_rowsList
  | 0x28 => rowsLowByte28_all_supported_rowsList
  | 0x29 => rowsLowByte29_all_supported_rowsList
  | 0x2A => rowsLowByte2A_all_supported_rowsList
  | 0x2B => rowsLowByte2B_all_supported_rowsList
  | 0x2C => rowsLowByte2C_all_supported_rowsList
  | 0x2D => rowsLowByte2D_all_supported_rowsList
  | 0x2E => rowsLowByte2E_all_supported_rowsList
  | 0x2F => rowsLowByte2F_all_supported_rowsList
  | 0x30 => rowsLowByte30_all_supported_rowsList
  | 0x31 => rowsLowByte31_all_supported_rowsList
  | 0x32 => rowsLowByte32_all_supported_rowsList
  | 0x33 => rowsLowByte33_all_supported_rowsList
  | 0x34 => rowsLowByte34_all_supported_rowsList
  | 0x35 => rowsLowByte35_all_supported_rowsList
  | 0x36 => rowsLowByte36_all_supported_rowsList
  | 0x37 => rowsLowByte37_all_supported_rowsList
  | 0x38 => rowsLowByte38_all_supported_rowsList
  | 0x39 => rowsLowByte39_all_supported_rowsList
  | 0x3A => rowsLowByte3A_all_supported_rowsList
  | 0x3B => rowsLowByte3B_all_supported_rowsList
  | 0x3C => rowsLowByte3C_all_supported_rowsList
  | 0x3D => rowsLowByte3D_all_supported_rowsList
  | 0x3E => rowsLowByte3E_all_supported_rowsList
  | 0x3F => rowsLowByte3F_all_supported_rowsList
  | 0x40 => rowsLowByte40_all_supported_rowsList
  | 0x41 => rowsLowByte41_all_supported_rowsList
  | 0x42 => rowsLowByte42_all_supported_rowsList
  | 0x43 => rowsLowByte43_all_supported_rowsList
  | 0x44 => rowsLowByte44_all_supported_rowsList
  | 0x45 => rowsLowByte45_all_supported_rowsList
  | 0x46 => rowsLowByte46_all_supported_rowsList
  | 0x47 => rowsLowByte47_all_supported_rowsList
  | 0x48 => rowsLowByte48_all_supported_rowsList
  | 0x49 => rowsLowByte49_all_supported_rowsList
  | 0x4A => rowsLowByte4A_all_supported_rowsList
  | 0x4B => rowsLowByte4B_all_supported_rowsList
  | 0x4C => rowsLowByte4C_all_supported_rowsList
  | 0x4D => rowsLowByte4D_all_supported_rowsList
  | 0x4E => rowsLowByte4E_all_supported_rowsList
  | 0x4F => rowsLowByte4F_all_supported_rowsList
  | 0x50 => rowsLowByte50_all_supported_rowsList
  | 0x51 => rowsLowByte51_all_supported_rowsList
  | 0x52 => rowsLowByte52_all_supported_rowsList
  | 0x53 => rowsLowByte53_all_supported_rowsList
  | 0x54 => rowsLowByte54_all_supported_rowsList
  | 0x55 => rowsLowByte55_all_supported_rowsList
  | 0x56 => rowsLowByte56_all_supported_rowsList
  | 0x57 => rowsLowByte57_all_supported_rowsList
  | 0x58 => rowsLowByte58_all_supported_rowsList
  | 0x59 => rowsLowByte59_all_supported_rowsList
  | 0x5A => rowsLowByte5A_all_supported_rowsList
  | 0x5B => rowsLowByte5B_all_supported_rowsList
  | 0x5C => rowsLowByte5C_all_supported_rowsList
  | 0x5D => rowsLowByte5D_all_supported_rowsList
  | 0x5E => rowsLowByte5E_all_supported_rowsList
  | 0x5F => rowsLowByte5F_all_supported_rowsList
  | 0x60 => rowsLowByte60_all_supported_rowsList
  | 0x61 => rowsLowByte61_all_supported_rowsList
  | 0x62 => rowsLowByte62_all_supported_rowsList
  | 0x63 => rowsLowByte63_all_supported_rowsList
  | 0x64 => rowsLowByte64_all_supported_rowsList
  | 0x65 => rowsLowByte65_all_supported_rowsList
  | 0x66 => rowsLowByte66_all_supported_rowsList
  | 0x67 => rowsLowByte67_all_supported_rowsList
  | 0x68 => rowsLowByte68_all_supported_rowsList
  | 0x69 => rowsLowByte69_all_supported_rowsList
  | 0x6A => rowsLowByte6A_all_supported_rowsList
  | 0x6B => rowsLowByte6B_all_supported_rowsList
  | 0x6C => rowsLowByte6C_all_supported_rowsList
  | 0x6D => rowsLowByte6D_all_supported_rowsList
  | 0x6E => rowsLowByte6E_all_supported_rowsList
  | 0x6F => rowsLowByte6F_all_supported_rowsList
  | 0x70 => rowsLowByte70_all_supported_rowsList
  | 0x71 => rowsLowByte71_all_supported_rowsList
  | 0x72 => rowsLowByte72_all_supported_rowsList
  | 0x73 => rowsLowByte73_all_supported_rowsList
  | 0x74 => rowsLowByte74_all_supported_rowsList
  | 0x75 => rowsLowByte75_all_supported_rowsList
  | 0x76 => rowsLowByte76_all_supported_rowsList
  | 0x77 => rowsLowByte77_all_supported_rowsList
  | 0x78 => rowsLowByte78_all_supported_rowsList
  | 0x79 => rowsLowByte79_all_supported_rowsList
  | 0x7A => rowsLowByte7A_all_supported_rowsList
  | 0x7B => rowsLowByte7B_all_supported_rowsList
  | 0x7C => rowsLowByte7C_all_supported_rowsList
  | 0x7D => rowsLowByte7D_all_supported_rowsList
  | 0x7E => rowsLowByte7E_all_supported_rowsList
  | 0x7F => rowsLowByte7F_all_supported_rowsList
  | 0x80 => rowsLowByte80_all_supported_rowsList
  | 0x81 => rowsLowByte81_all_supported_rowsList
  | 0x82 => rowsLowByte82_all_supported_rowsList
  | 0x83 => rowsLowByte83_all_supported_rowsList
  | 0x84 => rowsLowByte84_all_supported_rowsList
  | 0x85 => rowsLowByte85_all_supported_rowsList
  | 0x86 => rowsLowByte86_all_supported_rowsList
  | 0x87 => rowsLowByte87_all_supported_rowsList
  | 0x88 => rowsLowByte88_all_supported_rowsList
  | 0x89 => rowsLowByte89_all_supported_rowsList
  | 0x8A => rowsLowByte8A_all_supported_rowsList
  | 0x8B => rowsLowByte8B_all_supported_rowsList
  | 0x8C => rowsLowByte8C_all_supported_rowsList
  | 0x8D => rowsLowByte8D_all_supported_rowsList
  | 0x8E => rowsLowByte8E_all_supported_rowsList
  | 0x8F => rowsLowByte8F_all_supported_rowsList
  | 0x90 => rowsLowByte90_all_supported_rowsList
  | 0x91 => rowsLowByte91_all_supported_rowsList
  | 0x92 => rowsLowByte92_all_supported_rowsList
  | 0x93 => rowsLowByte93_all_supported_rowsList
  | 0x94 => rowsLowByte94_all_supported_rowsList
  | 0x95 => rowsLowByte95_all_supported_rowsList
  | 0x96 => rowsLowByte96_all_supported_rowsList
  | 0x97 => rowsLowByte97_all_supported_rowsList
  | 0x98 => rowsLowByte98_all_supported_rowsList
  | 0x99 => rowsLowByte99_all_supported_rowsList
  | 0x9A => rowsLowByte9A_all_supported_rowsList
  | 0x9B => rowsLowByte9B_all_supported_rowsList
  | 0x9C => rowsLowByte9C_all_supported_rowsList
  | 0x9D => rowsLowByte9D_all_supported_rowsList
  | 0x9E => rowsLowByte9E_all_supported_rowsList
  | 0x9F => rowsLowByte9F_all_supported_rowsList
  | 0xA0 => rowsLowByteA0_all_supported_rowsList
  | 0xA1 => rowsLowByteA1_all_supported_rowsList
  | 0xA2 => rowsLowByteA2_all_supported_rowsList
  | 0xA3 => rowsLowByteA3_all_supported_rowsList
  | 0xA4 => rowsLowByteA4_all_supported_rowsList
  | 0xA5 => rowsLowByteA5_all_supported_rowsList
  | 0xA6 => rowsLowByteA6_all_supported_rowsList
  | 0xA7 => rowsLowByteA7_all_supported_rowsList
  | 0xA8 => rowsLowByteA8_all_supported_rowsList
  | 0xA9 => rowsLowByteA9_all_supported_rowsList
  | 0xAA => rowsLowByteAA_all_supported_rowsList
  | 0xAB => rowsLowByteAB_all_supported_rowsList
  | 0xAC => rowsLowByteAC_all_supported_rowsList
  | 0xAD => rowsLowByteAD_all_supported_rowsList
  | 0xAE => rowsLowByteAE_all_supported_rowsList
  | 0xAF => rowsLowByteAF_all_supported_rowsList
  | 0xB0 => rowsLowByteB0_all_supported_rowsList
  | 0xB1 => rowsLowByteB1_all_supported_rowsList
  | 0xB2 => rowsLowByteB2_all_supported_rowsList
  | 0xB3 => rowsLowByteB3_all_supported_rowsList
  | 0xB4 => rowsLowByteB4_all_supported_rowsList
  | 0xB5 => rowsLowByteB5_all_supported_rowsList
  | 0xB6 => rowsLowByteB6_all_supported_rowsList
  | 0xB7 => rowsLowByteB7_all_supported_rowsList
  | 0xB8 => rowsLowByteB8_all_supported_rowsList
  | 0xB9 => rowsLowByteB9_all_supported_rowsList
  | 0xBA => rowsLowByteBA_all_supported_rowsList
  | 0xBB => rowsLowByteBB_all_supported_rowsList
  | 0xBC => rowsLowByteBC_all_supported_rowsList
  | 0xBD => rowsLowByteBD_all_supported_rowsList
  | 0xBE => rowsLowByteBE_all_supported_rowsList
  | 0xBF => rowsLowByteBF_all_supported_rowsList
  | 0xC0 => rowsLowByteC0_all_supported_rowsList
  | 0xC1 => rowsLowByteC1_all_supported_rowsList
  | 0xC2 => rowsLowByteC2_all_supported_rowsList
  | 0xC3 => rowsLowByteC3_all_supported_rowsList
  | 0xC4 => rowsLowByteC4_all_supported_rowsList
  | 0xC5 => rowsLowByteC5_all_supported_rowsList
  | 0xC6 => rowsLowByteC6_all_supported_rowsList
  | 0xC7 => rowsLowByteC7_all_supported_rowsList
  | 0xC8 => rowsLowByteC8_all_supported_rowsList
  | 0xC9 => rowsLowByteC9_all_supported_rowsList
  | 0xCA => rowsLowByteCA_all_supported_rowsList
  | 0xCB => rowsLowByteCB_all_supported_rowsList
  | 0xCC => rowsLowByteCC_all_supported_rowsList
  | 0xCD => rowsLowByteCD_all_supported_rowsList
  | 0xCE => rowsLowByteCE_all_supported_rowsList
  | 0xCF => rowsLowByteCF_all_supported_rowsList
  | 0xD0 => rowsLowByteD0_all_supported_rowsList
  | 0xD1 => rowsLowByteD1_all_supported_rowsList
  | 0xD2 => rowsLowByteD2_all_supported_rowsList
  | 0xD3 => rowsLowByteD3_all_supported_rowsList
  | 0xD4 => rowsLowByteD4_all_supported_rowsList
  | 0xD5 => rowsLowByteD5_all_supported_rowsList
  | 0xD6 => rowsLowByteD6_all_supported_rowsList
  | 0xD7 => rowsLowByteD7_all_supported_rowsList
  | 0xD8 => rowsLowByteD8_all_supported_rowsList
  | 0xD9 => rowsLowByteD9_all_supported_rowsList
  | 0xDA => rowsLowByteDA_all_supported_rowsList
  | 0xDB => rowsLowByteDB_all_supported_rowsList
  | 0xDC => rowsLowByteDC_all_supported_rowsList
  | 0xDD => rowsLowByteDD_all_supported_rowsList
  | 0xDE => rowsLowByteDE_all_supported_rowsList
  | 0xDF => rowsLowByteDF_all_supported_rowsList
  | 0xE0 => rowsLowByteE0_all_supported_rowsList
  | 0xE1 => rowsLowByteE1_all_supported_rowsList
  | 0xE2 => rowsLowByteE2_all_supported_rowsList
  | 0xE3 => rowsLowByteE3_all_supported_rowsList
  | 0xE4 => rowsLowByteE4_all_supported_rowsList
  | 0xE5 => rowsLowByteE5_all_supported_rowsList
  | 0xE6 => rowsLowByteE6_all_supported_rowsList
  | 0xE7 => rowsLowByteE7_all_supported_rowsList
  | 0xE8 => rowsLowByteE8_all_supported_rowsList
  | 0xE9 => rowsLowByteE9_all_supported_rowsList
  | 0xEA => rowsLowByteEA_all_supported_rowsList
  | 0xEB => rowsLowByteEB_all_supported_rowsList
  | 0xEC => rowsLowByteEC_all_supported_rowsList
  | 0xED => rowsLowByteED_all_supported_rowsList
  | 0xEE => rowsLowByteEE_all_supported_rowsList
  | 0xEF => rowsLowByteEF_all_supported_rowsList
  | 0xF0 => rowsLowByteF0_all_supported_rowsList
  | 0xF1 => rowsLowByteF1_all_supported_rowsList
  | 0xF2 => rowsLowByteF2_all_supported_rowsList
  | 0xF3 => rowsLowByteF3_all_supported_rowsList
  | 0xF4 => rowsLowByteF4_all_supported_rowsList
  | 0xF5 => rowsLowByteF5_all_supported_rowsList
  | 0xF6 => rowsLowByteF6_all_supported_rowsList
  | 0xF7 => rowsLowByteF7_all_supported_rowsList
  | 0xF8 => rowsLowByteF8_all_supported_rowsList
  | 0xF9 => rowsLowByteF9_all_supported_rowsList
  | 0xFA => rowsLowByteFA_all_supported_rowsList
  | 0xFB => rowsLowByteFB_all_supported_rowsList
  | 0xFC => rowsLowByteFC_all_supported_rowsList
  | 0xFD => rowsLowByteFD_all_supported_rowsList
  | 0xFE => rowsLowByteFE_all_supported_rowsList
  | 0xFF => rowsLowByteFF_all_supported_rowsList
  | low + 256 => by rfl

theorem rowsList_all_codepoint_mem_rowBucket : ∀ low : Nat,
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = low →
        (rowBucketByLowByte low).any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true
  | 0x00 => rowsList_all_codepoint_mem_rowsLowByte00
  | 0x01 => rowsList_all_codepoint_mem_rowsLowByte01
  | 0x02 => rowsList_all_codepoint_mem_rowsLowByte02
  | 0x03 => rowsList_all_codepoint_mem_rowsLowByte03
  | 0x04 => rowsList_all_codepoint_mem_rowsLowByte04
  | 0x05 => rowsList_all_codepoint_mem_rowsLowByte05
  | 0x06 => rowsList_all_codepoint_mem_rowsLowByte06
  | 0x07 => rowsList_all_codepoint_mem_rowsLowByte07
  | 0x08 => rowsList_all_codepoint_mem_rowsLowByte08
  | 0x09 => rowsList_all_codepoint_mem_rowsLowByte09
  | 0x0A => rowsList_all_codepoint_mem_rowsLowByte0A
  | 0x0B => rowsList_all_codepoint_mem_rowsLowByte0B
  | 0x0C => rowsList_all_codepoint_mem_rowsLowByte0C
  | 0x0D => rowsList_all_codepoint_mem_rowsLowByte0D
  | 0x0E => rowsList_all_codepoint_mem_rowsLowByte0E
  | 0x0F => rowsList_all_codepoint_mem_rowsLowByte0F
  | 0x10 => rowsList_all_codepoint_mem_rowsLowByte10
  | 0x11 => rowsList_all_codepoint_mem_rowsLowByte11
  | 0x12 => rowsList_all_codepoint_mem_rowsLowByte12
  | 0x13 => rowsList_all_codepoint_mem_rowsLowByte13
  | 0x14 => rowsList_all_codepoint_mem_rowsLowByte14
  | 0x15 => rowsList_all_codepoint_mem_rowsLowByte15
  | 0x16 => rowsList_all_codepoint_mem_rowsLowByte16
  | 0x17 => rowsList_all_codepoint_mem_rowsLowByte17
  | 0x18 => rowsList_all_codepoint_mem_rowsLowByte18
  | 0x19 => rowsList_all_codepoint_mem_rowsLowByte19
  | 0x1A => rowsList_all_codepoint_mem_rowsLowByte1A
  | 0x1B => rowsList_all_codepoint_mem_rowsLowByte1B
  | 0x1C => rowsList_all_codepoint_mem_rowsLowByte1C
  | 0x1D => rowsList_all_codepoint_mem_rowsLowByte1D
  | 0x1E => rowsList_all_codepoint_mem_rowsLowByte1E
  | 0x1F => rowsList_all_codepoint_mem_rowsLowByte1F
  | 0x20 => rowsList_all_codepoint_mem_rowsLowByte20
  | 0x21 => rowsList_all_codepoint_mem_rowsLowByte21
  | 0x22 => rowsList_all_codepoint_mem_rowsLowByte22
  | 0x23 => rowsList_all_codepoint_mem_rowsLowByte23
  | 0x24 => rowsList_all_codepoint_mem_rowsLowByte24
  | 0x25 => rowsList_all_codepoint_mem_rowsLowByte25
  | 0x26 => rowsList_all_codepoint_mem_rowsLowByte26
  | 0x27 => rowsList_all_codepoint_mem_rowsLowByte27
  | 0x28 => rowsList_all_codepoint_mem_rowsLowByte28
  | 0x29 => rowsList_all_codepoint_mem_rowsLowByte29
  | 0x2A => rowsList_all_codepoint_mem_rowsLowByte2A
  | 0x2B => rowsList_all_codepoint_mem_rowsLowByte2B
  | 0x2C => rowsList_all_codepoint_mem_rowsLowByte2C
  | 0x2D => rowsList_all_codepoint_mem_rowsLowByte2D
  | 0x2E => rowsList_all_codepoint_mem_rowsLowByte2E
  | 0x2F => rowsList_all_codepoint_mem_rowsLowByte2F
  | 0x30 => rowsList_all_codepoint_mem_rowsLowByte30
  | 0x31 => rowsList_all_codepoint_mem_rowsLowByte31
  | 0x32 => rowsList_all_codepoint_mem_rowsLowByte32
  | 0x33 => rowsList_all_codepoint_mem_rowsLowByte33
  | 0x34 => rowsList_all_codepoint_mem_rowsLowByte34
  | 0x35 => rowsList_all_codepoint_mem_rowsLowByte35
  | 0x36 => rowsList_all_codepoint_mem_rowsLowByte36
  | 0x37 => rowsList_all_codepoint_mem_rowsLowByte37
  | 0x38 => rowsList_all_codepoint_mem_rowsLowByte38
  | 0x39 => rowsList_all_codepoint_mem_rowsLowByte39
  | 0x3A => rowsList_all_codepoint_mem_rowsLowByte3A
  | 0x3B => rowsList_all_codepoint_mem_rowsLowByte3B
  | 0x3C => rowsList_all_codepoint_mem_rowsLowByte3C
  | 0x3D => rowsList_all_codepoint_mem_rowsLowByte3D
  | 0x3E => rowsList_all_codepoint_mem_rowsLowByte3E
  | 0x3F => rowsList_all_codepoint_mem_rowsLowByte3F
  | 0x40 => rowsList_all_codepoint_mem_rowsLowByte40
  | 0x41 => rowsList_all_codepoint_mem_rowsLowByte41
  | 0x42 => rowsList_all_codepoint_mem_rowsLowByte42
  | 0x43 => rowsList_all_codepoint_mem_rowsLowByte43
  | 0x44 => rowsList_all_codepoint_mem_rowsLowByte44
  | 0x45 => rowsList_all_codepoint_mem_rowsLowByte45
  | 0x46 => rowsList_all_codepoint_mem_rowsLowByte46
  | 0x47 => rowsList_all_codepoint_mem_rowsLowByte47
  | 0x48 => rowsList_all_codepoint_mem_rowsLowByte48
  | 0x49 => rowsList_all_codepoint_mem_rowsLowByte49
  | 0x4A => rowsList_all_codepoint_mem_rowsLowByte4A
  | 0x4B => rowsList_all_codepoint_mem_rowsLowByte4B
  | 0x4C => rowsList_all_codepoint_mem_rowsLowByte4C
  | 0x4D => rowsList_all_codepoint_mem_rowsLowByte4D
  | 0x4E => rowsList_all_codepoint_mem_rowsLowByte4E
  | 0x4F => rowsList_all_codepoint_mem_rowsLowByte4F
  | 0x50 => rowsList_all_codepoint_mem_rowsLowByte50
  | 0x51 => rowsList_all_codepoint_mem_rowsLowByte51
  | 0x52 => rowsList_all_codepoint_mem_rowsLowByte52
  | 0x53 => rowsList_all_codepoint_mem_rowsLowByte53
  | 0x54 => rowsList_all_codepoint_mem_rowsLowByte54
  | 0x55 => rowsList_all_codepoint_mem_rowsLowByte55
  | 0x56 => rowsList_all_codepoint_mem_rowsLowByte56
  | 0x57 => rowsList_all_codepoint_mem_rowsLowByte57
  | 0x58 => rowsList_all_codepoint_mem_rowsLowByte58
  | 0x59 => rowsList_all_codepoint_mem_rowsLowByte59
  | 0x5A => rowsList_all_codepoint_mem_rowsLowByte5A
  | 0x5B => rowsList_all_codepoint_mem_rowsLowByte5B
  | 0x5C => rowsList_all_codepoint_mem_rowsLowByte5C
  | 0x5D => rowsList_all_codepoint_mem_rowsLowByte5D
  | 0x5E => rowsList_all_codepoint_mem_rowsLowByte5E
  | 0x5F => rowsList_all_codepoint_mem_rowsLowByte5F
  | 0x60 => rowsList_all_codepoint_mem_rowsLowByte60
  | 0x61 => rowsList_all_codepoint_mem_rowsLowByte61
  | 0x62 => rowsList_all_codepoint_mem_rowsLowByte62
  | 0x63 => rowsList_all_codepoint_mem_rowsLowByte63
  | 0x64 => rowsList_all_codepoint_mem_rowsLowByte64
  | 0x65 => rowsList_all_codepoint_mem_rowsLowByte65
  | 0x66 => rowsList_all_codepoint_mem_rowsLowByte66
  | 0x67 => rowsList_all_codepoint_mem_rowsLowByte67
  | 0x68 => rowsList_all_codepoint_mem_rowsLowByte68
  | 0x69 => rowsList_all_codepoint_mem_rowsLowByte69
  | 0x6A => rowsList_all_codepoint_mem_rowsLowByte6A
  | 0x6B => rowsList_all_codepoint_mem_rowsLowByte6B
  | 0x6C => rowsList_all_codepoint_mem_rowsLowByte6C
  | 0x6D => rowsList_all_codepoint_mem_rowsLowByte6D
  | 0x6E => rowsList_all_codepoint_mem_rowsLowByte6E
  | 0x6F => rowsList_all_codepoint_mem_rowsLowByte6F
  | 0x70 => rowsList_all_codepoint_mem_rowsLowByte70
  | 0x71 => rowsList_all_codepoint_mem_rowsLowByte71
  | 0x72 => rowsList_all_codepoint_mem_rowsLowByte72
  | 0x73 => rowsList_all_codepoint_mem_rowsLowByte73
  | 0x74 => rowsList_all_codepoint_mem_rowsLowByte74
  | 0x75 => rowsList_all_codepoint_mem_rowsLowByte75
  | 0x76 => rowsList_all_codepoint_mem_rowsLowByte76
  | 0x77 => rowsList_all_codepoint_mem_rowsLowByte77
  | 0x78 => rowsList_all_codepoint_mem_rowsLowByte78
  | 0x79 => rowsList_all_codepoint_mem_rowsLowByte79
  | 0x7A => rowsList_all_codepoint_mem_rowsLowByte7A
  | 0x7B => rowsList_all_codepoint_mem_rowsLowByte7B
  | 0x7C => rowsList_all_codepoint_mem_rowsLowByte7C
  | 0x7D => rowsList_all_codepoint_mem_rowsLowByte7D
  | 0x7E => rowsList_all_codepoint_mem_rowsLowByte7E
  | 0x7F => rowsList_all_codepoint_mem_rowsLowByte7F
  | 0x80 => rowsList_all_codepoint_mem_rowsLowByte80
  | 0x81 => rowsList_all_codepoint_mem_rowsLowByte81
  | 0x82 => rowsList_all_codepoint_mem_rowsLowByte82
  | 0x83 => rowsList_all_codepoint_mem_rowsLowByte83
  | 0x84 => rowsList_all_codepoint_mem_rowsLowByte84
  | 0x85 => rowsList_all_codepoint_mem_rowsLowByte85
  | 0x86 => rowsList_all_codepoint_mem_rowsLowByte86
  | 0x87 => rowsList_all_codepoint_mem_rowsLowByte87
  | 0x88 => rowsList_all_codepoint_mem_rowsLowByte88
  | 0x89 => rowsList_all_codepoint_mem_rowsLowByte89
  | 0x8A => rowsList_all_codepoint_mem_rowsLowByte8A
  | 0x8B => rowsList_all_codepoint_mem_rowsLowByte8B
  | 0x8C => rowsList_all_codepoint_mem_rowsLowByte8C
  | 0x8D => rowsList_all_codepoint_mem_rowsLowByte8D
  | 0x8E => rowsList_all_codepoint_mem_rowsLowByte8E
  | 0x8F => rowsList_all_codepoint_mem_rowsLowByte8F
  | 0x90 => rowsList_all_codepoint_mem_rowsLowByte90
  | 0x91 => rowsList_all_codepoint_mem_rowsLowByte91
  | 0x92 => rowsList_all_codepoint_mem_rowsLowByte92
  | 0x93 => rowsList_all_codepoint_mem_rowsLowByte93
  | 0x94 => rowsList_all_codepoint_mem_rowsLowByte94
  | 0x95 => rowsList_all_codepoint_mem_rowsLowByte95
  | 0x96 => rowsList_all_codepoint_mem_rowsLowByte96
  | 0x97 => rowsList_all_codepoint_mem_rowsLowByte97
  | 0x98 => rowsList_all_codepoint_mem_rowsLowByte98
  | 0x99 => rowsList_all_codepoint_mem_rowsLowByte99
  | 0x9A => rowsList_all_codepoint_mem_rowsLowByte9A
  | 0x9B => rowsList_all_codepoint_mem_rowsLowByte9B
  | 0x9C => rowsList_all_codepoint_mem_rowsLowByte9C
  | 0x9D => rowsList_all_codepoint_mem_rowsLowByte9D
  | 0x9E => rowsList_all_codepoint_mem_rowsLowByte9E
  | 0x9F => rowsList_all_codepoint_mem_rowsLowByte9F
  | 0xA0 => rowsList_all_codepoint_mem_rowsLowByteA0
  | 0xA1 => rowsList_all_codepoint_mem_rowsLowByteA1
  | 0xA2 => rowsList_all_codepoint_mem_rowsLowByteA2
  | 0xA3 => rowsList_all_codepoint_mem_rowsLowByteA3
  | 0xA4 => rowsList_all_codepoint_mem_rowsLowByteA4
  | 0xA5 => rowsList_all_codepoint_mem_rowsLowByteA5
  | 0xA6 => rowsList_all_codepoint_mem_rowsLowByteA6
  | 0xA7 => rowsList_all_codepoint_mem_rowsLowByteA7
  | 0xA8 => rowsList_all_codepoint_mem_rowsLowByteA8
  | 0xA9 => rowsList_all_codepoint_mem_rowsLowByteA9
  | 0xAA => rowsList_all_codepoint_mem_rowsLowByteAA
  | 0xAB => rowsList_all_codepoint_mem_rowsLowByteAB
  | 0xAC => rowsList_all_codepoint_mem_rowsLowByteAC
  | 0xAD => rowsList_all_codepoint_mem_rowsLowByteAD
  | 0xAE => rowsList_all_codepoint_mem_rowsLowByteAE
  | 0xAF => rowsList_all_codepoint_mem_rowsLowByteAF
  | 0xB0 => rowsList_all_codepoint_mem_rowsLowByteB0
  | 0xB1 => rowsList_all_codepoint_mem_rowsLowByteB1
  | 0xB2 => rowsList_all_codepoint_mem_rowsLowByteB2
  | 0xB3 => rowsList_all_codepoint_mem_rowsLowByteB3
  | 0xB4 => rowsList_all_codepoint_mem_rowsLowByteB4
  | 0xB5 => rowsList_all_codepoint_mem_rowsLowByteB5
  | 0xB6 => rowsList_all_codepoint_mem_rowsLowByteB6
  | 0xB7 => rowsList_all_codepoint_mem_rowsLowByteB7
  | 0xB8 => rowsList_all_codepoint_mem_rowsLowByteB8
  | 0xB9 => rowsList_all_codepoint_mem_rowsLowByteB9
  | 0xBA => rowsList_all_codepoint_mem_rowsLowByteBA
  | 0xBB => rowsList_all_codepoint_mem_rowsLowByteBB
  | 0xBC => rowsList_all_codepoint_mem_rowsLowByteBC
  | 0xBD => rowsList_all_codepoint_mem_rowsLowByteBD
  | 0xBE => rowsList_all_codepoint_mem_rowsLowByteBE
  | 0xBF => rowsList_all_codepoint_mem_rowsLowByteBF
  | 0xC0 => rowsList_all_codepoint_mem_rowsLowByteC0
  | 0xC1 => rowsList_all_codepoint_mem_rowsLowByteC1
  | 0xC2 => rowsList_all_codepoint_mem_rowsLowByteC2
  | 0xC3 => rowsList_all_codepoint_mem_rowsLowByteC3
  | 0xC4 => rowsList_all_codepoint_mem_rowsLowByteC4
  | 0xC5 => rowsList_all_codepoint_mem_rowsLowByteC5
  | 0xC6 => rowsList_all_codepoint_mem_rowsLowByteC6
  | 0xC7 => rowsList_all_codepoint_mem_rowsLowByteC7
  | 0xC8 => rowsList_all_codepoint_mem_rowsLowByteC8
  | 0xC9 => rowsList_all_codepoint_mem_rowsLowByteC9
  | 0xCA => rowsList_all_codepoint_mem_rowsLowByteCA
  | 0xCB => rowsList_all_codepoint_mem_rowsLowByteCB
  | 0xCC => rowsList_all_codepoint_mem_rowsLowByteCC
  | 0xCD => rowsList_all_codepoint_mem_rowsLowByteCD
  | 0xCE => rowsList_all_codepoint_mem_rowsLowByteCE
  | 0xCF => rowsList_all_codepoint_mem_rowsLowByteCF
  | 0xD0 => rowsList_all_codepoint_mem_rowsLowByteD0
  | 0xD1 => rowsList_all_codepoint_mem_rowsLowByteD1
  | 0xD2 => rowsList_all_codepoint_mem_rowsLowByteD2
  | 0xD3 => rowsList_all_codepoint_mem_rowsLowByteD3
  | 0xD4 => rowsList_all_codepoint_mem_rowsLowByteD4
  | 0xD5 => rowsList_all_codepoint_mem_rowsLowByteD5
  | 0xD6 => rowsList_all_codepoint_mem_rowsLowByteD6
  | 0xD7 => rowsList_all_codepoint_mem_rowsLowByteD7
  | 0xD8 => rowsList_all_codepoint_mem_rowsLowByteD8
  | 0xD9 => rowsList_all_codepoint_mem_rowsLowByteD9
  | 0xDA => rowsList_all_codepoint_mem_rowsLowByteDA
  | 0xDB => rowsList_all_codepoint_mem_rowsLowByteDB
  | 0xDC => rowsList_all_codepoint_mem_rowsLowByteDC
  | 0xDD => rowsList_all_codepoint_mem_rowsLowByteDD
  | 0xDE => rowsList_all_codepoint_mem_rowsLowByteDE
  | 0xDF => rowsList_all_codepoint_mem_rowsLowByteDF
  | 0xE0 => rowsList_all_codepoint_mem_rowsLowByteE0
  | 0xE1 => rowsList_all_codepoint_mem_rowsLowByteE1
  | 0xE2 => rowsList_all_codepoint_mem_rowsLowByteE2
  | 0xE3 => rowsList_all_codepoint_mem_rowsLowByteE3
  | 0xE4 => rowsList_all_codepoint_mem_rowsLowByteE4
  | 0xE5 => rowsList_all_codepoint_mem_rowsLowByteE5
  | 0xE6 => rowsList_all_codepoint_mem_rowsLowByteE6
  | 0xE7 => rowsList_all_codepoint_mem_rowsLowByteE7
  | 0xE8 => rowsList_all_codepoint_mem_rowsLowByteE8
  | 0xE9 => rowsList_all_codepoint_mem_rowsLowByteE9
  | 0xEA => rowsList_all_codepoint_mem_rowsLowByteEA
  | 0xEB => rowsList_all_codepoint_mem_rowsLowByteEB
  | 0xEC => rowsList_all_codepoint_mem_rowsLowByteEC
  | 0xED => rowsList_all_codepoint_mem_rowsLowByteED
  | 0xEE => rowsList_all_codepoint_mem_rowsLowByteEE
  | 0xEF => rowsList_all_codepoint_mem_rowsLowByteEF
  | 0xF0 => rowsList_all_codepoint_mem_rowsLowByteF0
  | 0xF1 => rowsList_all_codepoint_mem_rowsLowByteF1
  | 0xF2 => rowsList_all_codepoint_mem_rowsLowByteF2
  | 0xF3 => rowsList_all_codepoint_mem_rowsLowByteF3
  | 0xF4 => rowsList_all_codepoint_mem_rowsLowByteF4
  | 0xF5 => rowsList_all_codepoint_mem_rowsLowByteF5
  | 0xF6 => rowsList_all_codepoint_mem_rowsLowByteF6
  | 0xF7 => rowsList_all_codepoint_mem_rowsLowByteF7
  | 0xF8 => rowsList_all_codepoint_mem_rowsLowByteF8
  | 0xF9 => rowsList_all_codepoint_mem_rowsLowByteF9
  | 0xFA => rowsList_all_codepoint_mem_rowsLowByteFA
  | 0xFB => rowsList_all_codepoint_mem_rowsLowByteFB
  | 0xFC => rowsList_all_codepoint_mem_rowsLowByteFC
  | 0xFD => rowsList_all_codepoint_mem_rowsLowByteFD
  | 0xFE => rowsList_all_codepoint_mem_rowsLowByteFE
  | 0xFF => rowsList_all_codepoint_mem_rowsLowByteFF
  | low + 256 => by
      rw [List.all_eq_true]
      intro row _hrow
      apply decide_eq_true
      intro hLow
      have hMod : row.codepoint % 256 < 256 := Nat.mod_lt row.codepoint (by decide)
      omega

theorem lookupRow?_codepoint {cp : Nat} {row : UnicodeDataRow}
    (h : lookupRow? cp = some row) : row.codepoint = cp := by
  unfold lookupRow? at h
  exact of_decide_eq_true
    (List.find?_some
      (p := fun (row : UnicodeDataRow) => decide (row.codepoint = cp)) h)

theorem lookupRow?_supported_rowsList {cp : Nat} {row : UnicodeDataRow}
    (h : lookupRow? cp = some row) :
    ∃ src, src ∈ UnicodeData.rowsList ∧
      src.codepoint = row.codepoint ∧
      src.canonicalCombiningClass = row.canonicalCombiningClass ∧
      src.canonicalDecomposition = row.canonicalDecomposition := by
  unfold lookupRow? at h
  have hMemBucket : row ∈ rowBucketByLowByte (cp % 256) :=
    List.mem_of_find?_eq_some h
  have hAll := rowBucket_all_supported_rowsList (cp % 256)
  have hAny := List.all_eq_true.mp hAll row hMemBucket
  rw [List.any_eq_true] at hAny
  obtain ⟨src, hSrcMem, hSrcFieldsBool⟩ := hAny
  exact ⟨src, hSrcMem, of_decide_eq_true hSrcFieldsBool⟩

theorem rowsList_codepoint_mem_rowBucket {cp : Nat} {row : UnicodeDataRow}
    (hMem : row ∈ UnicodeData.rowsList) (hCp : row.codepoint = cp) :
    (rowBucketByLowByte (cp % 256)).any
      (fun indexed => decide (indexed.codepoint = cp)) = true := by
  have hAll := rowsList_all_codepoint_mem_rowBucket (cp % 256)
  have hImp : row.codepoint % 256 = cp % 256 →
      (rowBucketByLowByte (cp % 256)).any
        (fun indexed => decide (indexed.codepoint = row.codepoint)) = true :=
    of_decide_eq_true (List.all_eq_true.mp hAll row hMem)
  have hAny := hImp (by rw [hCp])
  simpa [hCp] using hAny

theorem lookupRow?_none_no_rowsList_codepoint {cp : Nat} {row : UnicodeDataRow}
    (h : lookupRow? cp = none) (hMem : row ∈ UnicodeData.rowsList) :
    row.codepoint ≠ cp := by
  intro hCp
  unfold lookupRow? at h
  rw [List.find?_eq_none] at h
  have hAny := rowsList_codepoint_mem_rowBucket hMem hCp
  rw [List.any_eq_true] at hAny
  obtain ⟨indexed, hIndexedMem, hIndexedCpBool⟩ := hAny
  have hFalse := h indexed hIndexedMem
  exact hFalse hIndexedCpBool

end Unicode.Generated.UnicodeDataIndex
