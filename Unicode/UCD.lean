/-
  Unicode.UCD

  Programmatic interface to the SHA-256 digests of bundled UCD
  source files. The manifest is emitted as literal data and each
  digest gets a small local length certificate so aggregate checks
  do not reduce an include-string parser.
-/

import Unicode.Sha256

namespace Unicode.UCD

/-- The UCD release pinned by this distribution. -/
def currentUcdVersion : String := "17.0.0"

def digestBidiBracketsTxt : String :=
  "dadbaf38a0d0246e5b805bf8725cb81b7c621f93d030595635f5ba2c2f179428"

theorem digestBidiBracketsTxtLength : digestBidiBracketsTxt.length = 64 := by decide

def digestBidiCharacterTestTxt : String :=
  "a3e6e905ab5afbe318a96df5401d0372a04cd73ef139ab5e3cf0ae241c255488"

theorem digestBidiCharacterTestTxtLength : digestBidiCharacterTestTxt.length = 64 := by decide

def digestBidiMirroringTxt : String :=
  "a2f16fb873ab4fcdf3221cb1a8a85a134ddd6ed03603181823ff5206af3741ce"

theorem digestBidiMirroringTxtLength : digestBidiMirroringTxt.length = 64 := by decide

def digestBidiTestTxt : String :=
  "888bdfc8090652272d1f859cdb00ae659e2dc6c26740be61ef1d03998a687620"

theorem digestBidiTestTxtLength : digestBidiTestTxt.length = 64 := by decide

def digestCaseFoldingTxt : String :=
  "ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183"

theorem digestCaseFoldingTxtLength : digestCaseFoldingTxt.length = 64 := by decide

def digestCompositionExclusionsTxt : String :=
  "2f239196ef3b5b61db5cc476e9bd80f534d15aa1b74e1be1dea5d042a344c85f"

theorem digestCompositionExclusionsTxtLength : digestCompositionExclusionsTxt.length = 64 := by decide

def digestConfusablesTxt : String :=
  "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a"

theorem digestConfusablesTxtLength : digestConfusablesTxt.length = 64 := by decide

def digestDerivedBidiClassTxt : String :=
  "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4"

theorem digestDerivedBidiClassTxtLength : digestDerivedBidiClassTxt.length = 64 := by decide

def digestDerivedCorePropertiesTxt : String :=
  "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08"

theorem digestDerivedCorePropertiesTxtLength : digestDerivedCorePropertiesTxt.length = 64 := by decide

def digestDerivedNormalizationPropsTxt : String :=
  "71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488"

theorem digestDerivedNormalizationPropsTxtLength : digestDerivedNormalizationPropsTxt.length = 64 := by decide

def digestEastAsianWidthTxt : String :=
  "ea7ce50f3444a050333448dffef1cadd9325af55cbb764b4a2280faf52170a33"

theorem digestEastAsianWidthTxtLength : digestEastAsianWidthTxt.length = 64 := by decide

def digestIdentifierStatusTxt : String :=
  "617228a16da13850bf8af28b6cd08f5e9b6595d2eb60404fe6eee2c85b4e4a35"

theorem digestIdentifierStatusTxtLength : digestIdentifierStatusTxt.length = 64 := by decide

def digestIdentifierTypeTxt : String :=
  "924ac63faa97ed73420d6ac48d08279d90968c7da0502ab701e08bfbb9683c22"

theorem digestIdentifierTypeTxtLength : digestIdentifierTypeTxt.length = 64 := by decide

def digestIdnaMappingTableTxt : String :=
  "87f05505dc026fdb2bff16132bdc68a8014675836882a9a2b1844540ad3be382"

theorem digestIdnaMappingTableTxtLength : digestIdnaMappingTableTxt.length = 64 := by decide

def digestMANIFESTTxt : String :=
  "43749980e2cff7bd16cb8cc2f0c1f9f272372586c91442e37184f241f2ef6098"

theorem digestMANIFESTTxtLength : digestMANIFESTTxt.length = 64 := by decide

def digestNormalizationTestTxt : String :=
  "5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db"

theorem digestNormalizationTestTxtLength : digestNormalizationTestTxt.length = 64 := by decide

def digestPropListTxt : String :=
  "130dcddcaadaf071008bdfce1e7743e04fdfbc910886f017d9f9ac931d8c64dd"

theorem digestPropListTxtLength : digestPropListTxt.length = 64 := by decide

def digestScriptExtensionsTxt : String :=
  "ec2107e58825a1586acee8e0911ce18260394ac8b87e535ca325f1ccbeb06bc6"

theorem digestScriptExtensionsTxtLength : digestScriptExtensionsTxt.length = 64 := by decide

def digestScriptsTxt : String :=
  "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf"

theorem digestScriptsTxtLength : digestScriptsTxt.length = 64 := by decide

def digestUnicodeDataTxt : String :=
  "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c"

theorem digestUnicodeDataTxtLength : digestUnicodeDataTxt.length = 64 := by decide

def digestLineBreakTxt : String :=
  "e6a18fa91f8f6a6f8e534b1d3f128c21ada45bfe152eb6b1bcc5e15fd8ac92e6"

theorem digestLineBreakTxtLength : digestLineBreakTxt.length = 64 := by decide

def digestLineBreakTestTxt : String :=
  "e69884e0dde6a8724873f885d68c52dc14518abf9ae4ca9e2283b8773db3b752"

theorem digestLineBreakTestTxtLength : digestLineBreakTestTxt.length = 64 := by decide

def digestGraphemeBreakPropertyTxt : String :=
  "d6b51d1d2ae5c33b451b7ed994b48f1f4dc62b2272a5831e7fd418514a6bae89"

theorem digestGraphemeBreakPropertyTxtLength : digestGraphemeBreakPropertyTxt.length = 64 := by decide

def digestGraphemeBreakTestTxt : String :=
  "e2d134d2c52919bace503ebb6a551c1855fe1a1faec18478c78fff254a1793ec"

theorem digestGraphemeBreakTestTxtLength : digestGraphemeBreakTestTxt.length = 64 := by decide

def digestWordBreakPropertyTxt : String :=
  "72274cac1e6b919507db35655c3e175aa27274668a1ece95c28d2069f2ad9852"

theorem digestWordBreakPropertyTxtLength : digestWordBreakPropertyTxt.length = 64 := by decide

def digestWordBreakTestTxt : String :=
  "1de23a75f37904abc7d206239ee8d34f8fdf0fb4ab32a7174dfbabbde25419b2"

theorem digestWordBreakTestTxtLength : digestWordBreakTestTxt.length = 64 := by decide

def digestSentenceBreakPropertyTxt : String :=
  "871c0c985ad95125e25b302414065a10839d068970bceb383ecec138f22a0a18"

theorem digestSentenceBreakPropertyTxtLength : digestSentenceBreakPropertyTxt.length = 64 := by decide

def digestSentenceBreakTestTxt : String :=
  "12cb47d028ded0c1cb8a28558f95479cbcd24559c46977015c82f3b50a1cc6e4"

theorem digestSentenceBreakTestTxtLength : digestSentenceBreakTestTxt.length = 64 := by decide

def digestEmojiDataTxt : String :=
  "2cb2bb9455cda83e8481541ecf5b6dfda66a3bb89efa3fa7c5297eccf607b72b"

theorem digestEmojiDataTxtLength : digestEmojiDataTxt.length = 64 := by decide

def digestAllkeysTxt : String :=
  "2503d09367c2639a4fb8fd55e81aaacb0d9fb4ea26600333329bd12456b99ecd"

theorem digestAllkeysTxtLength : digestAllkeysTxt.length = 64 := by decide

def digestCollationTestNONIGNORABLESHORTTxt : String :=
  "06a8d9d2191574c74623f66af960682feadeb714a9fa12ab4657c425f8683f53"

theorem digestCollationTestNONIGNORABLESHORTTxtLength : digestCollationTestNONIGNORABLESHORTTxt.length = 64 := by decide

def digestCollationTestNONIGNORABLETxt : String :=
  "6c43c92ea9c87fcefa94a2e362fb31fb0650d5c80ae420b46d9ccc02784a0c5f"

theorem digestCollationTestNONIGNORABLETxtLength : digestCollationTestNONIGNORABLETxt.length = 64 := by decide

def digestCollationTestSHIFTEDSHORTTxt : String :=
  "3ede425165f0faf776f8d702a4d65863c347e8948aea18778ef78a7f410897ad"

theorem digestCollationTestSHIFTEDSHORTTxtLength : digestCollationTestSHIFTEDSHORTTxt.length = 64 := by decide

def digestCollationTestSHIFTEDTxt : String :=
  "cbeecf871a3567e8229c869a1f7c36e777c077ee2be6470efe4fb17f01886d4b"

theorem digestCollationTestSHIFTEDTxtLength : digestCollationTestSHIFTEDTxt.length = 64 := by decide

def digestIdnaTestV2Txt : String :=
  "beb5d0be20e896189b03209a82fdc34f06351502bbd4b8e2523583fc2954d9cf"

theorem digestIdnaTestV2TxtLength : digestIdnaTestV2Txt.length = 64 := by decide

def digestDerivedJoiningTypeTxt : String :=
  "f39ebe974825d6736aee15582250307aa532b2cfab3caf3f86bd23fddc9c5c4d"

theorem digestDerivedJoiningTypeTxtLength : digestDerivedJoiningTypeTxt.length = 64 := by decide

def digestEmojiSequencesTxt : String :=
  "12cc8267dc33cbd11ed32bcf6fc5dc2ad9c7a77bae1bdfba2f41b1b9b3ead8dd"

theorem digestEmojiSequencesTxtLength : digestEmojiSequencesTxt.length = 64 := by decide

def digestEmojiZwjSequencesTxt : String :=
  "5b25441daed2322b068c5e70cda522946a4f0274df864445a1965a92e5fc5cad"

theorem digestEmojiZwjSequencesTxtLength : digestEmojiZwjSequencesTxt.length = 64 := by decide

def digestEmojiTestTxt : String :=
  "1d8a944f88d7952f7ef7c5167fef3c67995bcae24543949710231b03a201acda"

theorem digestEmojiTestTxtLength : digestEmojiTestTxt.length = 64 := by decide

def digestVerticalOrientationTxt : String :=
  "dcef09c3fb24d356b042569c328ec341efc5b53447700d799f2fb4834c3cd3cd"

theorem digestVerticalOrientationTxtLength : digestVerticalOrientationTxt.length = 64 := by decide

def digestUnihanVariantsTxt : String :=
  "3f23cd71872633f3350875d25bd388e83b60fa71807634c9a600ec26f38a68ab"

theorem digestUnihanVariantsTxtLength : digestUnihanVariantsTxt.length = 64 := by decide

def digestUnihanNumericValuesTxt : String :=
  "c8a6ef56aa4828a238cc4ed806d81ae9ea32ed39290359a64b9f493142b61b5e"

theorem digestUnihanNumericValuesTxtLength : digestUnihanNumericValuesTxt.length = 64 := by decide

def digestPropertyAliasesTxt : String :=
  "4441f573caf952ffece1d7c892e7715bd7136dfc26f96eb6f268bf1e474715fb"

theorem digestPropertyAliasesTxtLength : digestPropertyAliasesTxt.length = 64 := by decide

def digestPropertyValueAliasesTxt : String :=
  "64e9a5f76f7a1e8b5a47d6a1f9a26522a251208f5276bdfa1559dac7cf2e827a"

theorem digestPropertyValueAliasesTxtLength : digestPropertyValueAliasesTxt.length = 64 := by decide

def digestSpecialCasingTxt : String :=
  "efc25faf19de21b92c1194c111c932e03d2a5eaf18194e33f1156e96de4c9588"

theorem digestSpecialCasingTxtLength : digestSpecialCasingTxt.length = 64 := by decide

def digestStandardizedVariantsTxt : String :=
  "f55100b2fb11d3d75a37b8c1ab752192dbd1c4b12328c5ec6b38e3807c0ca597"

theorem digestStandardizedVariantsTxtLength : digestStandardizedVariantsTxt.length = 64 := by decide

def digestEmojiVariationSequencesTxt : String :=
  "bb3d09ef03f206012c7532dd52dc0a21c9efddba0135ea4cf0d9201b8b9bba7e"

theorem digestEmojiVariationSequencesTxtLength : digestEmojiVariationSequencesTxt.length = 64 := by decide

/-- All `(filename, expected SHA-256)` pairs, in manifest order. -/
def ucdFileDigests : List (String × String) := [
  ("BidiBrackets.txt", digestBidiBracketsTxt),
  ("BidiCharacterTest.txt", digestBidiCharacterTestTxt),
  ("BidiMirroring.txt", digestBidiMirroringTxt),
  ("BidiTest.txt", digestBidiTestTxt),
  ("CaseFolding.txt", digestCaseFoldingTxt),
  ("CompositionExclusions.txt", digestCompositionExclusionsTxt),
  ("confusables.txt", digestConfusablesTxt),
  ("DerivedBidiClass.txt", digestDerivedBidiClassTxt),
  ("DerivedCoreProperties.txt", digestDerivedCorePropertiesTxt),
  ("DerivedNormalizationProps.txt", digestDerivedNormalizationPropsTxt),
  ("EastAsianWidth.txt", digestEastAsianWidthTxt),
  ("IdentifierStatus.txt", digestIdentifierStatusTxt),
  ("IdentifierType.txt", digestIdentifierTypeTxt),
  ("IdnaMappingTable.txt", digestIdnaMappingTableTxt),
  ("MANIFEST.txt", digestMANIFESTTxt),
  ("NormalizationTest.txt", digestNormalizationTestTxt),
  ("PropList.txt", digestPropListTxt),
  ("ScriptExtensions.txt", digestScriptExtensionsTxt),
  ("Scripts.txt", digestScriptsTxt),
  ("UnicodeData.txt", digestUnicodeDataTxt),
  ("LineBreak.txt", digestLineBreakTxt),
  ("LineBreakTest.txt", digestLineBreakTestTxt),
  ("GraphemeBreakProperty.txt", digestGraphemeBreakPropertyTxt),
  ("GraphemeBreakTest.txt", digestGraphemeBreakTestTxt),
  ("WordBreakProperty.txt", digestWordBreakPropertyTxt),
  ("WordBreakTest.txt", digestWordBreakTestTxt),
  ("SentenceBreakProperty.txt", digestSentenceBreakPropertyTxt),
  ("SentenceBreakTest.txt", digestSentenceBreakTestTxt),
  ("emoji-data.txt", digestEmojiDataTxt),
  ("allkeys.txt", digestAllkeysTxt),
  ("CollationTest_NON_IGNORABLE_SHORT.txt", digestCollationTestNONIGNORABLESHORTTxt),
  ("CollationTest_NON_IGNORABLE.txt", digestCollationTestNONIGNORABLETxt),
  ("CollationTest_SHIFTED_SHORT.txt", digestCollationTestSHIFTEDSHORTTxt),
  ("CollationTest_SHIFTED.txt", digestCollationTestSHIFTEDTxt),
  ("IdnaTestV2.txt", digestIdnaTestV2Txt),
  ("DerivedJoiningType.txt", digestDerivedJoiningTypeTxt),
  ("emoji-sequences.txt", digestEmojiSequencesTxt),
  ("emoji-zwj-sequences.txt", digestEmojiZwjSequencesTxt),
  ("emoji-test.txt", digestEmojiTestTxt),
  ("VerticalOrientation.txt", digestVerticalOrientationTxt),
  ("Unihan_Variants.txt", digestUnihanVariantsTxt),
  ("Unihan_NumericValues.txt", digestUnihanNumericValuesTxt),
  ("PropertyAliases.txt", digestPropertyAliasesTxt),
  ("PropertyValueAliases.txt", digestPropertyValueAliasesTxt),
  ("SpecialCasing.txt", digestSpecialCasingTxt),
  ("StandardizedVariants.txt", digestStandardizedVariantsTxt),
  ("emoji-variation-sequences.txt", digestEmojiVariationSequencesTxt)
]

/-- Filenames of every UCD source file pinned in this distribution. -/
def expectedUcdFiles : List String :=
  ucdFileDigests.map (·.fst)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 SHAPE CHECKS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The trusted base pins 47 UCD source files. -/
theorem ucdFileDigests_count : ucdFileDigests.length = 47 := by decide

/-- Every digest entry has the expected 64-hex-character SHA-256 payload. -/
theorem ucdFileDigests_all_64 :
    ucdFileDigests.all (fun fh => fh.snd.length = 64) = true := by
  simp [ucdFileDigests, digestBidiBracketsTxtLength, digestBidiCharacterTestTxtLength, digestBidiMirroringTxtLength, digestBidiTestTxtLength, digestCaseFoldingTxtLength, digestCompositionExclusionsTxtLength, digestConfusablesTxtLength, digestDerivedBidiClassTxtLength, digestDerivedCorePropertiesTxtLength, digestDerivedNormalizationPropsTxtLength, digestEastAsianWidthTxtLength, digestIdentifierStatusTxtLength, digestIdentifierTypeTxtLength, digestIdnaMappingTableTxtLength, digestMANIFESTTxtLength, digestNormalizationTestTxtLength, digestPropListTxtLength, digestScriptExtensionsTxtLength, digestScriptsTxtLength, digestUnicodeDataTxtLength, digestLineBreakTxtLength, digestLineBreakTestTxtLength, digestGraphemeBreakPropertyTxtLength, digestGraphemeBreakTestTxtLength, digestWordBreakPropertyTxtLength, digestWordBreakTestTxtLength, digestSentenceBreakPropertyTxtLength, digestSentenceBreakTestTxtLength, digestEmojiDataTxtLength, digestAllkeysTxtLength, digestCollationTestNONIGNORABLESHORTTxtLength, digestCollationTestNONIGNORABLETxtLength, digestCollationTestSHIFTEDSHORTTxtLength, digestCollationTestSHIFTEDTxtLength, digestIdnaTestV2TxtLength, digestDerivedJoiningTypeTxtLength, digestEmojiSequencesTxtLength, digestEmojiZwjSequencesTxtLength, digestEmojiTestTxtLength, digestVerticalOrientationTxtLength, digestUnihanVariantsTxtLength, digestUnihanNumericValuesTxtLength, digestPropertyAliasesTxtLength, digestPropertyValueAliasesTxtLength, digestSpecialCasingTxtLength, digestStandardizedVariantsTxtLength, digestEmojiVariationSequencesTxtLength]

/-- Sanity check on the canonical `UnicodeData.txt` digest. -/
theorem ucdFileDigests_unicode_data :
    ucdFileDigests.find? (fun fh => fh.fst = "UnicodeData.txt")
      = some ("UnicodeData.txt",
              "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c") := by
  simp [ucdFileDigests, digestUnicodeDataTxt]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 INTEGRITY GATE
--
-- Compute the real SHA-256 (Unicode.Sha256) of every pinned UCD source file
-- and compare it against the recorded digest. A drifted, stale, or tampered
-- `.txt` changes its hash and aborts the build. This is the enforcement that
-- the per-digest length certificates above only gesture at: those prove each
-- digest string is 64 hex characters; this proves each digest is the actual
-- hash of the actual file.
-- ═══════════════════════════════════════════════════════════════════════════════

#eval show IO Unit from do
  for (name, expected) in ucdFileDigests do
    let bytes ← IO.FS.readBinFile s!"Unicode/Ucd/{name}"
    let actual := Sha256.hashHex bytes
    unless actual == expected do
      throw (IO.userError
        s!"UCD integrity gate: {name} hashes to {actual}, but the pinned digest is {expected}")

end Unicode.UCD
