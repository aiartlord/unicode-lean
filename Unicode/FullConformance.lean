/-
  Unicode.FullConformance

  Explicit evidence root for the heavyweight official Unicode conformance
  suites. This root imports `Unicode.Assurance` and then demands the larger
  fixture-backed proofs that are too costly for routine edit/build cycles under
  Lean 4.30.0.
-/

import Unicode.Assurance

-- UAX #15 conformance — official NormalizationTest.txt against
-- toNFC / toNFD / toNFKC / toNFKD across all six @Part sections.
import Unicode.Conformance.NormalizationTest

-- UAX #9 conformance — official BidiTest.txt level + L1/L2 reorder
-- across all paragraph-level settings.
import Unicode.Conformance.BidiTest
import Unicode.Conformance.BidiCharacterTest

-- UAX #14 / #29 conformance — official break-test fixtures.
import Unicode.Conformance.LineBreakTest
import Unicode.Conformance.GraphemeBreakTest
import Unicode.Conformance.WordBreakTest
import Unicode.Conformance.SentenceBreakTest

-- The same four suites run over every row their files publish rather than over
-- a materialized selection. Each module's gate fails the build on a single
-- disagreeing row, and on a tally that does not account for the whole file.
import Unicode.Conformance.BidiTestRun
import Unicode.Conformance.BidiCharacterTestRun
import Unicode.Conformance.NormalizationTestRun
import Unicode.Conformance.BreakTestRun

-- UCA — `ucaCompare` against representative pairs and the reflexivity of the
-- collation order over all inputs. The full-corpus order check lives in
-- `CollationTestRun`, whose run is recorded by `scripts/conformance-execute.sh`
-- rather than elaborated here; that module states why.
import Unicode.Conformance.CollationTest
import Unicode.Conformance.CollationTestRun

-- UTS #46 conformance — official IdnaTestV2.txt against
-- toUnicode / toAscii / toAsciiTransitional.
import Unicode.Conformance.IdnaTestV2

-- UTS #51 / security-layer curated fixtures.
import Unicode.Conformance.EmojiTest
import Unicode.Conformance.Security.AdmissibilityFormDriftTest
import Unicode.Conformance.Security.AiWatermarkDetectabilityTest
import Unicode.Conformance.Security.BidiControlBalanceTest
import Unicode.Conformance.Security.NoncharacterControlTest
import Unicode.Conformance.Security.Bip39CanonicalTest
import Unicode.Conformance.Security.CaseExpansionMismatchTest
import Unicode.Conformance.Security.ConfusableBidiCompoundTest
import Unicode.Conformance.Security.CovertDisplayCompoundTest
import Unicode.Conformance.Security.EmojiZwjIntegrityTest
import Unicode.Conformance.Security.FilenameDisguiseTest
import Unicode.Conformance.Security.HashInputStabilityTest
import Unicode.Conformance.Security.HomoglyphConfusableTest
import Unicode.Conformance.Security.IdentifierFormDriftTest
import Unicode.Conformance.Security.LocaleCaseInversionTest
import Unicode.Conformance.Security.MixedScriptAdmissibilityTest
import Unicode.Conformance.Security.NfcIdempotenceWitnessTest
import Unicode.Conformance.Security.NormalizationBombTest
import Unicode.Conformance.Security.RendererDivergenceTest
import Unicode.Conformance.Security.RtlInjectionTest
import Unicode.Conformance.Security.SkinToneVariationForgeryTest
import Unicode.Conformance.Security.SourceDisplayDivergenceTest
import Unicode.Conformance.Security.StreamSafeViolationTest
import Unicode.Conformance.Security.SurrogateReassemblyTest
import Unicode.Conformance.Security.TagBlockPayloadTest
import Unicode.Conformance.Security.VariationSelectorPayloadTest
import Unicode.Conformance.Security.WidthClassConfusionTest
import Unicode.Conformance.Security.ZeroWidthPayloadTest
