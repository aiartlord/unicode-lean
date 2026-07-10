/-
  Unicode.FullConformance

  Explicit evidence root for the heavyweight official Unicode conformance
  suites. This root imports the default `Unicode` library surface and then
  demands the larger fixture-backed proofs that are too costly for routine
  edit/build cycles under Lean 4.30.0.
-/

import Unicode

-- UAX #15 conformance — official NormalizationTest.txt against
-- toNFC / toNFD / toNFKC / toNFKD across all six @Part sections.
import Unicode.Conformance.NormalizationTest

-- UAX #9 conformance — official BidiTest.txt level + L1/L2 reorder
-- across all paragraph-level settings.
import Unicode.Conformance.BidiTest

-- UCA conformance — official CollationTest_*_SHORT.txt against
-- sortKey under both NON_IGNORABLE and SHIFTED variable handling.
import Unicode.Conformance.CollationTest

-- UTS #46 conformance — official IdnaTestV2.txt against
-- toUnicode / toAscii / toAsciiTransitional.
import Unicode.Conformance.IdnaTestV2
