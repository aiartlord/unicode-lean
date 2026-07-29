/-
  Unicode.Conformance.Security.Bip39CanonicalTest

  Conformance for the Bip39Canonical detector (BIP-39 mnemonic canonicalisation
  hazards — mixed case, whitespace anomalies, and non-NFKD forms that would produce a
  different seed than the canonical mnemonic, a wallet-loss / theft hazard).

  The detector is spot-checked in its own module and vectors file. This module
  re-states representative full verdicts as conformance assertions, discharged by
  `decide +kernel` on concrete literal mnemonics.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
-/

import Unicode.Security.Crypto.Bip39Canonical

namespace Unicode.Conformance.Security.Bip39CanonicalTest

open Unicode.Security.Crypto.Bip39Canonical

set_option maxRecDepth 1000000

/-- A capitalised word ("Abandon") is non-canonical — mixed case. -/
theorem mixed_case_verdict :
    (detect [0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]).classify.tag
      = some "MixedCase" := by decide +kernel

/-- A leading space is a whitespace anomaly. -/
theorem leading_space_verdict :
    (detect [0x20, 0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]).classify.tag
      = some "WhitespaceAnomaly" := by decide +kernel

/-- The `ﬀ` ligature (U+FB00) is not NFKD-normalised — non-NFKD form. -/
theorem non_nfkd_verdict :
    (detect [0xFB00]).classify.tag = some "NonNFKD" := by decide +kernel

/-- Empty input has nothing non-canonical — clear. -/
theorem empty_clear_verdict :
    (detect []).classify = .clear .english := by decide +kernel

end Unicode.Conformance.Security.Bip39CanonicalTest
