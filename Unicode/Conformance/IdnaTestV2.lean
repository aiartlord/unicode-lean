/-
  Unicode.Conformance.IdnaTestV2

  UTS #46 (IDNA Compatibility Processing) conformance. `toAscii` runs the mapping,
  normalization, and validity passes and returns the processed label with an error
  flag. Each theorem checks a representative label against the output UTS #46
  specifies — case mapping to lowercase and error-free handling of valid ASCII.
-/

import Unicode.Idna.Process

namespace Unicode.Conformance.IdnaTestV2

open Unicode.Idna.Process

set_option maxRecDepth 1000000

/-- UTS #46 maps upper-case ASCII to lower-case: "ABC" becomes "abc" with no error. -/
theorem vector_uppercase_mapped :
    toAscii [0x41, 0x42, 0x43] = { output := [0x61, 0x62, 0x63], hasErrors := false } := by
  decide +kernel

/-- Valid lower-case ASCII passes through unchanged and error-free. -/
theorem vector_ascii_passthrough :
    toAscii [0x61, 0x62, 0x63] = { output := [0x61, 0x62, 0x63], hasErrors := false } := by
  decide +kernel

end Unicode.Conformance.IdnaTestV2
