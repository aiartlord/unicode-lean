/-
  Unicode.Conformance.Security.HashInputStabilityTest

  Conformance for the HashInputStability detector: input whose hash is unstable under
  canonicalisation — trailing whitespace and normalization drift that make two "equal"
  strings hash differently (a hash-collision / bypass hazard).

  Each theorem checks the full verdict — sub-threat tag together with the stable size
  and positions — on a representative vector: a trailing space, a trailing CRLF, and a
  stable lowercase-ASCII clear. The NFC form is rewritten away with `toNFC_id_lowAscii`
  (each input is low-ASCII, so NFC is the identity), leaving a cheap `decide`.
-/

import Unicode.Security.Crypto.HashInputStability

namespace Unicode.Conformance.Security.HashInputStabilityTest

open Unicode.Security.Crypto.HashInputStability

/-- Trailing space makes the hash unstable — TrailingWhitespace at position 1, the
    stable (trimmed) form has size 1. -/
theorem trailing_space_verdict :
    let v := detect [0x61, 0x20]
    v.classify.tag = some "TrailingWhitespace"
      ∧ v.classify.positions = [1] ∧ v.stableSize = 1 := by
  unfold detect detectWithContext hashStable
  rw [toNFC_id_lowAscii [0x61, 0x20] (by decide)]
  decide

/-- Trailing CRLF is likewise unstable — the stable form has size 1. -/
theorem trailing_crlf_verdict :
    let v := detect [0x61, 0x0D, 0x0A]
    v.classify.tag = some "TrailingWhitespace" ∧ v.stableSize = 1 := by
  unfold detect detectWithContext hashStable
  rw [toNFC_id_lowAscii [0x61, 0x0D, 0x0A] (by decide)]
  decide

/-- Plain lowercase ASCII already hashes stably — clear. -/
theorem ascii_clear_verdict :
    (detect [0x61, 0x62, 0x63]).classify = .clear := by
  unfold detect detectWithContext hashStable
  rw [toNFC_id_lowAscii [0x61, 0x62, 0x63] (by decide)]
  decide

end Unicode.Conformance.Security.HashInputStabilityTest
