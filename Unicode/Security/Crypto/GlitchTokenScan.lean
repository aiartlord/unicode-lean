/-
  Unicode.Security.Crypto.GlitchTokenScan

  Consumer of the curated glitch-token inventory
  (`Unicode.Generated.GlitchTokens`). Scans a decoded input for the presence of
  any glitch token — a tokenizer-encoded string that triggers anomalous
  behaviour in published LLMs (e.g. " SolidGoldMagikarp", " petertodd").

  Detection is over codepoints: each glitch token is converted to its codepoint
  sequence and matched as a contiguous infix of the input, so the check is
  kernel-reducible and encoding-agnostic.
-/

import Unicode.Generated.GlitchTokens

namespace Unicode.Security.Crypto.GlitchTokenScan

/-- The glitch-token inventory as codepoint sequences. -/
def glitchTokenCodepoints : List (List Nat) :=
  Unicode.Generated.GlitchTokens.tokens.map (fun t => t.toList.map (fun c => c.toNat))

/-- `needle` occurs as a contiguous infix of `hay`. -/
def containsInfix (needle hay : List Nat) : Bool :=
  (List.range (hay.length + 1)).any (fun i => needle.isPrefixOf (hay.drop i))

/-- True iff `input` contains any curated glitch token as a contiguous
    codepoint infix. -/
def containsGlitchToken (input : Array Nat) : Bool :=
  glitchTokenCodepoints.any (fun tok => containsInfix tok input.toList)

/-- Empty input contains no glitch token. -/
theorem empty_clear : containsGlitchToken #[] = false := by decide +kernel

end Unicode.Security.Crypto.GlitchTokenScan
