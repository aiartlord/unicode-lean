/-
  Unicode.Precis.ZsMapping

  Runtime definitions for RFC 8265 non-ASCII Zs remapping. Proofs about
  preservation through normalization live in `Unicode.Precis.ZsPreservation`.
-/

namespace Unicode.Precis.ZsPreservation

/-- The 16 Zs (space-separator) codepoints defined by Unicode 17.0,
    excluding U+0020 SPACE. Stable across Unicode releases since 1.1
    (1993). -/
def nonAsciiZsCodepoints : List Nat := [
  0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
  0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x202F, 0x205F, 0x3000
]

/-- `isNonAsciiZs cp` iff `cp` is a Zs category codepoint other than
    U+0020. -/
def isNonAsciiZs (cp : Nat) : Bool :=
  nonAsciiZsCodepoints.contains cp

/-- U+0020 is not a non-ASCII Zs. -/
theorem isNonAsciiZs_ascii_space : isNonAsciiZs 0x0020 = false := by
  simp [isNonAsciiZs, nonAsciiZsCodepoints]

/-- RFC 8265 §4.2.2: remap every non-ASCII Zs codepoint to U+0020 SPACE. -/
def remapZsToAscii (cps : Array Nat) : Array Nat :=
  cps.map (fun cp => if isNonAsciiZs cp then 0x0020 else cp)

end Unicode.Precis.ZsPreservation
