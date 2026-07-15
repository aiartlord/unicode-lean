/-
  Unicode.Generated.PropListUca16Data

  Materialized Unified_Ideograph ranges (UCA 16.0 — deliberately pinned to
  Unicode 16.0 so the UCA 16.0 conformance loader produces the 16.0 answer),
  as a `List` literal so per-codepoint membership reduces in the kernel. The
  parser and `include_str` source live in `Unicode.Generated.PropListUca16`,
  which imports this module and carries the build-time drift gate.
-/

namespace Unicode.Generated.PropListUca16

set_option maxRecDepth 1000000

/-- Materialized Unified_Ideograph ranges in source order. -/
def unifiedIdeographRangesList : List (Nat × Nat) := [
  (13312, 19903),
  (19968, 40959),
  (64014, 64015),
  (64017, 64017),
  (64019, 64020),
  (64031, 64031),
  (64033, 64033),
  (64035, 64036),
  (64039, 64041),
  (131072, 173791),
  (173824, 177977),
  (177984, 178205),
  (178208, 183969),
  (183984, 191456),
  (191472, 192093),
  (196608, 201546),
  (201552, 205743)
]

end Unicode.Generated.PropListUca16
