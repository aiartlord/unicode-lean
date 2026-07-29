/-
  Unicode.Conformance.CollationTest

  Unicode Collation Algorithm conformance. UCA's conformance property is that
  `sortKey` is non-decreasing across the sorted test corpus:
  `sortKey(rowᵢ) ≤ sortKey(rowᵢ₊₁)`. Each theorem checks `sortKey` reproduces the
  collation order Unicode specifies for a representative pair.
-/

import Unicode.Uca.SortKey

namespace Unicode.Conformance.CollationTest

open Unicode.Uca.SortKey

set_option maxRecDepth 1000000

/-- Primary-weight order: 'a' (U+0061) sorts before 'b' (U+0062). -/
theorem vector_a_before_b :
    sortKey .nonIgnorable [0x61] ≤ sortKey .nonIgnorable [0x62] := by decide +kernel

/-- The order is strict: 'b' does not sort before 'a'. -/
theorem vector_b_not_before_a :
    ¬ (sortKey .nonIgnorable [0x62] ≤ sortKey .nonIgnorable [0x61]) := by decide +kernel

/-- A prefix sorts before its extension: "a" before "ab". -/
theorem vector_prefix_before_extension :
    sortKey .nonIgnorable [0x61] ≤ sortKey .nonIgnorable [0x61, 0x62] := by decide +kernel

end Unicode.Conformance.CollationTest
