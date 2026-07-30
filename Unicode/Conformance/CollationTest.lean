/-
  Unicode.Conformance.CollationTest

  Unicode Collation Algorithm conformance. `ucaCompare` compares two strings by the
  lexicographic order of their multi-level sort keys under a variable-handling policy;
  UCA's corpus is sorted so `ucaCompare rowᵢ rowᵢ₊₁ ≠ .gt` throughout. Each vector
  checks `ucaCompare` reproduces the order Unicode specifies for a representative pair,
  and `order_reflexive` gives the total-preorder reflexivity axiom over all inputs.
-/

import Unicode.Uca.SortKey

namespace Unicode.Conformance.CollationTest

open Unicode.Uca.SortKey

set_option maxRecDepth 1000000

/-- **Reflexivity of the collation order, all inputs.** Every string compares equal to
    itself under UCA. -/
theorem order_reflexive (a : List Nat) : ucaCompare .nonIgnorable a a = .eq :=
  ucaCompare_refl .nonIgnorable a

/-- Primary-weight order: 'a' (U+0061) sorts strictly before 'b' (U+0062). -/
theorem vector_a_before_b :
    ucaCompare .nonIgnorable [0x61] [0x62] = .lt := by decide +kernel

/-- The order is antisymmetric on this pair: 'b' sorts strictly after 'a'. -/
theorem vector_b_after_a :
    ucaCompare .nonIgnorable [0x62] [0x61] = .gt := by decide +kernel

/-- A prefix sorts before its extension: "a" strictly before "ab". -/
theorem vector_prefix_before_extension :
    ucaCompare .nonIgnorable [0x61] [0x61, 0x62] = .lt := by decide +kernel

end Unicode.Conformance.CollationTest
