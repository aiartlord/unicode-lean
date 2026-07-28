/-
  Unicode.ConfusablesTableFacts

  Proof-heavy table-wide facts for `Unicode.Confusables`. These are kept out of
  the runtime module so ordinary security detector builds do not reduce the
  full confusables table.

  The all-row chain theorem below certifies the raw UTS #39 substitution graph
  used to justify `confusableChainBound`; it does not re-run the NFC/case-fold
  wrappers from the product `skeleton` pipeline for every table row.
-/

import Unicode.ConfusablesTableFactsCore
import Unicode.ConfusablesTableFactsGroup0
import Unicode.ConfusablesTableFactsGroup1
import Unicode.ConfusablesTableFactsGroup2
import Unicode.ConfusablesTableFactsGroup3
import Unicode.ConfusablesTableFactsGroup4
import Unicode.ConfusablesTableFactsGroup5
import Unicode.ConfusablesTableFactsGroup6
import Unicode.ConfusablesTableFactsGroup7
import Unicode.ConfusablesTableFactsGroup8
import Unicode.ConfusablesTableFactsGroup9
import Unicode.ConfusablesTableFactsGroup10

namespace Unicode.Confusables

open Unicode
open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

/-- Grouped mirror of the generated confusables table, in chunk order. -/
def mappingsFactGroupsList : List (Nat × List Nat) :=
  mappingsFactGroup0
  ++ mappingsFactGroup1
  ++ mappingsFactGroup2
  ++ mappingsFactGroup3
  ++ mappingsFactGroup4
  ++ mappingsFactGroup5
  ++ mappingsFactGroup6
  ++ mappingsFactGroup7
  ++ mappingsFactGroup8
  ++ mappingsFactGroup9
  ++ mappingsFactGroup10

/-- Every source row in the generated confusables table reaches a raw
    UTS #39 substitution-graph fixed point within `confusableChainBound`
    iterations after its first table edge. -/
def chainConvergesUnderBound : Bool :=
  mappingsFactGroupsList.all chainConvergesEntry

/-- Whole-table substitution-graph convergence for the bundled UTS #39 data. -/
theorem confusable_chain_within_bound :
    chainConvergesUnderBound = true := by
  unfold chainConvergesUnderBound mappingsFactGroupsList
  simp only [List.all_append, mappingsFactGroup0_chain, mappingsFactGroup1_chain, mappingsFactGroup2_chain, mappingsFactGroup3_chain, mappingsFactGroup4_chain, mappingsFactGroup5_chain, mappingsFactGroup6_chain, mappingsFactGroup7_chain, mappingsFactGroup8_chain, mappingsFactGroup9_chain, mappingsFactGroup10_chain, Bool.and_true]

/-- Every target sequence in the generated table has length <= 18. -/
theorem mappingsList_expansion_under_bound :
    mappingsFactGroupsList.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroupsList
  simp only [List.all_append, mappingsFactGroup0_expansion, mappingsFactGroup1_expansion, mappingsFactGroup2_expansion, mappingsFactGroup3_expansion, mappingsFactGroup4_expansion, mappingsFactGroup5_expansion, mappingsFactGroup6_expansion, mappingsFactGroup7_expansion, mappingsFactGroup8_expansion, mappingsFactGroup9_expansion, mappingsFactGroup10_expansion, Bool.and_true]

/-- The maximum target sequence length across the generated confusables table. -/
def maxConfusableExpansion : Nat :=
  mappingsFactGroupsList.foldl (fun m e => max m e.2.length) 0

/-- Concrete expansion bound for the bundled UTS #39 data. -/
theorem maxConfusableExpansion_concrete :
    maxConfusableExpansion <= 18 := by
  unfold maxConfusableExpansion
  exact foldl_max_size_le_of_all 18 mappingsFactGroupsList 0
    (Nat.zero_le 18) mappingsList_expansion_under_bound

end Unicode.Confusables
