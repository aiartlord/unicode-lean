/-
  Unicode.ConfusablesTableFactsGroup4

  Group facts for generated confusables chunks 40-49.
-/

import Unicode.ConfusablesTableFacts40
import Unicode.ConfusablesTableFacts41
import Unicode.ConfusablesTableFacts42
import Unicode.ConfusablesTableFacts43
import Unicode.ConfusablesTableFacts44
import Unicode.ConfusablesTableFacts45
import Unicode.ConfusablesTableFacts46
import Unicode.ConfusablesTableFacts47
import Unicode.ConfusablesTableFacts48
import Unicode.ConfusablesTableFacts49

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup4 : List (Nat × List Nat) :=
  Unicode.Generated.Confusables.mappingsChunk40
  ++ Unicode.Generated.Confusables.mappingsChunk41
  ++ Unicode.Generated.Confusables.mappingsChunk42
  ++ Unicode.Generated.Confusables.mappingsChunk43
  ++ Unicode.Generated.Confusables.mappingsChunk44
  ++ Unicode.Generated.Confusables.mappingsChunk45
  ++ Unicode.Generated.Confusables.mappingsChunk46
  ++ Unicode.Generated.Confusables.mappingsChunk47
  ++ Unicode.Generated.Confusables.mappingsChunk48
  ++ Unicode.Generated.Confusables.mappingsChunk49

theorem mappingsFactGroup4_chain :
    mappingsFactGroup4.all chainConvergesEntry = true := by
  unfold mappingsFactGroup4
  simp only [List.all_append, mappingsChunk40_chain, mappingsChunk41_chain, mappingsChunk42_chain, mappingsChunk43_chain, mappingsChunk44_chain, mappingsChunk45_chain, mappingsChunk46_chain, mappingsChunk47_chain, mappingsChunk48_chain, mappingsChunk49_chain, Bool.true_and, Bool.and_true]

theorem mappingsFactGroup4_expansion :
    mappingsFactGroup4.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup4
  simp only [List.all_append, mappingsChunk40_expansion, mappingsChunk41_expansion, mappingsChunk42_expansion, mappingsChunk43_expansion, mappingsChunk44_expansion, mappingsChunk45_expansion, mappingsChunk46_expansion, mappingsChunk47_expansion, mappingsChunk48_expansion, mappingsChunk49_expansion, Bool.true_and, Bool.and_true]

end Unicode.Confusables
