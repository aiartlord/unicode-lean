/-
  Unicode.ConfusablesTableFactsGroup5

  Group facts for generated confusables chunks 50-59.
-/

import Unicode.ConfusablesTableFacts50
import Unicode.ConfusablesTableFacts51
import Unicode.ConfusablesTableFacts52
import Unicode.ConfusablesTableFacts53
import Unicode.ConfusablesTableFacts54
import Unicode.ConfusablesTableFacts55
import Unicode.ConfusablesTableFacts56
import Unicode.ConfusablesTableFacts57
import Unicode.ConfusablesTableFacts58
import Unicode.ConfusablesTableFacts59

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup5 : List (Nat × List Nat) :=
  Unicode.Generated.Confusables.mappingsChunk50
  ++ Unicode.Generated.Confusables.mappingsChunk51
  ++ Unicode.Generated.Confusables.mappingsChunk52
  ++ Unicode.Generated.Confusables.mappingsChunk53
  ++ Unicode.Generated.Confusables.mappingsChunk54
  ++ Unicode.Generated.Confusables.mappingsChunk55
  ++ Unicode.Generated.Confusables.mappingsChunk56
  ++ Unicode.Generated.Confusables.mappingsChunk57
  ++ Unicode.Generated.Confusables.mappingsChunk58
  ++ Unicode.Generated.Confusables.mappingsChunk59

theorem mappingsFactGroup5_chain :
    mappingsFactGroup5.all chainConvergesEntry = true := by
  unfold mappingsFactGroup5
  simp only [List.all_append, mappingsChunk50_chain, mappingsChunk51_chain, mappingsChunk52_chain, mappingsChunk53_chain, mappingsChunk54_chain, mappingsChunk55_chain, mappingsChunk56_chain, mappingsChunk57_chain, mappingsChunk58_chain, mappingsChunk59_chain, Bool.true_and, Bool.and_true]

theorem mappingsFactGroup5_expansion :
    mappingsFactGroup5.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup5
  simp only [List.all_append, mappingsChunk50_expansion, mappingsChunk51_expansion, mappingsChunk52_expansion, mappingsChunk53_expansion, mappingsChunk54_expansion, mappingsChunk55_expansion, mappingsChunk56_expansion, mappingsChunk57_expansion, mappingsChunk58_expansion, mappingsChunk59_expansion, Bool.true_and, Bool.and_true]

end Unicode.Confusables
