/-
  Unicode.ConfusablesTableFactsGroup10

  Group facts for generated confusables chunks 100-102.
-/

import Unicode.ConfusablesTableFacts100
import Unicode.ConfusablesTableFacts101
import Unicode.ConfusablesTableFacts102

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup10 : List (Nat × List Nat) :=
  Unicode.Generated.Confusables.mappingsChunk100
  ++ Unicode.Generated.Confusables.mappingsChunk101
  ++ Unicode.Generated.Confusables.mappingsChunk102

theorem mappingsFactGroup10_chain :
    mappingsFactGroup10.all chainConvergesEntry = true := by
  unfold mappingsFactGroup10
  simp only [List.all_append, mappingsChunk100_chain, mappingsChunk101_chain, mappingsChunk102_chain, Bool.and_true]

theorem mappingsFactGroup10_expansion :
    mappingsFactGroup10.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup10
  simp only [List.all_append, mappingsChunk100_expansion, mappingsChunk101_expansion, mappingsChunk102_expansion, Bool.and_true]

end Unicode.Confusables
