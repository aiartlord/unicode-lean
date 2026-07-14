/-
  Unicode.ConfusablesTableFactsGroup2

  Group facts for generated confusables chunks 20-29.
-/

import Unicode.ConfusablesTableFacts20
import Unicode.ConfusablesTableFacts21
import Unicode.ConfusablesTableFacts22
import Unicode.ConfusablesTableFacts23
import Unicode.ConfusablesTableFacts24
import Unicode.ConfusablesTableFacts25
import Unicode.ConfusablesTableFacts26
import Unicode.ConfusablesTableFacts27
import Unicode.ConfusablesTableFacts28
import Unicode.ConfusablesTableFacts29

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup2 : List (Nat × Array Nat) :=
  Unicode.Generated.Confusables.mappingsChunk20
  ++ Unicode.Generated.Confusables.mappingsChunk21
  ++ Unicode.Generated.Confusables.mappingsChunk22
  ++ Unicode.Generated.Confusables.mappingsChunk23
  ++ Unicode.Generated.Confusables.mappingsChunk24
  ++ Unicode.Generated.Confusables.mappingsChunk25
  ++ Unicode.Generated.Confusables.mappingsChunk26
  ++ Unicode.Generated.Confusables.mappingsChunk27
  ++ Unicode.Generated.Confusables.mappingsChunk28
  ++ Unicode.Generated.Confusables.mappingsChunk29

theorem mappingsFactGroup2_chain :
    mappingsFactGroup2.all chainConvergesEntry = true := by
  unfold mappingsFactGroup2
  simp only [List.all_append, mappingsChunk20_chain, mappingsChunk21_chain, mappingsChunk22_chain, mappingsChunk23_chain, mappingsChunk24_chain, mappingsChunk25_chain, mappingsChunk26_chain, mappingsChunk27_chain, mappingsChunk28_chain, mappingsChunk29_chain, Bool.true_and, Bool.and_true]

theorem mappingsFactGroup2_expansion :
    mappingsFactGroup2.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup2
  simp only [List.all_append, mappingsChunk20_expansion, mappingsChunk21_expansion, mappingsChunk22_expansion, mappingsChunk23_expansion, mappingsChunk24_expansion, mappingsChunk25_expansion, mappingsChunk26_expansion, mappingsChunk27_expansion, mappingsChunk28_expansion, mappingsChunk29_expansion, Bool.true_and, Bool.and_true]

end Unicode.Confusables
