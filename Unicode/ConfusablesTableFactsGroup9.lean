/-
  Unicode.ConfusablesTableFactsGroup9

  Group facts for generated confusables chunks 90-99.
-/

import Unicode.ConfusablesTableFacts90
import Unicode.ConfusablesTableFacts91
import Unicode.ConfusablesTableFacts92
import Unicode.ConfusablesTableFacts93
import Unicode.ConfusablesTableFacts94
import Unicode.ConfusablesTableFacts95
import Unicode.ConfusablesTableFacts96
import Unicode.ConfusablesTableFacts97
import Unicode.ConfusablesTableFacts98
import Unicode.ConfusablesTableFacts99

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup9 : List (Nat × List Nat) :=
  Unicode.Generated.Confusables.mappingsChunk90
  ++ Unicode.Generated.Confusables.mappingsChunk91
  ++ Unicode.Generated.Confusables.mappingsChunk92
  ++ Unicode.Generated.Confusables.mappingsChunk93
  ++ Unicode.Generated.Confusables.mappingsChunk94
  ++ Unicode.Generated.Confusables.mappingsChunk95
  ++ Unicode.Generated.Confusables.mappingsChunk96
  ++ Unicode.Generated.Confusables.mappingsChunk97
  ++ Unicode.Generated.Confusables.mappingsChunk98
  ++ Unicode.Generated.Confusables.mappingsChunk99

theorem mappingsFactGroup9_chain :
    mappingsFactGroup9.all chainConvergesEntry = true := by
  unfold mappingsFactGroup9
  simp only [List.all_append, mappingsChunk90_chain, mappingsChunk91_chain, mappingsChunk92_chain, mappingsChunk93_chain, mappingsChunk94_chain, mappingsChunk95_chain, mappingsChunk96_chain, mappingsChunk97_chain, mappingsChunk98_chain, mappingsChunk99_chain, Bool.true_and, Bool.and_true]

theorem mappingsFactGroup9_expansion :
    mappingsFactGroup9.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup9
  simp only [List.all_append, mappingsChunk90_expansion, mappingsChunk91_expansion, mappingsChunk92_expansion, mappingsChunk93_expansion, mappingsChunk94_expansion, mappingsChunk95_expansion, mappingsChunk96_expansion, mappingsChunk97_expansion, mappingsChunk98_expansion, mappingsChunk99_expansion, Bool.true_and, Bool.and_true]

end Unicode.Confusables
