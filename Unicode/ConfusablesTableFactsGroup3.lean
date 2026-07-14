/-
  Unicode.ConfusablesTableFactsGroup3

  Group facts for generated confusables chunks 30-39.
-/

import Unicode.ConfusablesTableFacts30
import Unicode.ConfusablesTableFacts31
import Unicode.ConfusablesTableFacts32
import Unicode.ConfusablesTableFacts33
import Unicode.ConfusablesTableFacts34
import Unicode.ConfusablesTableFacts35
import Unicode.ConfusablesTableFacts36
import Unicode.ConfusablesTableFacts37
import Unicode.ConfusablesTableFacts38
import Unicode.ConfusablesTableFacts39

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup3 : List (Nat × Array Nat) :=
  Unicode.Generated.Confusables.mappingsChunk30
  ++ Unicode.Generated.Confusables.mappingsChunk31
  ++ Unicode.Generated.Confusables.mappingsChunk32
  ++ Unicode.Generated.Confusables.mappingsChunk33
  ++ Unicode.Generated.Confusables.mappingsChunk34
  ++ Unicode.Generated.Confusables.mappingsChunk35
  ++ Unicode.Generated.Confusables.mappingsChunk36
  ++ Unicode.Generated.Confusables.mappingsChunk37
  ++ Unicode.Generated.Confusables.mappingsChunk38
  ++ Unicode.Generated.Confusables.mappingsChunk39

theorem mappingsFactGroup3_chain :
    mappingsFactGroup3.all chainConvergesEntry = true := by
  unfold mappingsFactGroup3
  simp only [List.all_append, mappingsChunk30_chain, mappingsChunk31_chain, mappingsChunk32_chain, mappingsChunk33_chain, mappingsChunk34_chain, mappingsChunk35_chain, mappingsChunk36_chain, mappingsChunk37_chain, mappingsChunk38_chain, mappingsChunk39_chain, Bool.true_and, Bool.and_true]

theorem mappingsFactGroup3_expansion :
    mappingsFactGroup3.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup3
  simp only [List.all_append, mappingsChunk30_expansion, mappingsChunk31_expansion, mappingsChunk32_expansion, mappingsChunk33_expansion, mappingsChunk34_expansion, mappingsChunk35_expansion, mappingsChunk36_expansion, mappingsChunk37_expansion, mappingsChunk38_expansion, mappingsChunk39_expansion, Bool.true_and, Bool.and_true]

end Unicode.Confusables
