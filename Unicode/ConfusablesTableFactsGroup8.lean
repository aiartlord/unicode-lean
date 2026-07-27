/-
  Unicode.ConfusablesTableFactsGroup8

  Group facts for generated confusables chunks 80-89.
-/

import Unicode.ConfusablesTableFacts80
import Unicode.ConfusablesTableFacts81
import Unicode.ConfusablesTableFacts82
import Unicode.ConfusablesTableFacts83
import Unicode.ConfusablesTableFacts84
import Unicode.ConfusablesTableFacts85
import Unicode.ConfusablesTableFacts86
import Unicode.ConfusablesTableFacts87
import Unicode.ConfusablesTableFacts88
import Unicode.ConfusablesTableFacts89

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup8 : List (Nat × List Nat) :=
  Unicode.Generated.Confusables.mappingsChunk80
  ++ Unicode.Generated.Confusables.mappingsChunk81
  ++ Unicode.Generated.Confusables.mappingsChunk82
  ++ Unicode.Generated.Confusables.mappingsChunk83
  ++ Unicode.Generated.Confusables.mappingsChunk84
  ++ Unicode.Generated.Confusables.mappingsChunk85
  ++ Unicode.Generated.Confusables.mappingsChunk86
  ++ Unicode.Generated.Confusables.mappingsChunk87
  ++ Unicode.Generated.Confusables.mappingsChunk88
  ++ Unicode.Generated.Confusables.mappingsChunk89

theorem mappingsFactGroup8_chain :
    mappingsFactGroup8.all chainConvergesEntry = true := by
  unfold mappingsFactGroup8
  simp only [List.all_append, mappingsChunk80_chain, mappingsChunk81_chain, mappingsChunk82_chain, mappingsChunk83_chain, mappingsChunk84_chain, mappingsChunk85_chain, mappingsChunk86_chain, mappingsChunk87_chain, mappingsChunk88_chain, mappingsChunk89_chain, Bool.true_and, Bool.and_true]

theorem mappingsFactGroup8_expansion :
    mappingsFactGroup8.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup8
  simp only [List.all_append, mappingsChunk80_expansion, mappingsChunk81_expansion, mappingsChunk82_expansion, mappingsChunk83_expansion, mappingsChunk84_expansion, mappingsChunk85_expansion, mappingsChunk86_expansion, mappingsChunk87_expansion, mappingsChunk88_expansion, mappingsChunk89_expansion, Bool.true_and, Bool.and_true]

end Unicode.Confusables
