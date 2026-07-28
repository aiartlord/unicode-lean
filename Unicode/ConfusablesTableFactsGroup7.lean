/-
  Unicode.ConfusablesTableFactsGroup7

  Group facts for generated confusables chunks 70-79.
-/

import Unicode.ConfusablesTableFacts70
import Unicode.ConfusablesTableFacts71
import Unicode.ConfusablesTableFacts72
import Unicode.ConfusablesTableFacts73
import Unicode.ConfusablesTableFacts74
import Unicode.ConfusablesTableFacts75
import Unicode.ConfusablesTableFacts76
import Unicode.ConfusablesTableFacts77
import Unicode.ConfusablesTableFacts78
import Unicode.ConfusablesTableFacts79

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup7 : List (Nat × List Nat) :=
  Unicode.Generated.Confusables.mappingsChunk70
  ++ Unicode.Generated.Confusables.mappingsChunk71
  ++ Unicode.Generated.Confusables.mappingsChunk72
  ++ Unicode.Generated.Confusables.mappingsChunk73
  ++ Unicode.Generated.Confusables.mappingsChunk74
  ++ Unicode.Generated.Confusables.mappingsChunk75
  ++ Unicode.Generated.Confusables.mappingsChunk76
  ++ Unicode.Generated.Confusables.mappingsChunk77
  ++ Unicode.Generated.Confusables.mappingsChunk78
  ++ Unicode.Generated.Confusables.mappingsChunk79

theorem mappingsFactGroup7_chain :
    mappingsFactGroup7.all chainConvergesEntry = true := by
  unfold mappingsFactGroup7
  simp only [List.all_append, mappingsChunk70_chain, mappingsChunk71_chain, mappingsChunk72_chain, mappingsChunk73_chain, mappingsChunk74_chain, mappingsChunk75_chain, mappingsChunk76_chain, mappingsChunk77_chain, mappingsChunk78_chain, mappingsChunk79_chain, Bool.and_true]

theorem mappingsFactGroup7_expansion :
    mappingsFactGroup7.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup7
  simp only [List.all_append, mappingsChunk70_expansion, mappingsChunk71_expansion, mappingsChunk72_expansion, mappingsChunk73_expansion, mappingsChunk74_expansion, mappingsChunk75_expansion, mappingsChunk76_expansion, mappingsChunk77_expansion, mappingsChunk78_expansion, mappingsChunk79_expansion, Bool.and_true]

end Unicode.Confusables
