/-
  Unicode.ConfusablesTableFactsGroup1

  Group facts for generated confusables chunks 10-19.
-/

import Unicode.ConfusablesTableFacts10
import Unicode.ConfusablesTableFacts11
import Unicode.ConfusablesTableFacts12
import Unicode.ConfusablesTableFacts13
import Unicode.ConfusablesTableFacts14
import Unicode.ConfusablesTableFacts15
import Unicode.ConfusablesTableFacts16
import Unicode.ConfusablesTableFacts17
import Unicode.ConfusablesTableFacts18
import Unicode.ConfusablesTableFacts19

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup1 : List (Nat × Array Nat) :=
  Unicode.Generated.Confusables.mappingsChunk10
  ++ Unicode.Generated.Confusables.mappingsChunk11
  ++ Unicode.Generated.Confusables.mappingsChunk12
  ++ Unicode.Generated.Confusables.mappingsChunk13
  ++ Unicode.Generated.Confusables.mappingsChunk14
  ++ Unicode.Generated.Confusables.mappingsChunk15
  ++ Unicode.Generated.Confusables.mappingsChunk16
  ++ Unicode.Generated.Confusables.mappingsChunk17
  ++ Unicode.Generated.Confusables.mappingsChunk18
  ++ Unicode.Generated.Confusables.mappingsChunk19

theorem mappingsFactGroup1_chain :
    mappingsFactGroup1.all chainConvergesEntry = true := by
  unfold mappingsFactGroup1
  simp only [List.all_append, mappingsChunk10_chain, mappingsChunk11_chain, mappingsChunk12_chain, mappingsChunk13_chain, mappingsChunk14_chain, mappingsChunk15_chain, mappingsChunk16_chain, mappingsChunk17_chain, mappingsChunk18_chain, mappingsChunk19_chain, Bool.true_and, Bool.and_true]

theorem mappingsFactGroup1_expansion :
    mappingsFactGroup1.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup1
  simp only [List.all_append, mappingsChunk10_expansion, mappingsChunk11_expansion, mappingsChunk12_expansion, mappingsChunk13_expansion, mappingsChunk14_expansion, mappingsChunk15_expansion, mappingsChunk16_expansion, mappingsChunk17_expansion, mappingsChunk18_expansion, mappingsChunk19_expansion, Bool.true_and, Bool.and_true]

end Unicode.Confusables
