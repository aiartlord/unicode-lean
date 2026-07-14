/-
  Unicode.ConfusablesTableFactsGroup0

  Group facts for generated confusables chunks 0-9.
-/

import Unicode.ConfusablesTableFacts0
import Unicode.ConfusablesTableFacts1
import Unicode.ConfusablesTableFacts2
import Unicode.ConfusablesTableFacts3
import Unicode.ConfusablesTableFacts4
import Unicode.ConfusablesTableFacts5
import Unicode.ConfusablesTableFacts6
import Unicode.ConfusablesTableFacts7
import Unicode.ConfusablesTableFacts8
import Unicode.ConfusablesTableFacts9

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup0 : List (Nat × Array Nat) :=
  Unicode.Generated.Confusables.mappingsChunk0
  ++ Unicode.Generated.Confusables.mappingsChunk1
  ++ Unicode.Generated.Confusables.mappingsChunk2
  ++ Unicode.Generated.Confusables.mappingsChunk3
  ++ Unicode.Generated.Confusables.mappingsChunk4
  ++ Unicode.Generated.Confusables.mappingsChunk5
  ++ Unicode.Generated.Confusables.mappingsChunk6
  ++ Unicode.Generated.Confusables.mappingsChunk7
  ++ Unicode.Generated.Confusables.mappingsChunk8
  ++ Unicode.Generated.Confusables.mappingsChunk9

theorem mappingsFactGroup0_chain :
    mappingsFactGroup0.all chainConvergesEntry = true := by
  unfold mappingsFactGroup0
  simp only [List.all_append, mappingsChunk0_chain, mappingsChunk1_chain, mappingsChunk2_chain, mappingsChunk3_chain, mappingsChunk4_chain, mappingsChunk5_chain, mappingsChunk6_chain, mappingsChunk7_chain, mappingsChunk8_chain, mappingsChunk9_chain, Bool.true_and, Bool.and_true]

theorem mappingsFactGroup0_expansion :
    mappingsFactGroup0.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup0
  simp only [List.all_append, mappingsChunk0_expansion, mappingsChunk1_expansion, mappingsChunk2_expansion, mappingsChunk3_expansion, mappingsChunk4_expansion, mappingsChunk5_expansion, mappingsChunk6_expansion, mappingsChunk7_expansion, mappingsChunk8_expansion, mappingsChunk9_expansion, Bool.true_and, Bool.and_true]

end Unicode.Confusables
