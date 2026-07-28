/-
  Unicode.ConfusablesTableFactsGroup6

  Group facts for generated confusables chunks 60-69.
-/

import Unicode.ConfusablesTableFacts60
import Unicode.ConfusablesTableFacts61
import Unicode.ConfusablesTableFacts62
import Unicode.ConfusablesTableFacts63
import Unicode.ConfusablesTableFacts64
import Unicode.ConfusablesTableFacts65
import Unicode.ConfusablesTableFacts66
import Unicode.ConfusablesTableFacts67
import Unicode.ConfusablesTableFacts68
import Unicode.ConfusablesTableFacts69

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def mappingsFactGroup6 : List (Nat × List Nat) :=
  Unicode.Generated.Confusables.mappingsChunk60
  ++ Unicode.Generated.Confusables.mappingsChunk61
  ++ Unicode.Generated.Confusables.mappingsChunk62
  ++ Unicode.Generated.Confusables.mappingsChunk63
  ++ Unicode.Generated.Confusables.mappingsChunk64
  ++ Unicode.Generated.Confusables.mappingsChunk65
  ++ Unicode.Generated.Confusables.mappingsChunk66
  ++ Unicode.Generated.Confusables.mappingsChunk67
  ++ Unicode.Generated.Confusables.mappingsChunk68
  ++ Unicode.Generated.Confusables.mappingsChunk69

theorem mappingsFactGroup6_chain :
    mappingsFactGroup6.all chainConvergesEntry = true := by
  unfold mappingsFactGroup6
  simp only [List.all_append, mappingsChunk60_chain, mappingsChunk61_chain, mappingsChunk62_chain, mappingsChunk63_chain, mappingsChunk64_chain, mappingsChunk65_chain, mappingsChunk66_chain, mappingsChunk67_chain, mappingsChunk68_chain, mappingsChunk69_chain, Bool.and_true]

theorem mappingsFactGroup6_expansion :
    mappingsFactGroup6.all (expansionEntryUnderBound 18) = true := by
  unfold mappingsFactGroup6
  simp only [List.all_append, mappingsChunk60_expansion, mappingsChunk61_expansion, mappingsChunk62_expansion, mappingsChunk63_expansion, mappingsChunk64_expansion, mappingsChunk65_expansion, mappingsChunk66_expansion, mappingsChunk67_expansion, mappingsChunk68_expansion, mappingsChunk69_expansion, Bool.and_true]

end Unicode.Confusables
