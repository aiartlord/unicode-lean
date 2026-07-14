/-
  Unicode.ConfusablesTableFacts69

  Chunk facts for generated confusables chunk 69.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk69_chain :
    Unicode.Generated.Confusables.mappingsChunk69.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk69_expansion :
    Unicode.Generated.Confusables.mappingsChunk69.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
