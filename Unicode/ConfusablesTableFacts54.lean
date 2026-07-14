/-
  Unicode.ConfusablesTableFacts54

  Chunk facts for generated confusables chunk 54.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk54_chain :
    Unicode.Generated.Confusables.mappingsChunk54.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk54_expansion :
    Unicode.Generated.Confusables.mappingsChunk54.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
