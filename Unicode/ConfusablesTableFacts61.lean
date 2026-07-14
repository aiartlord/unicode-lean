/-
  Unicode.ConfusablesTableFacts61

  Chunk facts for generated confusables chunk 61.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk61_chain :
    Unicode.Generated.Confusables.mappingsChunk61.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk61_expansion :
    Unicode.Generated.Confusables.mappingsChunk61.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
