/-
  Unicode.ConfusablesTableFacts41

  Chunk facts for generated confusables chunk 41.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk41_chain :
    Unicode.Generated.Confusables.mappingsChunk41.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk41_expansion :
    Unicode.Generated.Confusables.mappingsChunk41.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
