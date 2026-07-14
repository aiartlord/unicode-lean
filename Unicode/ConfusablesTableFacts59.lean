/-
  Unicode.ConfusablesTableFacts59

  Chunk facts for generated confusables chunk 59.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk59_chain :
    Unicode.Generated.Confusables.mappingsChunk59.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk59_expansion :
    Unicode.Generated.Confusables.mappingsChunk59.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
