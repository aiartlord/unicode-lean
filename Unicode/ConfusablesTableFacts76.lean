/-
  Unicode.ConfusablesTableFacts76

  Chunk facts for generated confusables chunk 76.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk76_chain :
    Unicode.Generated.Confusables.mappingsChunk76.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk76_expansion :
    Unicode.Generated.Confusables.mappingsChunk76.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
