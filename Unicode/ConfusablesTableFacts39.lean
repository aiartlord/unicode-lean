/-
  Unicode.ConfusablesTableFacts39

  Chunk facts for generated confusables chunk 39.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk39_chain :
    Unicode.Generated.Confusables.mappingsChunk39.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk39_expansion :
    Unicode.Generated.Confusables.mappingsChunk39.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
