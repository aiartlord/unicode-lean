/-
  Unicode.ConfusablesTableFacts93

  Chunk facts for generated confusables chunk 93.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk93_chain :
    Unicode.Generated.Confusables.mappingsChunk93.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk93_expansion :
    Unicode.Generated.Confusables.mappingsChunk93.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
