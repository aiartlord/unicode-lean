/-
  Unicode.ConfusablesTableFacts55

  Chunk facts for generated confusables chunk 55.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk55_chain :
    Unicode.Generated.Confusables.mappingsChunk55.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk55_expansion :
    Unicode.Generated.Confusables.mappingsChunk55.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
