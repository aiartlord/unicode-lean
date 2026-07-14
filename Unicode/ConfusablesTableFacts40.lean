/-
  Unicode.ConfusablesTableFacts40

  Chunk facts for generated confusables chunk 40.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk40_chain :
    Unicode.Generated.Confusables.mappingsChunk40.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk40_expansion :
    Unicode.Generated.Confusables.mappingsChunk40.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
