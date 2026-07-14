/-
  Unicode.ConfusablesTableFacts16

  Chunk facts for generated confusables chunk 16.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk16_chain :
    Unicode.Generated.Confusables.mappingsChunk16.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk16_expansion :
    Unicode.Generated.Confusables.mappingsChunk16.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
