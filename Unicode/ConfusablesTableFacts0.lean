/-
  Unicode.ConfusablesTableFacts0

  Chunk facts for generated confusables chunk 0.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk0_chain :
    Unicode.Generated.Confusables.mappingsChunk0.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk0_expansion :
    Unicode.Generated.Confusables.mappingsChunk0.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
