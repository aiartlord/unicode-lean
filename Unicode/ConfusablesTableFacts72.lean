/-
  Unicode.ConfusablesTableFacts72

  Chunk facts for generated confusables chunk 72.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk72_chain :
    Unicode.Generated.Confusables.mappingsChunk72.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk72_expansion :
    Unicode.Generated.Confusables.mappingsChunk72.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
