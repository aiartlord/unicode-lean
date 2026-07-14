/-
  Unicode.ConfusablesTableFacts62

  Chunk facts for generated confusables chunk 62.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk62_chain :
    Unicode.Generated.Confusables.mappingsChunk62.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk62_expansion :
    Unicode.Generated.Confusables.mappingsChunk62.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
