/-
  Unicode.ConfusablesTableFacts100

  Chunk facts for generated confusables chunk 100.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk100_chain :
    Unicode.Generated.Confusables.mappingsChunk100.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk100_expansion :
    Unicode.Generated.Confusables.mappingsChunk100.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
