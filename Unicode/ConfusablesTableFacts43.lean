/-
  Unicode.ConfusablesTableFacts43

  Chunk facts for generated confusables chunk 43.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk43_chain :
    Unicode.Generated.Confusables.mappingsChunk43.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk43_expansion :
    Unicode.Generated.Confusables.mappingsChunk43.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
