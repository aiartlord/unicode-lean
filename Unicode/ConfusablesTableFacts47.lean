/-
  Unicode.ConfusablesTableFacts47

  Chunk facts for generated confusables chunk 47.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk47_chain :
    Unicode.Generated.Confusables.mappingsChunk47.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk47_expansion :
    Unicode.Generated.Confusables.mappingsChunk47.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
