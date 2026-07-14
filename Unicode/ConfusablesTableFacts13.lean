/-
  Unicode.ConfusablesTableFacts13

  Chunk facts for generated confusables chunk 13.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk13_chain :
    Unicode.Generated.Confusables.mappingsChunk13.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk13_expansion :
    Unicode.Generated.Confusables.mappingsChunk13.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
