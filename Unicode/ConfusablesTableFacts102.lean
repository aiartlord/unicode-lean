/-
  Unicode.ConfusablesTableFacts102

  Chunk facts for generated confusables chunk 102.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk102_chain :
    Unicode.Generated.Confusables.mappingsChunk102.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk102_expansion :
    Unicode.Generated.Confusables.mappingsChunk102.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
