/-
  Unicode.ConfusablesTableFacts29

  Chunk facts for generated confusables chunk 29.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk29_chain :
    Unicode.Generated.Confusables.mappingsChunk29.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk29_expansion :
    Unicode.Generated.Confusables.mappingsChunk29.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
