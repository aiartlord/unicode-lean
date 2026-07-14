/-
  Unicode.ConfusablesTableFacts38

  Chunk facts for generated confusables chunk 38.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk38_chain :
    Unicode.Generated.Confusables.mappingsChunk38.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk38_expansion :
    Unicode.Generated.Confusables.mappingsChunk38.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
