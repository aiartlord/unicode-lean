/-
  Unicode.ConfusablesTableFacts20

  Chunk facts for generated confusables chunk 20.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk20_chain :
    Unicode.Generated.Confusables.mappingsChunk20.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk20_expansion :
    Unicode.Generated.Confusables.mappingsChunk20.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
