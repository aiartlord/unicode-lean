/-
  Unicode.ConfusablesTableFacts75

  Chunk facts for generated confusables chunk 75.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk75_chain :
    Unicode.Generated.Confusables.mappingsChunk75.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk75_expansion :
    Unicode.Generated.Confusables.mappingsChunk75.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
