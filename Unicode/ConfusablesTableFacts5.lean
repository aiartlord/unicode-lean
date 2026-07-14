/-
  Unicode.ConfusablesTableFacts5

  Chunk facts for generated confusables chunk 5.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk5_chain :
    Unicode.Generated.Confusables.mappingsChunk5.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk5_expansion :
    Unicode.Generated.Confusables.mappingsChunk5.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
