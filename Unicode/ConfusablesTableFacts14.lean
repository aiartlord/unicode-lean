/-
  Unicode.ConfusablesTableFacts14

  Chunk facts for generated confusables chunk 14.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk14_chain :
    Unicode.Generated.Confusables.mappingsChunk14.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk14_expansion :
    Unicode.Generated.Confusables.mappingsChunk14.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
