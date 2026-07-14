/-
  Unicode.ConfusablesTableFacts25

  Chunk facts for generated confusables chunk 25.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk25_chain :
    Unicode.Generated.Confusables.mappingsChunk25.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk25_expansion :
    Unicode.Generated.Confusables.mappingsChunk25.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
