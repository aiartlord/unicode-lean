/-
  Unicode.ConfusablesTableFacts77

  Chunk facts for generated confusables chunk 77.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk77_chain :
    Unicode.Generated.Confusables.mappingsChunk77.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk77_expansion :
    Unicode.Generated.Confusables.mappingsChunk77.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
