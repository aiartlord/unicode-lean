/-
  Unicode.ConfusablesTableFacts60

  Chunk facts for generated confusables chunk 60.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk60_chain :
    Unicode.Generated.Confusables.mappingsChunk60.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk60_expansion :
    Unicode.Generated.Confusables.mappingsChunk60.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
