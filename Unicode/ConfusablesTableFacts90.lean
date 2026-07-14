/-
  Unicode.ConfusablesTableFacts90

  Chunk facts for generated confusables chunk 90.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk90_chain :
    Unicode.Generated.Confusables.mappingsChunk90.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk90_expansion :
    Unicode.Generated.Confusables.mappingsChunk90.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
