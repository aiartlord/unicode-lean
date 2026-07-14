/-
  Unicode.ConfusablesTableFacts22

  Chunk facts for generated confusables chunk 22.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk22_chain :
    Unicode.Generated.Confusables.mappingsChunk22.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk22_expansion :
    Unicode.Generated.Confusables.mappingsChunk22.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
