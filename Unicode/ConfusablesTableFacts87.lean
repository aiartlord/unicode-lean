/-
  Unicode.ConfusablesTableFacts87

  Chunk facts for generated confusables chunk 87.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk87_chain :
    Unicode.Generated.Confusables.mappingsChunk87.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk87_expansion :
    Unicode.Generated.Confusables.mappingsChunk87.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
