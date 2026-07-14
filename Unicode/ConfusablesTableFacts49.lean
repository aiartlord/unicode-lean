/-
  Unicode.ConfusablesTableFacts49

  Chunk facts for generated confusables chunk 49.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk49_chain :
    Unicode.Generated.Confusables.mappingsChunk49.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk49_expansion :
    Unicode.Generated.Confusables.mappingsChunk49.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
