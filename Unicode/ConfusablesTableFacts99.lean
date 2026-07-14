/-
  Unicode.ConfusablesTableFacts99

  Chunk facts for generated confusables chunk 99.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk99_chain :
    Unicode.Generated.Confusables.mappingsChunk99.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk99_expansion :
    Unicode.Generated.Confusables.mappingsChunk99.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
