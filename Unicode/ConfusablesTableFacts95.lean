/-
  Unicode.ConfusablesTableFacts95

  Chunk facts for generated confusables chunk 95.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk95_chain :
    Unicode.Generated.Confusables.mappingsChunk95.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk95_expansion :
    Unicode.Generated.Confusables.mappingsChunk95.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
