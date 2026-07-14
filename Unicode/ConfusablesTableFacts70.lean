/-
  Unicode.ConfusablesTableFacts70

  Chunk facts for generated confusables chunk 70.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk70_chain :
    Unicode.Generated.Confusables.mappingsChunk70.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk70_expansion :
    Unicode.Generated.Confusables.mappingsChunk70.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
