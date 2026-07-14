/-
  Unicode.ConfusablesTableFacts57

  Chunk facts for generated confusables chunk 57.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk57_chain :
    Unicode.Generated.Confusables.mappingsChunk57.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk57_expansion :
    Unicode.Generated.Confusables.mappingsChunk57.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
