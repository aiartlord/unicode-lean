/-
  Unicode.ConfusablesTableFacts82

  Chunk facts for generated confusables chunk 82.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk82_chain :
    Unicode.Generated.Confusables.mappingsChunk82.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk82_expansion :
    Unicode.Generated.Confusables.mappingsChunk82.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
