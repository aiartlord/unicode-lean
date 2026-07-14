/-
  Unicode.ConfusablesTableFacts19

  Chunk facts for generated confusables chunk 19.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk19_chain :
    Unicode.Generated.Confusables.mappingsChunk19.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk19_expansion :
    Unicode.Generated.Confusables.mappingsChunk19.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
