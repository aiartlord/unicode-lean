/-
  Unicode.ConfusablesTableFacts74

  Chunk facts for generated confusables chunk 74.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk74_chain :
    Unicode.Generated.Confusables.mappingsChunk74.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk74_expansion :
    Unicode.Generated.Confusables.mappingsChunk74.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
