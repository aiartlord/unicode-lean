/-
  Unicode.ConfusablesTableFacts31

  Chunk facts for generated confusables chunk 31.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk31_chain :
    Unicode.Generated.Confusables.mappingsChunk31.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk31_expansion :
    Unicode.Generated.Confusables.mappingsChunk31.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
