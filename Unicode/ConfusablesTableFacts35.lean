/-
  Unicode.ConfusablesTableFacts35

  Chunk facts for generated confusables chunk 35.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk35_chain :
    Unicode.Generated.Confusables.mappingsChunk35.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk35_expansion :
    Unicode.Generated.Confusables.mappingsChunk35.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
