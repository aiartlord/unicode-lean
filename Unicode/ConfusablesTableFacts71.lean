/-
  Unicode.ConfusablesTableFacts71

  Chunk facts for generated confusables chunk 71.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk71_chain :
    Unicode.Generated.Confusables.mappingsChunk71.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk71_expansion :
    Unicode.Generated.Confusables.mappingsChunk71.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
