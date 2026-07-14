/-
  Unicode.ConfusablesTableFacts32

  Chunk facts for generated confusables chunk 32.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk32_chain :
    Unicode.Generated.Confusables.mappingsChunk32.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk32_expansion :
    Unicode.Generated.Confusables.mappingsChunk32.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
