/-
  Unicode.ConfusablesTableFacts6

  Chunk facts for generated confusables chunk 6.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk6_chain :
    Unicode.Generated.Confusables.mappingsChunk6.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk6_expansion :
    Unicode.Generated.Confusables.mappingsChunk6.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
