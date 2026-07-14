/-
  Unicode.ConfusablesTableFacts34

  Chunk facts for generated confusables chunk 34.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk34_chain :
    Unicode.Generated.Confusables.mappingsChunk34.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk34_expansion :
    Unicode.Generated.Confusables.mappingsChunk34.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
