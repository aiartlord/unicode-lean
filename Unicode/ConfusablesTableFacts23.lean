/-
  Unicode.ConfusablesTableFacts23

  Chunk facts for generated confusables chunk 23.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk23_chain :
    Unicode.Generated.Confusables.mappingsChunk23.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk23_expansion :
    Unicode.Generated.Confusables.mappingsChunk23.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
