/-
  Unicode.ConfusablesTableFacts15

  Chunk facts for generated confusables chunk 15.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk15_chain :
    Unicode.Generated.Confusables.mappingsChunk15.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk15_expansion :
    Unicode.Generated.Confusables.mappingsChunk15.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
