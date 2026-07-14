/-
  Unicode.ConfusablesTableFacts17

  Chunk facts for generated confusables chunk 17.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk17_chain :
    Unicode.Generated.Confusables.mappingsChunk17.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk17_expansion :
    Unicode.Generated.Confusables.mappingsChunk17.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
