/-
  Unicode.ConfusablesTableFacts1

  Chunk facts for generated confusables chunk 1.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk1_chain :
    Unicode.Generated.Confusables.mappingsChunk1.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk1_expansion :
    Unicode.Generated.Confusables.mappingsChunk1.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
