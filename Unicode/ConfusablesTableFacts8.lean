/-
  Unicode.ConfusablesTableFacts8

  Chunk facts for generated confusables chunk 8.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk8_chain :
    Unicode.Generated.Confusables.mappingsChunk8.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk8_expansion :
    Unicode.Generated.Confusables.mappingsChunk8.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
