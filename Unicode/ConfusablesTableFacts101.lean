/-
  Unicode.ConfusablesTableFacts101

  Chunk facts for generated confusables chunk 101.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk101_chain :
    Unicode.Generated.Confusables.mappingsChunk101.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk101_expansion :
    Unicode.Generated.Confusables.mappingsChunk101.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
