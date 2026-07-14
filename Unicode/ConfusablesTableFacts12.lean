/-
  Unicode.ConfusablesTableFacts12

  Chunk facts for generated confusables chunk 12.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk12_chain :
    Unicode.Generated.Confusables.mappingsChunk12.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk12_expansion :
    Unicode.Generated.Confusables.mappingsChunk12.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
