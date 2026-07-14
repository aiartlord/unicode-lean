/-
  Unicode.ConfusablesTableFacts4

  Chunk facts for generated confusables chunk 4.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk4_chain :
    Unicode.Generated.Confusables.mappingsChunk4.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk4_expansion :
    Unicode.Generated.Confusables.mappingsChunk4.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
