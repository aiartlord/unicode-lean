/-
  Unicode.ConfusablesTableFacts7

  Chunk facts for generated confusables chunk 7.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk7_chain :
    Unicode.Generated.Confusables.mappingsChunk7.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk7_expansion :
    Unicode.Generated.Confusables.mappingsChunk7.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
