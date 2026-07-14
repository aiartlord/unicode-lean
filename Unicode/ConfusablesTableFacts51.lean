/-
  Unicode.ConfusablesTableFacts51

  Chunk facts for generated confusables chunk 51.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk51_chain :
    Unicode.Generated.Confusables.mappingsChunk51.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk51_expansion :
    Unicode.Generated.Confusables.mappingsChunk51.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
