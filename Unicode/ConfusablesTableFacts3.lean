/-
  Unicode.ConfusablesTableFacts3

  Chunk facts for generated confusables chunk 3.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk3_chain :
    Unicode.Generated.Confusables.mappingsChunk3.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk3_expansion :
    Unicode.Generated.Confusables.mappingsChunk3.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
