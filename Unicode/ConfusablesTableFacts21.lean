/-
  Unicode.ConfusablesTableFacts21

  Chunk facts for generated confusables chunk 21.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk21_chain :
    Unicode.Generated.Confusables.mappingsChunk21.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk21_expansion :
    Unicode.Generated.Confusables.mappingsChunk21.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
