/-
  Unicode.ConfusablesTableFacts91

  Chunk facts for generated confusables chunk 91.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk91_chain :
    Unicode.Generated.Confusables.mappingsChunk91.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk91_expansion :
    Unicode.Generated.Confusables.mappingsChunk91.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
