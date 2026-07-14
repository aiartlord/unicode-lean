/-
  Unicode.ConfusablesTableFacts24

  Chunk facts for generated confusables chunk 24.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk24_chain :
    Unicode.Generated.Confusables.mappingsChunk24.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk24_expansion :
    Unicode.Generated.Confusables.mappingsChunk24.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
