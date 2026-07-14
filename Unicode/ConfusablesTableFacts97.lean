/-
  Unicode.ConfusablesTableFacts97

  Chunk facts for generated confusables chunk 97.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk97_chain :
    Unicode.Generated.Confusables.mappingsChunk97.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk97_expansion :
    Unicode.Generated.Confusables.mappingsChunk97.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
