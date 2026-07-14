/-
  Unicode.ConfusablesTableFacts84

  Chunk facts for generated confusables chunk 84.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk84_chain :
    Unicode.Generated.Confusables.mappingsChunk84.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk84_expansion :
    Unicode.Generated.Confusables.mappingsChunk84.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
