/-
  Unicode.ConfusablesTableFacts86

  Chunk facts for generated confusables chunk 86.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk86_chain :
    Unicode.Generated.Confusables.mappingsChunk86.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk86_expansion :
    Unicode.Generated.Confusables.mappingsChunk86.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
