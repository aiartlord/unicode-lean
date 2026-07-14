/-
  Unicode.ConfusablesTableFacts42

  Chunk facts for generated confusables chunk 42.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk42_chain :
    Unicode.Generated.Confusables.mappingsChunk42.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk42_expansion :
    Unicode.Generated.Confusables.mappingsChunk42.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
