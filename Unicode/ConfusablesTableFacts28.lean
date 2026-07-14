/-
  Unicode.ConfusablesTableFacts28

  Chunk facts for generated confusables chunk 28.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk28_chain :
    Unicode.Generated.Confusables.mappingsChunk28.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk28_expansion :
    Unicode.Generated.Confusables.mappingsChunk28.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
