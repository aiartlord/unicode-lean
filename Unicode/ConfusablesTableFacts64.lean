/-
  Unicode.ConfusablesTableFacts64

  Chunk facts for generated confusables chunk 64.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk64_chain :
    Unicode.Generated.Confusables.mappingsChunk64.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk64_expansion :
    Unicode.Generated.Confusables.mappingsChunk64.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
