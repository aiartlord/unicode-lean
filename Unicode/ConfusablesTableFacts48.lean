/-
  Unicode.ConfusablesTableFacts48

  Chunk facts for generated confusables chunk 48.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk48_chain :
    Unicode.Generated.Confusables.mappingsChunk48.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk48_expansion :
    Unicode.Generated.Confusables.mappingsChunk48.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
