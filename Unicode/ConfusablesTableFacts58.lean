/-
  Unicode.ConfusablesTableFacts58

  Chunk facts for generated confusables chunk 58.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk58_chain :
    Unicode.Generated.Confusables.mappingsChunk58.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk58_expansion :
    Unicode.Generated.Confusables.mappingsChunk58.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
