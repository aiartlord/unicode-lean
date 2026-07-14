/-
  Unicode.ConfusablesTableFacts26

  Chunk facts for generated confusables chunk 26.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk26_chain :
    Unicode.Generated.Confusables.mappingsChunk26.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk26_expansion :
    Unicode.Generated.Confusables.mappingsChunk26.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
