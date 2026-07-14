/-
  Unicode.ConfusablesTableFacts68

  Chunk facts for generated confusables chunk 68.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk68_chain :
    Unicode.Generated.Confusables.mappingsChunk68.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk68_expansion :
    Unicode.Generated.Confusables.mappingsChunk68.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
