/-
  Unicode.ConfusablesTableFacts2

  Chunk facts for generated confusables chunk 2.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk2_chain :
    Unicode.Generated.Confusables.mappingsChunk2.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk2_expansion :
    Unicode.Generated.Confusables.mappingsChunk2.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
