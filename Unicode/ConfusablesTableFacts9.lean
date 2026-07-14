/-
  Unicode.ConfusablesTableFacts9

  Chunk facts for generated confusables chunk 9.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk9_chain :
    Unicode.Generated.Confusables.mappingsChunk9.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk9_expansion :
    Unicode.Generated.Confusables.mappingsChunk9.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
