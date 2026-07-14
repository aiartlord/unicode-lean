/-
  Unicode.ConfusablesTableFacts27

  Chunk facts for generated confusables chunk 27.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk27_chain :
    Unicode.Generated.Confusables.mappingsChunk27.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk27_expansion :
    Unicode.Generated.Confusables.mappingsChunk27.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
