/-
  Unicode.ConfusablesTableFacts44

  Chunk facts for generated confusables chunk 44.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk44_chain :
    Unicode.Generated.Confusables.mappingsChunk44.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk44_expansion :
    Unicode.Generated.Confusables.mappingsChunk44.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
