/-
  Unicode.ConfusablesTableFacts10

  Chunk facts for generated confusables chunk 10.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk10_chain :
    Unicode.Generated.Confusables.mappingsChunk10.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk10_expansion :
    Unicode.Generated.Confusables.mappingsChunk10.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
