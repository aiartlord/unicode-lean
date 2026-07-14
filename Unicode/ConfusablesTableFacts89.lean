/-
  Unicode.ConfusablesTableFacts89

  Chunk facts for generated confusables chunk 89.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk89_chain :
    Unicode.Generated.Confusables.mappingsChunk89.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk89_expansion :
    Unicode.Generated.Confusables.mappingsChunk89.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
