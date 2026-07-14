/-
  Unicode.ConfusablesTableFacts88

  Chunk facts for generated confusables chunk 88.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk88_chain :
    Unicode.Generated.Confusables.mappingsChunk88.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk88_expansion :
    Unicode.Generated.Confusables.mappingsChunk88.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
