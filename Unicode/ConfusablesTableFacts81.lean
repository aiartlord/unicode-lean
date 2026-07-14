/-
  Unicode.ConfusablesTableFacts81

  Chunk facts for generated confusables chunk 81.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk81_chain :
    Unicode.Generated.Confusables.mappingsChunk81.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk81_expansion :
    Unicode.Generated.Confusables.mappingsChunk81.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
