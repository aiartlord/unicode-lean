/-
  Unicode.ConfusablesTableFacts52

  Chunk facts for generated confusables chunk 52.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk52_chain :
    Unicode.Generated.Confusables.mappingsChunk52.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk52_expansion :
    Unicode.Generated.Confusables.mappingsChunk52.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
