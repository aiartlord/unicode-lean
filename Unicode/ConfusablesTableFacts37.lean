/-
  Unicode.ConfusablesTableFacts37

  Chunk facts for generated confusables chunk 37.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk37_chain :
    Unicode.Generated.Confusables.mappingsChunk37.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk37_expansion :
    Unicode.Generated.Confusables.mappingsChunk37.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
