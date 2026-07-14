/-
  Unicode.ConfusablesTableFacts66

  Chunk facts for generated confusables chunk 66.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk66_chain :
    Unicode.Generated.Confusables.mappingsChunk66.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk66_expansion :
    Unicode.Generated.Confusables.mappingsChunk66.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
