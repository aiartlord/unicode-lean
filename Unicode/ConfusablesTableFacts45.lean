/-
  Unicode.ConfusablesTableFacts45

  Chunk facts for generated confusables chunk 45.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk45_chain :
    Unicode.Generated.Confusables.mappingsChunk45.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk45_expansion :
    Unicode.Generated.Confusables.mappingsChunk45.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
