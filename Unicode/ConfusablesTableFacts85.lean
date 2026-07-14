/-
  Unicode.ConfusablesTableFacts85

  Chunk facts for generated confusables chunk 85.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk85_chain :
    Unicode.Generated.Confusables.mappingsChunk85.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk85_expansion :
    Unicode.Generated.Confusables.mappingsChunk85.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
