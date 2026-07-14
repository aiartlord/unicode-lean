/-
  Unicode.ConfusablesTableFacts67

  Chunk facts for generated confusables chunk 67.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk67_chain :
    Unicode.Generated.Confusables.mappingsChunk67.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk67_expansion :
    Unicode.Generated.Confusables.mappingsChunk67.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
