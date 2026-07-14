/-
  Unicode.ConfusablesTableFacts79

  Chunk facts for generated confusables chunk 79.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk79_chain :
    Unicode.Generated.Confusables.mappingsChunk79.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk79_expansion :
    Unicode.Generated.Confusables.mappingsChunk79.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
