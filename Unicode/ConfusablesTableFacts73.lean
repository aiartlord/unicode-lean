/-
  Unicode.ConfusablesTableFacts73

  Chunk facts for generated confusables chunk 73.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk73_chain :
    Unicode.Generated.Confusables.mappingsChunk73.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk73_expansion :
    Unicode.Generated.Confusables.mappingsChunk73.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
