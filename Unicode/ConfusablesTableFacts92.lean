/-
  Unicode.ConfusablesTableFacts92

  Chunk facts for generated confusables chunk 92.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk92_chain :
    Unicode.Generated.Confusables.mappingsChunk92.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk92_expansion :
    Unicode.Generated.Confusables.mappingsChunk92.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
