/-
  Unicode.ConfusablesTableFacts83

  Chunk facts for generated confusables chunk 83.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk83_chain :
    Unicode.Generated.Confusables.mappingsChunk83.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk83_expansion :
    Unicode.Generated.Confusables.mappingsChunk83.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
