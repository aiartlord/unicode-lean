/-
  Unicode.ConfusablesTableFacts11

  Chunk facts for generated confusables chunk 11.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk11_chain :
    Unicode.Generated.Confusables.mappingsChunk11.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk11_expansion :
    Unicode.Generated.Confusables.mappingsChunk11.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
