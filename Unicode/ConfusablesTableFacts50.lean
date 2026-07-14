/-
  Unicode.ConfusablesTableFacts50

  Chunk facts for generated confusables chunk 50.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk50_chain :
    Unicode.Generated.Confusables.mappingsChunk50.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk50_expansion :
    Unicode.Generated.Confusables.mappingsChunk50.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
