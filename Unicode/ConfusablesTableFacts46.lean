/-
  Unicode.ConfusablesTableFacts46

  Chunk facts for generated confusables chunk 46.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk46_chain :
    Unicode.Generated.Confusables.mappingsChunk46.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk46_expansion :
    Unicode.Generated.Confusables.mappingsChunk46.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
