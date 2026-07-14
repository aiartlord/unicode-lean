/-
  Unicode.ConfusablesTableFacts56

  Chunk facts for generated confusables chunk 56.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk56_chain :
    Unicode.Generated.Confusables.mappingsChunk56.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk56_expansion :
    Unicode.Generated.Confusables.mappingsChunk56.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
