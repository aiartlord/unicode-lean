/-
  Unicode.ConfusablesTableFacts78

  Chunk facts for generated confusables chunk 78.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk78_chain :
    Unicode.Generated.Confusables.mappingsChunk78.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk78_expansion :
    Unicode.Generated.Confusables.mappingsChunk78.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
