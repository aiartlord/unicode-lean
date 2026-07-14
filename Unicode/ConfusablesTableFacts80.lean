/-
  Unicode.ConfusablesTableFacts80

  Chunk facts for generated confusables chunk 80.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk80_chain :
    Unicode.Generated.Confusables.mappingsChunk80.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk80_expansion :
    Unicode.Generated.Confusables.mappingsChunk80.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
