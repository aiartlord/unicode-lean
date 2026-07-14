/-
  Unicode.ConfusablesTableFacts63

  Chunk facts for generated confusables chunk 63.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk63_chain :
    Unicode.Generated.Confusables.mappingsChunk63.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk63_expansion :
    Unicode.Generated.Confusables.mappingsChunk63.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
