/-
  Unicode.ConfusablesTableFacts36

  Chunk facts for generated confusables chunk 36.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk36_chain :
    Unicode.Generated.Confusables.mappingsChunk36.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk36_expansion :
    Unicode.Generated.Confusables.mappingsChunk36.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
