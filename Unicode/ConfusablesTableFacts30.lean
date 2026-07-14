/-
  Unicode.ConfusablesTableFacts30

  Chunk facts for generated confusables chunk 30.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk30_chain :
    Unicode.Generated.Confusables.mappingsChunk30.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk30_expansion :
    Unicode.Generated.Confusables.mappingsChunk30.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
