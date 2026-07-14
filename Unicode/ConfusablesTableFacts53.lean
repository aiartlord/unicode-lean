/-
  Unicode.ConfusablesTableFacts53

  Chunk facts for generated confusables chunk 53.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk53_chain :
    Unicode.Generated.Confusables.mappingsChunk53.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk53_expansion :
    Unicode.Generated.Confusables.mappingsChunk53.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
