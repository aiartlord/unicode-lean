/-
  Unicode.ConfusablesTableFacts18

  Chunk facts for generated confusables chunk 18.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk18_chain :
    Unicode.Generated.Confusables.mappingsChunk18.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk18_expansion :
    Unicode.Generated.Confusables.mappingsChunk18.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
