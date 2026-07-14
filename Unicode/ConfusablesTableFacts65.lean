/-
  Unicode.ConfusablesTableFacts65

  Chunk facts for generated confusables chunk 65.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk65_chain :
    Unicode.Generated.Confusables.mappingsChunk65.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk65_expansion :
    Unicode.Generated.Confusables.mappingsChunk65.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
