/-
  Unicode.ConfusablesTableFacts98

  Chunk facts for generated confusables chunk 98.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk98_chain :
    Unicode.Generated.Confusables.mappingsChunk98.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk98_expansion :
    Unicode.Generated.Confusables.mappingsChunk98.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
