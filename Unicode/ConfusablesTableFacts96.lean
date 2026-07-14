/-
  Unicode.ConfusablesTableFacts96

  Chunk facts for generated confusables chunk 96.
-/

import Unicode.ConfusablesTableFactsCore

namespace Unicode.Confusables

open Unicode.Generated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem mappingsChunk96_chain :
    Unicode.Generated.Confusables.mappingsChunk96.all chainConvergesEntry = true := by
  decide +kernel

theorem mappingsChunk96_expansion :
    Unicode.Generated.Confusables.mappingsChunk96.all (expansionEntryUnderBound 18) = true := by
  decide +kernel

end Unicode.Confusables
