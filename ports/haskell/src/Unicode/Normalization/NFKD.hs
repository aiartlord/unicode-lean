{-|
Module      : Unicode.Normalization.NFKD
Description : Normalization Form KD (UAX #15 §1.3).

Haskell port of @Unicode.Normalization.NFKD@ from unicode-lean.

@toNFKD = reorder . compatDecomposeSequence@ — compatibility
decomposition followed by canonical reordering. Differs from NFD only in
the decomposition stage: NFD applies just canonical decomposition, NFKD
applies both canonical and compatibility decompositions. The reorder
stage is identical.
-}
module Unicode.Normalization.NFKD
  ( toNFKD
  ) where

import Unicode.Normalization.CompatDecompose (compatDecomposeSequence)
import Unicode.Normalization.Reorder (reorder)

-- | Normalize a codepoint sequence to NFKD.
toNFKD :: [Int] -> [Int]
toNFKD = reorder . compatDecomposeSequence
