{-|
Module      : Unicode.Normalization.NFKC
Description : Normalization Form KC (UAX #15 §1.3).

Haskell port of @Unicode.Normalization.NFKC@ from unicode-lean.

@toNFKC = compose . toNFKD@ — compatibility decomposition and reordering,
then canonical composition.
-}
module Unicode.Normalization.NFKC
  ( toNFKC
  ) where

import Unicode.Normalization.Compose (compose)
import Unicode.Normalization.NFKD (toNFKD)

-- | Normalize a codepoint sequence to NFKC.
toNFKC :: [Int] -> [Int]
toNFKC = compose . toNFKD
