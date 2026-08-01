{-|
Module      : Unicode.Normalization.NFC
Description : Normalization Form C (UAX #15 §1.3).

Haskell port of @Unicode.Normalization.NFC@ from unicode-lean.

@toNFC = compose . toNFD@ — canonical decomposition and reordering, then
canonical composition.
-}
module Unicode.Normalization.NFC
  ( toNFC
  ) where

import Unicode.Normalization.Compose (compose)
import Unicode.Normalization.NFD (toNFD)

-- | Normalize a codepoint sequence to NFC.
toNFC :: [Int] -> [Int]
toNFC = compose . toNFD
