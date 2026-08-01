{-|
Module      : Unicode.Security.Form.NfcIdempotenceWitness
Description : NFC-idempotence-witness detector (F6).

Haskell port of @Unicode.Security.Form.NfcIdempotenceWitness@ from
unicode-lean.

Detects inputs that are not already in NFC (or, failing that, not in NFKC) —
the silent normalization-drift class where a signer and verifier pick
different canonical forms and their hashes diverge. Compares @input@
element-wise against @toNFC input@ then @toNFKC input@, reporting the first
divergent position: a mismatch against NFC is @NonNfcForm@; a sequence already
in NFC but not NFKC is @NonNfkcCompatForm@.
-}
module Unicode.Security.Form.NfcIdempotenceWitness
  ( Detection (Detection, detectionSub, detectionPositions)
  , detect
  ) where

import Unicode.Normalization.NFC (toNFC)
import Unicode.Normalization.NFKC (toNFKC)

-- | One NFC-idempotence-witness scan result: the divergence tag (@Nothing@
-- when the input is already NFC- and NFKC-stable) and the first divergent
-- position.
data Detection = Detection
  { detectionSub       :: !(Maybe String)
  , detectionPositions :: ![Int]
  }
  deriving stock (Eq, Show)

-- | First index at which two sequences diverge (in element, or one ends);
-- @Nothing@ when identical.
firstDivergence :: [Int] -> [Int] -> Maybe Int
firstDivergence = go 0
  where
    go _index [] [] = Nothing
    go index [] (_y : _ys) = Just index
    go index (_x : _xs) [] = Just index
    go index (x : xs) (y : ys)
      | x /= y    = Just index
      | otherwise = go (index + 1) xs ys

-- | Detect an input not in canonical (NFC), or not in compatibility (NFKC),
-- form. NFC divergence takes priority over NFKC.
detect :: [Int] -> Detection
detect input =
  case firstDivergence input (toNFC input) of
    Just pos -> Detection (Just "NonNfcForm") [pos]
    Nothing ->
      case firstDivergence input (toNFKC input) of
        Just pos -> Detection (Just "NonNfkcCompatForm") [pos]
        Nothing  -> Detection Nothing []
