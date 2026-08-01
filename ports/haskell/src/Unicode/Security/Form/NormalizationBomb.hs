{-|
Module      : Unicode.Security.Form.NormalizationBomb
Description : Normalization-expansion-bomb detector (F1).

Haskell port of @Unicode.Security.Form.NormalizationBomb@ from unicode-lean.

Detects inputs whose NFD or NFKD expansion exceeds documented bounds — the
normalization-expansion DoS, where a small input expands to a very large
normalized form (Arabic ligature U+FDFA → 18 codepoints under NFKD). Pure
functional: compute NFD and NFKD lengths, then three priority-ordered checks
— a per-codepoint NFKD blow-up scan, an overall NFKD ratio, an overall NFD
ratio. Ratios are expressed in hundredths to avoid floats.
-}
module Unicode.Security.Form.NormalizationBomb
  ( Detection (Detection, detectionSub, detectionPositions)
  , detect
  ) where

import Unicode.Normalization.NFD (toNFD)
import Unicode.Normalization.NFKD (toNFKD)

-- | Maximum allowed NFKD expansion per single codepoint (Hangul ≤ 3, Greek
-- extended 4, largest non-FDFA Arabic ligature 8); anything greater is flagged.
maxNfkdPerCp :: Int
maxNfkdPerCp = 8

-- | Overall-sequence NFD expansion ratio threshold, in hundredths (300 = 3×).
nfdRatioPct :: Int
nfdRatioPct = 300

-- | Overall-sequence NFKD expansion ratio threshold, in hundredths (400 = 4×).
nfkdRatioPct :: Int
nfkdRatioPct = 400

-- | One normalization-bomb scan result: the sub-threat tag (@Nothing@ when
-- clear) and the implicated positions (the blow-up index; empty for ratios).
data Detection = Detection
  { detectionSub       :: !(Maybe String)
  , detectionPositions :: ![Int]
  }
  deriving stock (Eq, Show)

-- | First position whose single-codepoint NFKD expansion exceeds
-- 'maxNfkdPerCp', with the codepoint and its expansion length.
firstBlowupCp :: [Int] -> Maybe (Int, Int, Int)
firstBlowupCp input =
  case [ (index, cp, expand)
       | (index, cp) <- zip [0 ..] input
       , let expand = length (toNFKD [cp])
       , expand > maxNfkdPerCp
       ] of
    (hit : _rest) -> Just hit
    []            -> Nothing

-- | NFD ratio percentage (@100 * nfdLen / inputLen@); 0 on empty input.
nfdRatioPctOf :: [Int] -> Int
nfdRatioPctOf input
  | null input = 0
  | otherwise  = length (toNFD input) * 100 `div` length input

-- | NFKD ratio percentage (@100 * nfkdLen / inputLen@); 0 on empty input.
nfkdRatioPctOf :: [Int] -> Int
nfkdRatioPctOf input
  | null input = 0
  | otherwise  = length (toNFKD input) * 100 `div` length input

-- | Detect a normalization-expansion bomb. Priority: per-codepoint blow-up,
-- then overall NFKD ratio, then overall NFD ratio.
detect :: [Int] -> Detection
detect input =
  case firstBlowupCp input of
    Just (pos, _cp, _expand) -> Detection (Just "SingleCpBlowup") [pos]
    Nothing
      | nfkdRatioPctOf input > nfkdRatioPct -> Detection (Just "NfkdHighExpansion") []
      | nfdRatioPctOf input > nfdRatioPct   -> Detection (Just "NfdHighExpansion") []
      | otherwise                           -> Detection Nothing []
