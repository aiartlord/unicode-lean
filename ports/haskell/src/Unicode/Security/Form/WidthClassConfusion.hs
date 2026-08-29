{-|
Module      : Unicode.Security.Form.WidthClassConfusion
Description : Width-class-confusion detector.

Haskell port of @Unicode.Security.Form.WidthClassConfusion@ from
unicode-lean.

Detects UAX #11 East Asian Width class confusion: an input containing a
Fullwidth (EAW = F) or Halfwidth (EAW = H) codepoint whose NFKD form carries a
different EAW class. These are the canonical compatibility-fold homograph
shapes:

* @U+FF21 'Ａ'@ (F) folds to @U+0041 'A'@ (Na)
* @U+FF11 '１'@ (F) folds to @U+0031 '1'@ (Na)
* @U+FF71 'ｱ'@ (H) folds to @U+30A2 'ア'@ (W)

The two-system bypass: a validator that whitelists ASCII rejects @Ａ@, while a
downstream NFKC step at storage or comparison time folds it to plain @A@, so
@ＡＤＭＩＮ@ claims the username @ADMIN@ against a system that did not
normalise before whitelisting.

Distinct from @RendererDivergence@'s @FullwidthVariance@, which fires on
F-class codepoints for renderer-cohort reasons; this is the NFKC-fold verdict,
and the two can fire on one input independently. Hangul syllables decompose to
jamos that are still W class, so pure Hangul stays clear.
-}
module Unicode.Security.Form.WidthClassConfusion
  ( Detection (Detection, detectionSub, detectionPositions)
  , detect
  , eastAsianWidth
  ) where

import Data.List (find)

import Unicode.Generated.EastAsianWidth (EastAsianWidth (EawF, EawH, EawN), explicitRanges)
import Unicode.Normalization.NFKD (toNFKD)

-- | One width-class-confusion scan result: the fold tag (@Nothing@ when the
-- input is clear) and the single position the fold was found at.
data Detection = Detection
  { detectionSub       :: !(Maybe String)
  , detectionPositions :: ![Int]
  }
  deriving stock (Eq, Show)

-- | @East_Asian_Width@ of a codepoint. The UCD file's @\@missing@ line
-- declares @N@ over the whole space, so an unlisted codepoint is 'EawN'.
eastAsianWidth :: Int -> EastAsianWidth
eastAsianWidth cp =
  case find inRange explicitRanges of
    Just (_lo, _hi, cls) -> cls
    Nothing              -> EawN
  where
    inRange (lo, hi, _cls) = lo <= cp && cp <= hi

-- | True iff the NFKD head of the codepoint carries a different EAW class.
hasWidthFold :: Int -> Bool
hasWidthFold cp =
  case toNFKD [cp] of
    []           -> False
    (headCp : _) -> eastAsianWidth headCp /= eastAsianWidth cp

-- | First position whose codepoint has the given class and folds away from it.
firstFold :: EastAsianWidth -> [Int] -> Maybe Int
firstFold want input =
  fmap fst (find matches (zip [0 ..] input))
  where
    matches (_index, cp) = eastAsianWidth cp == want && hasWidthFold cp

-- | Classify a codepoint sequence. A Fullwidth fold takes priority over a
-- Halfwidth one, matching the reference's sub-threat order.
detect :: [Int] -> Detection
detect input =
  case firstFold EawF input of
    Just pos -> Detection (Just "FullwidthFold") [pos]
    Nothing ->
      case firstFold EawH input of
        Just pos -> Detection (Just "HalfwidthFold") [pos]
        Nothing  -> Detection Nothing []
