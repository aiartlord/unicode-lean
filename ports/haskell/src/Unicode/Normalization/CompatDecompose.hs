{-|
Module      : Unicode.Normalization.CompatDecompose
Description : Compatibility decomposition for NFKD (UAX #15).

Haskell port of @Unicode.Normalization.CompatDecompose@ from
unicode-lean.

Fully decomposes each codepoint per UAX #15 NFKD: Hangul syllables
decompose algorithmically; otherwise canonical mappings apply first and
compatibility mappings second, recursively to a fixed point. Canonical
combining class and canonical decomposition come from the shared
'Unicode.Normalization.Lookup' accessors over the generated NFC-relevant
subset; the compatibility mappings — which that subset omits by
construction — are loaded here from the pinned @UnicodeData.txt@
(Decomposition_Mapping column, @\<tag\>@-prefixed rows), matching the
runtime-table idiom the security layer already uses for its own tables.
-}
module Unicode.Normalization.CompatDecompose
  ( fullCompatDecompose
  , compatDecomposeSequence
  ) where

import Data.Char (isSpace)
import Data.List (dropWhileEnd, stripPrefix)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe, mapMaybe)
import Numeric (readHex)
import System.IO.Unsafe (unsafePerformIO)

import Paths_unicode_haskell (getDataFileName)
import Unicode.Normalization.Hangul (decomposeSyllable)
import Unicode.Normalization.Lookup (canonicalDecomposition)

-- | Maximum recursion depth for compatibility decomposition. UAX #15
-- bounds the longest decomposition chain at a small integer; 32 leaves a
-- comfortable margin over every published UCD.
maxDepth :: Int
maxDepth = 32

-- | Compatibility decomposition mappings, keyed by codepoint. Parsed once
-- from @UnicodeData.txt@ and memoised. Codepoints without a compatibility
-- mapping are absent.
compatibilityMap :: Map Int [Int]
compatibilityMap = unsafePerformIO $ do
  path <- getDataFileName "data/UnicodeData.txt"
  parseCompatibilityMappings <$> readFile path
{-# NOINLINE compatibilityMap #-}

-- | Compatibility decomposition target for a codepoint, or the empty list
-- when it has none.
compatDecomposition :: Int -> [Int]
compatDecomposition cp = Map.findWithDefault [] cp compatibilityMap

-- | Fully decompose a single codepoint per UAX #15 NFKD, applying
-- canonical mappings first and compatibility mappings second until a
-- fixed point. Returns @[cp]@ when the codepoint has no decomposition.
-- @fuel@ bounds recursion depth; exhaustion returns the partial
-- expansion, unreachable under 'maxDepth' on any real UCD release.
fullCompatDecomposeFuel :: Int -> Int -> [Int]
fullCompatDecomposeFuel 0 cp = [cp]
fullCompatDecomposeFuel fuel cp =
  case decomposeSyllable cp of
    Just jamo -> jamo
    Nothing ->
      let canon = canonicalDecomposition cp
      in if null canon
           then
             let compat = compatDecomposition cp
             in if null compat
                  then [cp]
                  else concatMap (fullCompatDecomposeFuel (fuel - 1)) compat
           else concatMap (fullCompatDecomposeFuel (fuel - 1)) canon

-- | Fully compatibility-decompose a single codepoint at the default depth.
fullCompatDecompose :: Int -> [Int]
fullCompatDecompose = fullCompatDecomposeFuel maxDepth

-- | Fully compatibility-decompose a codepoint sequence, concatenating each
-- codepoint's expansion in order.
compatDecomposeSequence :: [Int] -> [Int]
compatDecomposeSequence = concatMap fullCompatDecompose

-- ─────────────────────────────────────────────────────────────────────
-- UnicodeData.txt Decomposition_Mapping parsing (compatibility rows only)
-- ─────────────────────────────────────────────────────────────────────

parseCompatibilityMappings :: String -> Map Int [Int]
parseCompatibilityMappings =
  Map.fromList . mapMaybe parseCompatibilityLine . lines

-- | A UnicodeData.txt row contributes a mapping only when its
-- Decomposition_Mapping field (column 5) is a compatibility decomposition —
-- a @\<tag\>@-prefixed sequence. The tag is stripped and the remaining
-- codepoints kept. A row lacking column 0 or 5, or whose mapping is
-- canonical or empty, contributes nothing: each @Maybe@ bind short-circuits.
parseCompatibilityLine :: String -> Maybe (Int, [Int])
parseCompatibilityLine raw = do
  let fields = splitFields ';' raw
  cpField       <- nthField 0 fields
  decompField   <- nthField 5 fields
  cp            <- parseHexInt cpField
  compatTargets <- taggedCompatTargets (trim decompField)
  Just (cp, compatTargets)

-- | The compatibility targets a Decomposition_Mapping field encodes:
-- @Just cps@ for a non-empty @\<tag\>@-prefixed mapping; @Nothing@ for an
-- empty field, or a canonical (untagged) mapping, which carry no
-- compatibility decomposition. 'stripPrefix' distinguishes the two cases
-- through @Maybe@'s constructors — no catch-all.
taggedCompatTargets :: String -> Maybe [Int]
taggedCompatTargets decompField =
  case stripPrefix "<" decompField of
    Just tagged ->
      let afterTag      = drop 1 (dropWhile (/= '>') tagged)
          compatTargets = mapMaybe parseHexInt (words afterTag)
      in if null compatTargets then Nothing else Just compatTargets
    Nothing -> Nothing

-- | The @n@th (zero-based) field of a split row, if present.
nthField :: Int -> [String] -> Maybe String
nthField n fields = listToMaybe (drop n fields)

-- | Split a string into fields on a delimiter. Every emitted field is the
-- run of characters up to the next delimiter; the delimiter itself is
-- consumed. Recurses on the tail after the matched delimiter.
splitFields :: Char -> String -> [String]
splitFields delimiter s =
  let (field, remainder) = break (== delimiter) s
  in if null remainder
       then [field]
       else field : splitFields delimiter (drop 1 remainder)

-- | Parse a hexadecimal integer, requiring the whole (trimmed) string to be
-- consumed. The list comprehension keeps only complete parses (empty
-- remainder); 'listToMaybe' takes the first.
parseHexInt :: String -> Maybe Int
parseHexInt s = listToMaybe [ value | (value, "") <- readHex (trim s) ]

trim :: String -> String
trim = dropWhileEnd isSpace . dropWhile isSpace
