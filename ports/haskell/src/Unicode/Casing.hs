{-|
Module      : Unicode.Casing
Description : UAX #21 case mapping (toLower / per-codepoint upper).

Haskell port of @Unicode.Casing@ from unicode-lean.

Full lowercase mapping per UAX #21: @SpecialCasing.txt@ supplies the
one-to-many and context/locale-dependent rows, and the simple lowercase
mapping (UnicodeData.txt column 13) is the fallback. The four context
conditions — Final_Sigma, After_Soft_Dotted, More_Above, Not_Before_Dot
(plus After_I for the Turkic locales) — read canonical combining class,
via the shared 'Unicode.Normalization.Lookup' accessor, together with the
@Cased@ and @Soft_Dotted@ properties from @DerivedCoreProperties.txt@.

The uppercase side, 'upperCodepoint', mirrors 'lowerCodepoint' exactly: it
reuses the same SpecialCasing row selection and context predicates but
returns the row's uppercase column (@SpecialCasing.txt@ field 3), falling
back to the simple uppercase mapping (UnicodeData.txt column 12). Only the
mapped column differs; the context machinery is shared.

This is a shared primitive: the bip39-canonical detector lowercases
through @toLower Default@, and the case-expansion-mismatch detector reads
per-codepoint lengths through 'lowerCodepoint' and 'upperCodepoint'. The
tables load once, at first use, through the same NOINLINE runtime-table
idiom the security layer already uses.
-}
module Unicode.Casing
  ( Locale (Default, Turkish, Azeri, Lithuanian)
  , toLower
  , lowerCodepoint
  , upperCodepoint
  ) where

import Data.Char (isSpace)
import Data.List (dropWhileEnd, stripPrefix)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe, mapMaybe)
import Data.Word (Word8)
import Numeric (readHex)
import System.IO.Unsafe (unsafePerformIO)

import Paths_unicode_haskell (getDataFileName)
import Unicode.Normalization.Lookup (canonicalCombiningClass)

-- | The locales that SpecialCasing.txt distinguishes. 'Default' covers
-- every locale not tagged Turkish, Azeri, or Lithuanian.
data Locale
  = Default
  | Turkish
  | Azeri
  | Lithuanian
  deriving stock (Eq, Show)

-- | A SpecialCasing.txt condition token. The three @Lang*@ tags select a
-- locale; the five context conditions read the surrounding text; 'Other'
-- carries any token outside this vocabulary (which never holds), mirroring
-- the @Condition@ inductive in the Lean source.
data Condition
  = LangTr
  | LangAz
  | LangLt
  | FinalSigma
  | NotFinalSigma
  | AfterSoftDotted
  | MoreAbove
  | NotBeforeDot
  | AfterI
  | Other String
  deriving stock (Eq, Show)

-- | A parsed SpecialCasing.txt row: the source codepoint, its full
-- lowercase mapping, its full uppercase mapping, and the (possibly empty)
-- condition list.
data SpecialRow = SpecialRow
  { rowCode       :: !Int
  , rowLower      :: ![Int]
  , rowUpper      :: ![Int]
  , rowConditions :: ![Condition]
  }

-- | An inclusive codepoint range from a DerivedCoreProperties property.
data Range = Range
  { rangeLo :: !Int
  , rangeHi :: !Int
  }

-- ─────────────────────────────────────────────────────────────────────
-- Runtime tables (SpecialCasing rows, simple lowercase, Cased/Soft_Dotted)
-- ─────────────────────────────────────────────────────────────────────

specialCasingRows :: [SpecialRow]
specialCasingRows = unsafePerformIO $ do
  path <- getDataFileName "data/SpecialCasing.txt"
  mapMaybe parseSpecialCasingLine . lines <$> readFile path
{-# NOINLINE specialCasingRows #-}

simpleLowercaseMap :: Map Int Int
simpleLowercaseMap = unsafePerformIO $ do
  path <- getDataFileName "data/UnicodeData.txt"
  parseSimpleLowercase <$> readFile path
{-# NOINLINE simpleLowercaseMap #-}

simpleUppercaseMap :: Map Int Int
simpleUppercaseMap = unsafePerformIO $ do
  path <- getDataFileName "data/UnicodeData.txt"
  parseSimpleUppercase <$> readFile path
{-# NOINLINE simpleUppercaseMap #-}

casedRanges :: [Range]
casedRanges = unsafePerformIO $ do
  path <- getDataFileName "data/DerivedCoreProperties.txt"
  parseDerivedProperty "Cased" <$> readFile path
{-# NOINLINE casedRanges #-}

softDottedRanges :: [Range]
softDottedRanges = unsafePerformIO $ do
  path <- getDataFileName "data/DerivedCoreProperties.txt"
  parseDerivedProperty "Soft_Dotted" <$> readFile path
{-# NOINLINE softDottedRanges #-}

-- | Simple lowercase (UnicodeData.txt column 13); a codepoint absent from
-- the map lowercases to itself.
simpleLowercase :: Int -> Int
simpleLowercase cp = Map.findWithDefault cp cp simpleLowercaseMap

-- | Simple uppercase (UnicodeData.txt column 12); a codepoint absent from
-- the map uppercases to itself.
simpleUppercase :: Int -> Int
simpleUppercase cp = Map.findWithDefault cp cp simpleUppercaseMap

inRanges :: [Range] -> Int -> Bool
inRanges ranges cp = any (\r -> rangeLo r <= cp && cp <= rangeHi r) ranges

isCased :: Int -> Bool
isCased = inRanges casedRanges

isSoftDotted :: Int -> Bool
isSoftDotted = inRanges softDottedRanges

-- ─────────────────────────────────────────────────────────────────────
-- Context predicates (UAX #21). @revPrefix@ is the preceding codepoints
-- nearest-first; @suffix@ the strictly-following ones.
-- ─────────────────────────────────────────────────────────────────────

ccc :: Int -> Word8
ccc = canonicalCombiningClass

-- | More_Above: a ccc=230 mark follows before the next ccc=0 break.
moreAboveAfter :: [Int] -> Bool
moreAboveAfter [] = False
moreAboveAfter (cp : rest)
  | ccc cp == 230 = True
  | ccc cp == 0   = False
  | otherwise     = moreAboveAfter rest

-- | After_Soft_Dotted: the last preceding base is Soft_Dotted (searching
-- nearest-first, stopping at the next ccc=0 or ccc=230 break).
afterSoftDotted :: [Int] -> Bool
afterSoftDotted [] = False
afterSoftDotted (cp : rest)
  | isSoftDotted cp              = True
  | ccc cp == 230 || ccc cp == 0 = False
  | otherwise                    = afterSoftDotted rest

-- | After_I: an uppercase @I@ (U+0049) precedes before the next
-- above/base break.
afterI :: [Int] -> Bool
afterI [] = False
afterI (cp : rest)
  | cp == 0x0049                 = True
  | ccc cp == 230 || ccc cp == 0 = False
  | otherwise                    = afterI rest

-- | Before_Dot: a U+0307 follows before the next ccc=0 break.
beforeDot :: [Int] -> Bool
beforeDot [] = False
beforeDot (cp : rest)
  | cp == 0x0307 = True
  | ccc cp == 0  = False
  | otherwise    = beforeDot rest

-- | Nearest preceding cased character, skipping combining marks up to the
-- next starter.
hasCasedBefore :: [Int] -> Bool
hasCasedBefore [] = False
hasCasedBefore (cp : rest)
  | isCased cp  = True
  | ccc cp == 0 = False
  | otherwise   = hasCasedBefore rest

-- | Next following character (skipping combining marks) is cased.
hasCasedAfter :: [Int] -> Bool
hasCasedAfter [] = False
hasCasedAfter (cp : rest)
  | isCased cp  = True
  | ccc cp == 0 = False
  | otherwise   = hasCasedAfter rest

-- | Final_Sigma: a cased character precedes and none follows.
finalSigma :: [Int] -> [Int] -> Bool
finalSigma revPrefix suffix = hasCasedBefore revPrefix && not (hasCasedAfter suffix)

-- ─────────────────────────────────────────────────────────────────────
-- Condition evaluation and row selection
-- ─────────────────────────────────────────────────────────────────────

-- | True for the three locale-selecting condition tags.
isLocaleCondition :: Condition -> Bool
isLocaleCondition LangTr          = True
isLocaleCondition LangAz          = True
isLocaleCondition LangLt          = True
isLocaleCondition FinalSigma      = False
isLocaleCondition NotFinalSigma   = False
isLocaleCondition AfterSoftDotted = False
isLocaleCondition MoreAbove       = False
isLocaleCondition NotBeforeDot    = False
isLocaleCondition AfterI          = False
isLocaleCondition (Other _token)  = False

-- | Whether a single locale-tag condition selects the chosen locale.
-- Non-locale conditions never select a locale.
localeConditionMatches :: Locale -> Condition -> Bool
localeConditionMatches loc LangTr          = loc == Turkish
localeConditionMatches loc LangAz          = loc == Azeri
localeConditionMatches loc LangLt          = loc == Lithuanian
localeConditionMatches _loc FinalSigma      = False
localeConditionMatches _loc NotFinalSigma   = False
localeConditionMatches _loc AfterSoftDotted = False
localeConditionMatches _loc MoreAbove       = False
localeConditionMatches _loc NotBeforeDot    = False
localeConditionMatches _loc AfterI          = False
localeConditionMatches _loc (Other _token)  = False

-- | A row with no locale-tagged condition matches every locale; a
-- locale-tagged row matches only its own locale.
localeMatches :: Locale -> [Condition] -> Bool
localeMatches loc conds =
  if any isLocaleCondition conds
    then any (localeConditionMatches loc) conds
    else True

-- | Evaluate one condition against the locale and context. A locale-tag
-- condition is handled by 'localeMatches' and holds here; an 'Other'
-- (unrecognised) token never holds.
conditionHolds :: Locale -> [Int] -> [Int] -> Condition -> Bool
conditionHolds _loc _revPrefix _suffix LangTr          = True
conditionHolds _loc _revPrefix _suffix LangAz          = True
conditionHolds _loc _revPrefix _suffix LangLt          = True
conditionHolds _loc revPrefix  suffix  FinalSigma      = finalSigma revPrefix suffix
conditionHolds _loc revPrefix  suffix  NotFinalSigma   = not (finalSigma revPrefix suffix)
conditionHolds _loc revPrefix  _suffix AfterSoftDotted = afterSoftDotted revPrefix
conditionHolds _loc _revPrefix suffix  MoreAbove       = moreAboveAfter suffix
conditionHolds _loc _revPrefix suffix  NotBeforeDot    = not (beforeDot suffix)
conditionHolds _loc revPrefix  _suffix AfterI          = afterI revPrefix
conditionHolds _loc _revPrefix _suffix (Other _token)  = False

-- | Every condition in a row's list holds, under the chosen locale.
conditionsHold :: Locale -> [Int] -> [Int] -> [Condition] -> Bool
conditionsHold loc revPrefix suffix conds =
  localeMatches loc conds
    && all (conditionHolds loc revPrefix suffix) conds

-- | The most-specific applicable SpecialCasing row for @cp@ in context: a
-- conditional row whose conditions hold outranks the unconditional row.
findSpecialRow :: Locale -> [Int] -> [Int] -> Int -> Maybe SpecialRow
findSpecialRow loc revPrefix suffix cp =
  case listToMaybe conditionalMatches of
    Just row -> Just row
    Nothing  -> listToMaybe unconditionalMatches
  where
    conditionalMatches =
      [ row
      | row <- specialCasingRows
      , rowCode row == cp
      , not (null (rowConditions row))
      , conditionsHold loc revPrefix suffix (rowConditions row)
      ]
    unconditionalMatches =
      [ row
      | row <- specialCasingRows
      , rowCode row == cp
      , null (rowConditions row)
      ]

-- | Lowercase a single codepoint in context, falling back to the simple
-- lowercase mapping when no SpecialCasing row applies.
lowerCodepoint :: Locale -> [Int] -> [Int] -> Int -> [Int]
lowerCodepoint loc revPrefix suffix cp =
  case findSpecialRow loc revPrefix suffix cp of
    Just row -> rowLower row
    Nothing  -> [simpleLowercase cp]

-- | Uppercase a single codepoint in context, falling back to the simple
-- uppercase mapping when no SpecialCasing row applies. Mirrors
-- 'lowerCodepoint' exactly, sharing 'findSpecialRow' and the context
-- predicates; only the mapped column differs (uppercase vs lowercase).
upperCodepoint :: Locale -> [Int] -> [Int] -> Int -> [Int]
upperCodepoint loc revPrefix suffix cp =
  case findSpecialRow loc revPrefix suffix cp of
    Just row -> rowUpper row
    Nothing  -> [simpleUppercase cp]

-- | Lowercase a codepoint sequence under @loc@, carrying processed
-- codepoints as a nearest-first prefix so each position reads its context.
toLowerGo :: Locale -> [Int] -> [Int] -> [Int]
toLowerGo _loc _revPrefix [] = []
toLowerGo loc revPrefix (cp : suffix) =
  lowerCodepoint loc revPrefix suffix cp ++ toLowerGo loc (cp : revPrefix) suffix

-- | Lowercase a codepoint sequence under the given locale (UAX #21 full
-- mapping).
toLower :: Locale -> [Int] -> [Int]
toLower loc = toLowerGo loc []

-- ─────────────────────────────────────────────────────────────────────
-- Data-file parsing
-- ─────────────────────────────────────────────────────────────────────

-- | Classify a SpecialCasing.txt condition token into the 'Condition'
-- vocabulary; anything outside it becomes 'Other'.
parseCondition :: String -> Condition
parseCondition token =
  case token of
    "tr"                -> LangTr
    "az"                -> LangAz
    "lt"                -> LangLt
    "Final_Sigma"       -> FinalSigma
    "Not_Final_Sigma"   -> NotFinalSigma
    "After_Soft_Dotted" -> AfterSoftDotted
    "More_Above"        -> MoreAbove
    "Not_Before_Dot"    -> NotBeforeDot
    "After_I"           -> AfterI
    unknownToken        -> Other unknownToken

-- | Parse one SpecialCasing.txt row into a @SpecialRow@. Only rows with a
-- lowercase mapping and at least the code and lower fields contribute; the
-- uppercase field (column 3) and condition field (column 4) are captured
-- when present, mirroring the row shape @code; lower; title; upper; conditions@.
parseSpecialCasingLine :: String -> Maybe SpecialRow
parseSpecialCasingLine raw = do
  let fields = splitFields ';' (stripComment raw)
  codeField  <- nthField 0 fields
  lowerField <- nthField 1 fields
  code       <- parseHexInt codeField
  let lower      = mapMaybe parseHexInt (words lowerField)
      upper      = mapMaybe parseHexInt (maybe [] words (nthField 3 fields))
      conditions = map parseCondition (maybe [] words (nthField 4 fields))
  if null lower then Nothing else Just (SpecialRow code lower upper conditions)

-- | Parse the simple lowercase mapping (column 13) from UnicodeData.txt.
parseSimpleLowercase :: String -> Map Int Int
parseSimpleLowercase =
  Map.fromList . mapMaybe parseSimpleLowercaseLine . lines

parseSimpleLowercaseLine :: String -> Maybe (Int, Int)
parseSimpleLowercaseLine raw = do
  let fields = splitFields ';' raw
  codeField  <- nthField 0 fields
  lowerField <- nthField 13 fields
  code       <- parseHexInt codeField
  lower      <- parseHexInt lowerField
  Just (code, lower)

-- | Parse the simple uppercase mapping (column 12) from UnicodeData.txt.
parseSimpleUppercase :: String -> Map Int Int
parseSimpleUppercase =
  Map.fromList . mapMaybe parseSimpleUppercaseLine . lines

parseSimpleUppercaseLine :: String -> Maybe (Int, Int)
parseSimpleUppercaseLine raw = do
  let fields = splitFields ';' raw
  codeField  <- nthField 0 fields
  upperField <- nthField 12 fields
  code       <- parseHexInt codeField
  upper      <- parseHexInt upperField
  Just (code, upper)

-- | Parse the inclusive ranges of a single DerivedCoreProperties property.
parseDerivedProperty :: String -> String -> [Range]
parseDerivedProperty propertyName =
  mapMaybe (parseDerivedPropertyLine propertyName) . lines

parseDerivedPropertyLine :: String -> String -> Maybe Range
parseDerivedPropertyLine propertyName raw = do
  let fields = splitFields ';' (stripComment raw)
  rangeField    <- nthField 0 fields
  propertyField <- nthField 1 fields
  if trim propertyField == propertyName
    then parseRange (trim rangeField)
    else Nothing

-- | Parse a DerivedCoreProperties range field: @LO..HI@ or a single @CP@.
parseRange :: String -> Maybe Range
parseRange field =
  case stripInfix ".." field of
    Just (loText, hiText) -> do
      lo <- parseHexInt loText
      hi <- parseHexInt hiText
      Just (Range lo hi)
    Nothing -> do
      cp <- parseHexInt field
      Just (Range cp cp)

-- ─────────────────────────────────────────────────────────────────────
-- Small parsing helpers (explicit, total)
-- ─────────────────────────────────────────────────────────────────────

-- | Drop a @#@-introduced trailing comment.
stripComment :: String -> String
stripComment = takeWhile (/= '#')

-- | The @n@th (zero-based) field of a split row, if present.
nthField :: Int -> [String] -> Maybe String
nthField n fields = listToMaybe (drop n fields)

splitFields :: Char -> String -> [String]
splitFields delimiter s =
  let (field, remainder) = break (== delimiter) s
  in if null remainder
       then [field]
       else field : splitFields delimiter (drop 1 remainder)

-- | Split a string at the first occurrence of an infix separator, if present.
stripInfix :: String -> String -> Maybe (String, String)
stripInfix separator = go ""
  where
    go acc rest =
      case stripPrefix separator rest of
        Just after -> Just (reverse acc, after)
        Nothing ->
          case rest of
            []              -> Nothing
            headChar : more -> go (headChar : acc) more

parseHexInt :: String -> Maybe Int
parseHexInt s = listToMaybe [ value | (value, "") <- readHex (trim s) ]

trim :: String -> String
trim = dropWhileEnd isSpace . dropWhile isSpace
