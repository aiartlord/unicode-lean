{-|
Module      : Unicode.Security.Boundary.IdentifierFormDrift
Description : Cross-layer identifier × form drift (boundary-layer detector).

Haskell port of @Unicode.Security.Boundary.IdentifierFormDrift@ from
unicode-lean, transliterated byte-faithfully from the verified Rust reference
implementation (the boundary-layer detector, reason-code letter @X@).

Threat model. An identity validator and a form normalizer disagree about a
codepoint. Stage A runs the UTS #39 @Identifier_Status@ check before
normalisation and rejects, say, U+1D44E MATHEMATICAL ITALIC SMALL A
(Restricted); stage B normalises first and then runs the same check, seeing
U+0061 'a' (Allowed) and accepting. The attacker controls which stage
processes the input and exploits the disagreement. The same shape covers
fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01), and Roman-numeral
(U+2163) compatibility forms.

What the detector draws. It fires on the /form transition/ itself — it reports
every input position whose @Identifier_Status@ differs from the
@Identifier_Status@ of that codepoint's NFKD head. This is orthogonal to the
single-form identity-spoofing detectors and stronger than a form-of-input fold
(it asks whether the identifier verdict changes, not whether any output bit
changes).

Note on Hangul: precomposed syllables are Allowed while their NFKD-head jamos
are Restricted, so pure Korean text fires; callers intending to accept Korean
identifiers should apply NFC before evaluating admissibility.

It reuses the port's own predicates — the UTS #39 @Identifier_Status@ Allowed
set via 'isIdAllowed' (parsed from the bundled IdentifierStatus.txt) and the
NFKD pipeline via 'Unicode.Normalization.NFKD.toNFKD' — never a host
normalization or identifier library.

Sub-threat (direction-agnostic).

  1. 'IdentifierStatusShift' — the first input position whose @Identifier_Status@
     differs from its NFKD-head's. The verdict carries the total shift count.
-}
module Unicode.Security.Boundary.IdentifierFormDrift
  ( SubThreat (IdentifierStatusShift)
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classificationPositions
  , Verdict
      ( Verdict, verdictInput, verdictClassify, verdictShiftCount )
  , isIdAllowed
  , nfkdHeadAllowed
  , detect
  , reasonCode
  ) where

import Data.Char (isSpace)
import Data.List (dropWhileEnd)
import Data.Maybe (listToMaybe, mapMaybe)
import Numeric (readHex)
import System.IO.Unsafe (unsafePerformIO)

import Unicode.Normalization.NFKD (toNFKD)
import Paths_unicode_haskell (getDataFileName)

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- | Sub-threat enumeration for IdentifierFormDrift. There is exactly one
-- sub-threat; its payload carries the position and codepoint the conformance
-- harness's attribution column reads back, mirroring the Rust @SubThreat@
-- variant field-for-field.
data SubThreat
  = -- | A codepoint at the given position (the first 'Int') whose
    -- @Identifier_Status@ differs from its NFKD-head's (the second 'Int' is
    -- that status-shifting codepoint).
    IdentifierStatusShift Int Int
  deriving stock (Eq, Show)

-- | Fixture-row tag string for this sub-threat (matches @SubThreat.tag@).
subThreatTag :: SubThreat -> String
subThreatTag (IdentifierStatusShift _basePos _cp) = "IdentifierStatusShift"

-- | Top-level classification for IdentifierFormDrift (no shift = 'Clear').
data Classification
  = -- | No status shift present.
    Clear
  | -- | A status shift fired: the sub-threat, the implicated codepoint
    -- positions, and the decoded-byte projection (always @[]@ here; kept for
    -- shape parity with the Lean @Classification.hazard@).
    Hazard SubThreat [Int] [Int]
  deriving stock (Eq, Show)

-- | True iff the classification is 'Clear'.
classificationIsClear :: Classification -> Bool
classificationIsClear Clear               = True
classificationIsClear (Hazard _sub _p _d) = False

-- | Human-facing tag for a hazard, or 'Nothing' when clear.
classificationTag :: Classification -> Maybe String
classificationTag Clear                  = Nothing
classificationTag (Hazard sub _pos _dec) = Just (subThreatTag sub)

-- | Implicated positions ('[]' when clear).
classificationPositions :: Classification -> [Int]
classificationPositions Clear                      = []
classificationPositions (Hazard _sub positions _d) = positions

-- | Verdict — the structured output of 'detect' (mirrors the Lean @Verdict@).
data Verdict = Verdict
  { verdictInput      :: ![Int]
    -- ^ The scanned input codepoints.
  , verdictClassify   :: !Classification
    -- ^ The classification verdict.
  , verdictShiftCount :: !Int
    -- ^ Total count of positions whose status shifts under NFKD.
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- §2 Core predicates
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@ has UTS #39 @Identifier_Status = Allowed@. The Allowed set
-- is the range list parsed once from the bundled @IdentifierStatus.txt@
-- (UCD 17.0.0); every codepoint outside it is Restricted, per the table's
-- @\@missing: 0000..10FFFF; Restricted@ default.
isIdAllowed :: Int -> Bool
isIdAllowed cp = any inRange allowedRanges
  where
    inRange (lo, hi) = lo <= cp && cp <= hi

-- | @Identifier_Status = Allowed@ of the first codepoint of @cp@'s NFKD form,
-- or @cp@'s own status when NFKD is empty (defensive — 'toNFKD' is total and
-- returns at least @[cp]@). Reuses the port's own UTS #39 predicate and NFKD.
nfkdHeadAllowed :: Int -> Bool
nfkdHeadAllowed cp =
  case listToMaybe (toNFKD [cp]) of
    Just head_ -> isIdAllowed head_
    Nothing    -> isIdAllowed cp

-- ─────────────────────────────────────────────────────────────────────
-- §3 Sub-detectors
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@'s own @Identifier_Status@ differs from its NFKD-head's.
statusShifts :: Int -> Bool
statusShifts cp = not (isIdAllowed cp) && nfkdHeadAllowed cp

-- | First input position (and its codepoint) whose 'isIdAllowed' differs from
-- its NFKD-head's.
firstStatusShift :: [Int] -> Maybe (Int, Int)
firstStatusShift input =
  listToMaybe [ (idx, cp) | (idx, cp) <- zip [0 ..] input, statusShifts cp ]

-- | Total count of input positions where the per-cp status shifts under NFKD.
statusShiftCount :: [Int] -> Int
statusShiftCount input = length (filter statusShifts input)

-- ─────────────────────────────────────────────────────────────────────
-- §4 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | The IdentifierFormDrift detection function. Fires on the first
-- status-shifting position; the verdict carries the total shift count. Mirrors
-- the verified Rust reference exactly.
detect :: [Int] -> Verdict
detect input =
  Verdict
    { verdictInput      = input
    , verdictClassify   = classification
    , verdictShiftCount = statusShiftCount input
    }
  where
    classification =
      case firstStatusShift input of
        Just (pos, cp) -> Hazard (IdentifierStatusShift pos cp) [pos] []
        Nothing        -> Clear

-- | Fully-qualified reason code for the fired sub-threat, of the shape
-- @unicode.security.X.identifier-form-drift.\<subThreatTag\>@.
reasonCode :: SubThreat -> String
reasonCode sub = "unicode.security.X.identifier-form-drift." ++ subThreatTag sub

-- ─────────────────────────────────────────────────────────────────────
-- §5 Identifier_Status Allowed set (parsed from the bundled table)
-- ─────────────────────────────────────────────────────────────────────

-- | The UTS #39 @Identifier_Status = Allowed@ ranges, parsed once from the
-- bundled @IdentifierStatus.txt@. Loaded via the port's runtime-load idiom
-- (getDataFileName + 'unsafePerformIO' + @NOINLINE@), the same shape the port
-- uses for its other bundled UCD tables.
allowedRanges :: [(Int, Int)]
allowedRanges = unsafePerformIO $ do
  path <- getDataFileName "data/IdentifierStatus.txt"
  parseAllowedRanges <$> readFile path
{-# NOINLINE allowedRanges #-}

-- | Parse every @Allowed@ range line of an @IdentifierStatus.txt@ body. Each
-- data line is @<code>; Allowed # comment@ where @<code>@ is a single
-- @XXXX@ hex codepoint or an @XXXX..YYYY@ hex range. The @\@missing@ default
-- and every other comment line begin with @#@ and are dropped by
-- 'stripComment'.
parseAllowedRanges :: String -> [(Int, Int)]
parseAllowedRanges = mapMaybe parseAllowedRange . lines

-- | Parse a single @Allowed@ range line, or 'Nothing' for a comment, a blank
-- line, or a non-@Allowed@ status.
parseAllowedRange :: String -> Maybe (Int, Int)
parseAllowedRange raw =
  case break (== ';') (stripComment raw) of
    (_codeField, [])                -> Nothing
    (codeField, _semicolon : after) ->
      if trim after == "Allowed"
        then parseCodeRange (trim codeField)
        else Nothing

-- | Parse the code field — either a single @XXXX@ codepoint (a one-element
-- range) or an @XXXX..YYYY@ range.
parseCodeRange :: String -> Maybe (Int, Int)
parseCodeRange field =
  case breakOnDotDot field of
    Nothing -> do
      cp <- parseHexInt field
      Just (cp, cp)
    Just (loField, hiField) -> do
      lo <- parseHexInt loField
      hi <- parseHexInt hiField
      Just (lo, hi)

-- | Split a code field on its @..@ range separator, or 'Nothing' when it holds
-- a single codepoint.
breakOnDotDot :: String -> Maybe (String, String)
breakOnDotDot text =
  case break (== '.') text of
    (_before, [])                     -> Nothing
    (before, '.' : '.' : after)       -> Just (before, after)
    (_before, _dot : _rest)           -> Nothing

-- | Drop an inline @#@ comment.
stripComment :: String -> String
stripComment = takeWhile (/= '#')

-- | Strip leading and trailing whitespace.
trim :: String -> String
trim = dropWhileEnd isSpace . dropWhile isSpace

-- | Parse a whitespace-padded hexadecimal integer.
parseHexInt :: String -> Maybe Int
parseHexInt text =
  case readHex (trim text) of
    [(value, rest)] | all isSpace rest -> Just value
    _noUniqueParse                     -> Nothing
