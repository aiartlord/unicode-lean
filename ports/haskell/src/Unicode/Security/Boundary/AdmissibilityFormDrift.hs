{-|
Module      : Unicode.Security.Boundary.AdmissibilityFormDrift
Description : Cross-layer identifier-admissibility × form drift (boundary-layer detector).

Haskell port of @Unicode.Security.Boundary.AdmissibilityFormDrift@ from
unicode-lean, transliterated byte-faithfully from the verified Rust reference
implementation (the boundary-layer detector, reason-code letter @X@).

Threat model. The UTS #39 whole-string @isAllowedIdentifier@ verdict differs
between an input and its NFKC form. This is the string-level complement of
'Unicode.Security.Boundary.IdentifierFormDrift' (which scans @Identifier_Status@
against the per-codepoint NFKD head): here the whole-string admissibility
predicate is evaluated twice — once on the input, once on @toNFKC input@. The
two are not redundant. In particular, a sequence of decomposed Hangul jamos
passes the per-codepoint scan cleanly (each jamo has identity NFKD and
Restricted status on both sides) but fires here — the jamo sequence is rejected
by @isAllowedIdentifier@, while its NFKC composition into a precomposed Hangul
syllable is accepted.

What the detector draws. It reuses the port's own UTS #39 admissibility
predicate ('isAllowedIdentifier' = UAX #31 default identifier ∧ every codepoint
Allowed) and NFKC pipeline ('Unicode.Normalization.NFKC.toNFKC'), never a host
normalization or identifier library. The @Identifier_Status = Allowed@
per-codepoint test is the port's own 'Unicode.Security.Boundary.IdentifierFormDrift.isIdAllowed';
the @XID_Start@ / @XID_Continue@ ranges are parsed here from the bundled
DerivedCoreProperties.txt (the same table the casing conditions read
@Cased@ / @Soft_Dotted@ from).

Sub-threat (direction-agnostic).

  1. 'AdmissibilityFormDrift' — @isAllowedIdentifier input \/=
     isAllowedIdentifier (toNFKC input)@. The pair of booleans is carried so the
     verdict records which direction the drift goes; no position is reported
     because the predicate is whole-string.
-}
module Unicode.Security.Boundary.AdmissibilityFormDrift
  ( SubThreat (AdmissibilityFormDrift)
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classificationPositions
  , Verdict
      ( Verdict, verdictInput, verdictClassify, verdictInputAdmissible
      , verdictNfkcAdmissible
      )
  , isXidStart
  , isXidContinue
  , isDefaultIdStart
  , isDefaultIdContinue
  , isDefaultIdentifier
  , isAllowedIdentifier
  , detect
  , reasonCode
  ) where

import Data.Char (isSpace)
import Data.List (dropWhileEnd)
import Data.Maybe (mapMaybe)
import Numeric (readHex)
import System.IO.Unsafe (unsafePerformIO)

import Unicode.Normalization.NFKC (toNFKC)
import Unicode.Security.Boundary.IdentifierFormDrift (isIdAllowed)
import Paths_unicode_haskell (getDataFileName)

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- | Sub-threat enumeration for AdmissibilityFormDrift. There is exactly one
-- sub-threat; its payload carries the two whole-string admissibility booleans
-- the conformance harness's attribution column reads back, mirroring the Rust
-- @SubThreat@ variant field-for-field: @isAllowedIdentifier input@ then
-- @isAllowedIdentifier (toNFKC input)@.
data SubThreat
  = -- | The whole-string admissibility verdict differs between the input (first
    -- field) and its NFKC form (second field).
    AdmissibilityFormDrift Bool Bool
  deriving stock (Eq, Show)

-- | Fixture-row tag string for this sub-threat (matches @SubThreat.tag@).
subThreatTag :: SubThreat -> String
subThreatTag (AdmissibilityFormDrift _inputAdmissible _nfkcAdmissible) =
  "AdmissibilityFormDrift"

-- | Top-level classification for AdmissibilityFormDrift (verdicts agree =
-- 'Clear').
data Classification
  = -- | The admissibility verdict agrees across forms.
    Clear
  | -- | The admissibility verdict drifts across forms: the sub-threat, the
    -- implicated positions (always @[]@ — the predicate is whole-string), and
    -- the decoded-byte projection (always @[]@ here; kept for shape parity with
    -- the Lean @Classification.hazard@).
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

-- | Implicated positions (always @[]@ — the predicate is whole-string).
classificationPositions :: Classification -> [Int]
classificationPositions Clear                      = []
classificationPositions (Hazard _sub positions _d) = positions

-- | Verdict — the structured output of 'detect' (mirrors the Lean @Verdict@).
data Verdict = Verdict
  { verdictInput           :: ![Int]
    -- ^ The scanned input codepoints.
  , verdictClassify        :: !Classification
    -- ^ The classification verdict.
  , verdictInputAdmissible :: !Bool
    -- ^ @isAllowedIdentifier input@.
  , verdictNfkcAdmissible  :: !Bool
    -- ^ @isAllowedIdentifier (toNFKC input)@.
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- §2 UAX #31 default identifier + UTS #39 whole-string admissibility
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@ has the @XID_Start@ derived property. The range list is
-- parsed once from the bundled @DerivedCoreProperties.txt@.
isXidStart :: Int -> Bool
isXidStart = inRanges xidStartRanges

-- | True iff @cp@ has the @XID_Continue@ derived property. The range list is
-- parsed once from the bundled @DerivedCoreProperties.txt@.
isXidContinue :: Int -> Bool
isXidContinue = inRanges xidContinueRanges

-- | UAX #31 default identifier start: @XID_Start@ or @U+005F LOW LINE@.
isDefaultIdStart :: Int -> Bool
isDefaultIdStart cp = isXidStart cp || cp == 0x005F

-- | UAX #31 default identifier continue: @XID_Continue@.
isDefaultIdContinue :: Int -> Bool
isDefaultIdContinue = isXidContinue

-- | True iff @cps@ is a well-formed UAX #31 default identifier: a non-empty
-- sequence whose first codepoint is a default-id start and whose remaining
-- codepoints are default-id continues.
isDefaultIdentifier :: [Int] -> Bool
isDefaultIdentifier []             = False
isDefaultIdentifier (first : rest) = isDefaultIdStart first && all isDefaultIdContinue rest

-- | True iff @cps@ is a well-formed default identifier AND every codepoint has
-- @Identifier_Status = Allowed@ per UTS #39 (the whole-string admissibility
-- predicate @isAllowedIdentifier@). Reuses the port's own 'isIdAllowed'.
isAllowedIdentifier :: [Int] -> Bool
isAllowedIdentifier cps = isDefaultIdentifier cps && all isIdAllowed cps

-- ─────────────────────────────────────────────────────────────────────
-- §3 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | The AdmissibilityFormDrift detection function. Evaluates the whole-string
-- admissibility predicate twice — on the input and on its NFKC form — and fires
-- when the two verdicts disagree. Mirrors the verified Rust reference exactly.
detect :: [Int] -> Verdict
detect input =
  Verdict
    { verdictInput           = input
    , verdictClassify        = classification
    , verdictInputAdmissible = inOk
    , verdictNfkcAdmissible  = nfkcOk
    }
  where
    nfkc   = toNFKC input
    inOk   = isAllowedIdentifier input
    nfkcOk = isAllowedIdentifier nfkc

    classification =
      if inOk == nfkcOk
        then Clear
        else Hazard (AdmissibilityFormDrift inOk nfkcOk) [] []

-- | Fully-qualified reason code for the fired sub-threat, of the shape
-- @unicode.security.X.admissibility-form-drift.\<subThreatTag\>@.
reasonCode :: SubThreat -> String
reasonCode sub = "unicode.security.X.admissibility-form-drift." ++ subThreatTag sub

-- ─────────────────────────────────────────────────────────────────────
-- §4 XID_Start / XID_Continue ranges (parsed from the bundled table)
-- ─────────────────────────────────────────────────────────────────────

-- | The @XID_Start@ ranges, parsed once from the bundled
-- @DerivedCoreProperties.txt@ via the port's runtime-load idiom
-- (getDataFileName + 'unsafePerformIO' + @NOINLINE@).
xidStartRanges :: [(Int, Int)]
xidStartRanges = unsafePerformIO $ do
  path <- getDataFileName "data/DerivedCoreProperties.txt"
  parseDerivedProperty "XID_Start" <$> readFile path
{-# NOINLINE xidStartRanges #-}

-- | The @XID_Continue@ ranges, parsed once from the bundled
-- @DerivedCoreProperties.txt@.
xidContinueRanges :: [(Int, Int)]
xidContinueRanges = unsafePerformIO $ do
  path <- getDataFileName "data/DerivedCoreProperties.txt"
  parseDerivedProperty "XID_Continue" <$> readFile path
{-# NOINLINE xidContinueRanges #-}

-- | True iff @cp@ falls inside any inclusive range of @ranges@.
inRanges :: [(Int, Int)] -> Int -> Bool
inRanges ranges cp = any inRange ranges
  where
    inRange (lo, hi) = lo <= cp && cp <= hi

-- | Parse every range line of a @DerivedCoreProperties.txt@ body tagged with
-- @propertyName@. Each data line is @<code>; <Property> # comment@ where
-- @<code>@ is a single @XXXX@ hex codepoint or an @XXXX..YYYY@ hex range.
parseDerivedProperty :: String -> String -> [(Int, Int)]
parseDerivedProperty propertyName =
  mapMaybe (parseDerivedPropertyLine propertyName) . lines

-- | Parse a single property line, or 'Nothing' for a comment, a blank line, or
-- a line whose property field differs from @propertyName@.
parseDerivedPropertyLine :: String -> String -> Maybe (Int, Int)
parseDerivedPropertyLine propertyName raw =
  case break (== ';') (stripComment raw) of
    (_codeField, [])                 -> Nothing
    (codeField, _semicolon : after) ->
      if trim after == propertyName
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
    (_before, [])                -> Nothing
    (before, '.' : '.' : after)  -> Just (before, after)
    (_before, _dot : _rest)      -> Nothing

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
