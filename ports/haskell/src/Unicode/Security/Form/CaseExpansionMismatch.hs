{-|
Module      : Unicode.Security.Form.CaseExpansionMismatch
Description : Case-expansion-mismatch detector (UAX #21 / Tier A1..A2).

Haskell port of @Unicode.Security.Form.CaseExpansionMismatch@ from
unicode-lean, transliterated byte-faithfully from the verified Rust
reference (the form-layer detector, reason-code letter @F@).

Threat model. An attacker submits text whose case-mapped form has a
different codepoint count than the input. A receiver that fixes a 16-byte
username column and stores @toUpper(username)@ overflows when the user
picks @"ßßßßßßßß"@ (8 in, 16 stored); a receiver that checks
@len(stored) == len(input)@ rejects valid case-insensitive logins whose
names expand under folding. Examples: @U+00DF ß@ uppercases to @"SS"@,
@U+FB01 ﬁ@ to @"FI"@, @U+0130 İ@ lowercases to @"i̇"@ (@i@ + @U+0307@).

Distinct from "Unicode.Security.Form.LocaleCaseInversion" (case mapping
that changes /across/ locales): this fires on shapes whose mapping is
locale-stable but length-changing under the default locale itself.

It reuses the port's own UAX #21 case mapping — 'upperCodepoint' and
'lowerCodepoint' from "Unicode.Casing", which evaluate the SpecialCasing
context predicates — never a host casing library.

Sub-threats (priority order).

  1. 'UpperExpansion' — first position whose default 'upperCodepoint' yields > 1 cp.
  2. 'LowerExpansion' — first position whose default 'lowerCodepoint' yields > 1 cp
     (reached only when no upper expansion fires first).
-}
module Unicode.Security.Form.CaseExpansionMismatch
  ( SubThreat (UpperExpansion, LowerExpansion)
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classificationPositions
  , Verdict
      ( Verdict, verdictInput, verdictClassify, verdictUpperExpansionCount
      , verdictLowerExpansionCount, verdictMaxExpansionLen
      )
  , detect
  , reasonCode
  ) where

import Data.Maybe (listToMaybe)

import Unicode.Casing (Locale (Default), lowerCodepoint, upperCodepoint)

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- | Sub-threat enumeration for CaseExpansionMismatch, in priority order.
-- Each payload carries the values the conformance harness's attribution
-- column reads back, mirroring the Rust @SubThreat@ variants field-for-field.
data SubThreat
  = -- | A codepoint whose default uppercase mapping expands. Fields: the
    -- position, the expanding codepoint, then the expansion length (> 1).
    UpperExpansion Int Int Int
  | -- | A codepoint whose default lowercase mapping expands. Fields: the
    -- position, the expanding codepoint, then the expansion length (> 1).
    LowerExpansion Int Int Int
  deriving stock (Eq, Show)

-- | Fixture-row tag string for this sub-threat (matches @SubThreat.tag@).
subThreatTag :: SubThreat -> String
subThreatTag (UpperExpansion _pos _cp _len) = "UpperExpansion"
subThreatTag (LowerExpansion _pos _cp _len) = "LowerExpansion"

-- | Top-level classification for CaseExpansionMismatch (no trigger = 'Clear').
data Classification
  = -- | No case-mapped expansion present.
    Clear
  | -- | An expansion fired: the sub-threat, the implicated positions, and the
    -- decoded-byte projection (always @[]@ here; kept for shape parity with the
    -- Lean @Classification.hazard@).
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
  { verdictInput               :: ![Int]
    -- ^ The scanned input codepoints.
  , verdictClassify            :: !Classification
    -- ^ The classification verdict.
  , verdictUpperExpansionCount :: !Int
    -- ^ Count of positions whose default uppercase mapping expands.
  , verdictLowerExpansionCount :: !Int
    -- ^ Count of positions whose default lowercase mapping expands.
  , verdictMaxExpansionLen     :: !Int
    -- ^ Maximum case-mapped expansion length across all positions (upper or
    -- lower); @0@ for empty input.
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- §2 Per-position expansion scan
-- ─────────────────────────────────────────────────────────────────────

-- | One scanned position: its index, its codepoint, and the default-locale
-- uppercase and lowercase expansion lengths there. The lengths are evaluated
-- against the SpecialCasing context — the preceding codepoints nearest-first
-- and the strictly-following ones — mirroring @input[..i].rev()@ / @input[i+1..]@.
data PositionScan = PositionScan
  { scanIndex    :: !Int
  , scanCp       :: !Int
  , scanUpperLen :: !Int
  , scanLowerLen :: !Int
  }

-- | Scan every input position, carrying the already-processed codepoints as a
-- nearest-first prefix so each position reads its full case-mapping context.
positionScans :: [Int] -> [PositionScan]
positionScans = go 0 []
  where
    go _index _revPrefix [] = []
    go index revPrefix (cp : suffix) =
      PositionScan
        { scanIndex    = index
        , scanCp       = cp
        , scanUpperLen = length (upperCodepoint Default revPrefix suffix cp)
        , scanLowerLen = length (lowerCodepoint Default revPrefix suffix cp)
        }
        : go (index + 1) (cp : revPrefix) suffix

-- | First position whose default uppercase mapping expands to > 1 codepoint,
-- with that codepoint and its expansion length.
firstUpperExpansion :: [PositionScan] -> Maybe (Int, Int, Int)
firstUpperExpansion scans =
  listToMaybe
    [ (scanIndex s, scanCp s, scanUpperLen s) | s <- scans, scanUpperLen s > 1 ]

-- | First position whose default lowercase mapping expands to > 1 codepoint,
-- with that codepoint and its expansion length.
firstLowerExpansion :: [PositionScan] -> Maybe (Int, Int, Int)
firstLowerExpansion scans =
  listToMaybe
    [ (scanIndex s, scanCp s, scanLowerLen s) | s <- scans, scanLowerLen s > 1 ]

-- | Count of positions whose default uppercase mapping expands.
upperExpansionCount :: [PositionScan] -> Int
upperExpansionCount scans = length [ () | s <- scans, scanUpperLen s > 1 ]

-- | Count of positions whose default lowercase mapping expands.
lowerExpansionCount :: [PositionScan] -> Int
lowerExpansionCount scans = length [ () | s <- scans, scanLowerLen s > 1 ]

-- | Maximum case-mapped expansion length across all positions (upper or
-- lower); @0@ for empty input.
maxExpansionLen :: [PositionScan] -> Int
maxExpansionLen scans =
  case [ max (scanUpperLen s) (scanLowerLen s) | s <- scans ] of
    []               -> 0
    (len : moreLens) -> foldr max len moreLens

-- ─────────────────────────────────────────────────────────────────────
-- §3 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | The CaseExpansionMismatch detection function. Priority ladder mirrors the
-- verified Rust reference exactly: an uppercase expansion outranks a lowercase
-- expansion; the lower scan is reached only when no upper expansion fires.
detect :: [Int] -> Verdict
detect input =
  Verdict
    { verdictInput               = input
    , verdictClassify            = classification
    , verdictUpperExpansionCount = upperExpansionCount scans
    , verdictLowerExpansionCount = lowerExpansionCount scans
    , verdictMaxExpansionLen     = maxExpansionLen scans
    }
  where
    scans = positionScans input
    classification =
      -- Priority 1: an uppercase expansion.
      case firstUpperExpansion scans of
        Just (pos, cp, len) -> Hazard (UpperExpansion pos cp len) [pos] []
        Nothing ->
          -- Priority 2: a lowercase expansion.
          case firstLowerExpansion scans of
            Just (pos, cp, len) -> Hazard (LowerExpansion pos cp len) [pos] []
            Nothing             -> Clear

-- | Fully-qualified reason code for a fired sub-threat, of the shape
-- @unicode.security.F.case-expansion-mismatch.\<subThreatTag\>@.
reasonCode :: SubThreat -> String
reasonCode sub = "unicode.security.F.case-expansion-mismatch." ++ subThreatTag sub
