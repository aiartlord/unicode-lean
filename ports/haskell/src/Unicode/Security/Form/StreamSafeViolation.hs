{-|
Module      : Unicode.Security.Form.StreamSafeViolation
Description : Stream-Safe-Text-Format-violation detector (F2).

Haskell port of @Unicode.Security.Form.StreamSafeViolation@ from unicode-lean,
transliterated from the verified Rust reference
@ports/rust/src/security/form/stream_safe_violation.rs@.

Detects inputs whose consecutive non-starter run exceeds the UAX #15 §13
@streamSafeLimit@ of 30. Such an input (the canonical "Zalgo" shape, a single
base codepoint followed by a long combining-mark run) forces unbounded
combining-mark buffers in receiver-side streaming normalization (@toNFC@ /
@toNFD@ / @toNFKC@ / @toNFKD@) and is a known DoS vector.

UAX #15 §13 defines Stream-Safe Text Format as the remediation: insert U+034F
COMBINING GRAPHEME JOINER (a starter) after every 30 consecutive non-starters,
which bounds the normalization buffer. 'detect' is the security verdict over
the same property.

A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
(UAX #15 D49). This module reads CCC from the port's own bundled UCD table via
'Unicode.Normalization.Lookup.canonicalCombiningClass', never a host
normalizer.

Sub-threat: 'StreamSafeOverrun' @basePos runLen@ — the first non-starter run
whose length exceeds 'streamSafeLimit'. @basePos@ is the index of that run's
first non-starter codepoint.
-}
module Unicode.Security.Form.StreamSafeViolation
  ( SubThreat (StreamSafeOverrun)
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classificationPositions
  , Verdict
      ( Verdict
      , verdictInput
      , verdictClassify
      , verdictMaxRunLen
      , verdictOverrunCount
      , verdictTotalNonStarters
      )
  , streamSafeLimit
  , detect
  , reasonCode
  ) where

import Data.List (find)
import Data.Word (Word8)

import qualified Unicode.Normalization.Lookup as NormalizationLookup

-- ─────────────────────────────────────────────────────────────────────
-- §1 Run inventory
-- ─────────────────────────────────────────────────────────────────────

-- | UAX #15 §13 Stream-Safe limit: the maximum number of consecutive
-- non-starters permitted before a COMBINING GRAPHEME JOINER must be inserted.
streamSafeLimit :: Int
streamSafeLimit = 30

-- | True iff @cp@ is a non-starter — a codepoint with non-zero
-- Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0. Reads CCC
-- from the port's own bundled UCD table, never a host normalizer.
isNonStarter :: Int -> Bool
isNonStarter cp = NormalizationLookup.canonicalCombiningClass cp /= (0 :: Word8)

-- | Inventory of @(startIndex, length)@ for every maximal non-starter run in
-- @input@. Mirrors @collectRunsGo@: a run opens on the first non-starter, its
-- start index is fixed to that codepoint's absolute index, and it closes
-- (emitting its @(start, length)@ pair) on the next starter or at end of input.
nonStarterRuns :: [Int] -> [(Int, Int)]
nonStarterRuns = go 0 Nothing 0 []
  where
    go :: Int -> Maybe Int -> Int -> [(Int, Int)] -> [Int] -> [(Int, Int)]
    go _i Nothing  _curLen acc [] = reverse acc
    go _i (Just s) curLen  acc [] = reverse ((s, curLen) : acc)
    go i curStart curLen acc (cp : rest)
      | isNonStarter cp =
          let start' = case curStart of
                         Just s  -> Just s
                         Nothing -> Just i
          in go (i + 1) start' (curLen + 1) acc rest
      | otherwise =
          let acc' = case curStart of
                       Just s  -> (s, curLen) : acc
                       Nothing -> acc
          in go (i + 1) Nothing 0 acc' rest

-- | First non-starter run whose length exceeds 'streamSafeLimit', as
-- @(startIndex, length)@.
firstOverrun :: [Int] -> Maybe (Int, Int)
firstOverrun input = find (\(_start, len) -> len > streamSafeLimit) (nonStarterRuns input)

-- | Longest non-starter run length in @input@.
maxRunLen :: [Int] -> Int
maxRunLen input =
  foldl' (\acc (_start, len) -> if len > acc then len else acc) 0 (nonStarterRuns input)

-- | Number of distinct non-starter runs that exceed 'streamSafeLimit'.
overrunCount :: [Int] -> Int
overrunCount input =
  foldl' (\acc (_start, len) -> if len > streamSafeLimit then acc + 1 else acc) 0 (nonStarterRuns input)

-- | Total non-starter codepoints in @input@ (sum of all run lengths).
totalNonStarters :: [Int] -> Int
totalNonStarters input =
  foldl' (\acc (_start, len) -> acc + len) 0 (nonStarterRuns input)

-- ─────────────────────────────────────────────────────────────────────
-- §2 Types
-- ─────────────────────────────────────────────────────────────────────

-- | Sub-threats this detector can fire.
--
-- @StreamSafeOverrun basePos runLen@ is the first non-starter run whose length
-- exceeds 'streamSafeLimit'; @basePos@ is the index of the run's first
-- non-starter codepoint and @runLen@ is the run's length.
data SubThreat
  = StreamSafeOverrun Int Int
  deriving stock (Eq, Show)

-- | Human-facing classification tag for this sub-threat.
subThreatTag :: SubThreat -> String
subThreatTag (StreamSafeOverrun _basePos _runLen) = "StreamSafeOverrun"

-- | Top-level F2 classification. 'Hazard' carries the sub-threat that fired,
-- the codepoint positions it implicates, and any decoded byte context (always
-- empty for this detector — the field mirrors the spec's @Classification.hazard@
-- shape).
data Classification
  = Clear
  | Hazard SubThreat [Int] [Word8]
  deriving stock (Eq, Show)

-- | True iff the input is clear.
classificationIsClear :: Classification -> Bool
classificationIsClear Clear                = True
classificationIsClear (Hazard _sub _p _d)  = False

-- | Human-facing tag for a hazard, or 'Nothing' when clear.
classificationTag :: Classification -> Maybe String
classificationTag Clear                    = Nothing
classificationTag (Hazard sub _pos _dec)   = Just (subThreatTag sub)

-- | Implicated positions ('[]' when clear).
classificationPositions :: Classification -> [Int]
classificationPositions Clear                       = []
classificationPositions (Hazard _sub positions _dec) = positions

-- | F2 verdict — the structured output of 'detect'. The run-inventory summaries
-- ('verdictMaxRunLen', 'verdictOverrunCount', 'verdictTotalNonStarters') are
-- exposed so downstream callers can size the buffer pressure a streaming
-- normalizer would see.
data Verdict = Verdict
  { verdictInput            :: ![Int]
  , verdictClassify         :: !Classification
  , verdictMaxRunLen        :: !Int
  , verdictOverrunCount     :: !Int
  , verdictTotalNonStarters :: !Int
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- §3 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | The F2 detection function. Fires 'StreamSafeOverrun' on the first
-- non-starter run whose length exceeds 'streamSafeLimit'.
detect :: [Int] -> Verdict
detect input =
  let classification = case firstOverrun input of
        Just (basePos, runLen) ->
          Hazard (StreamSafeOverrun basePos runLen) [basePos] []
        Nothing -> Clear
  in Verdict
       { verdictInput            = input
       , verdictClassify         = classification
       , verdictMaxRunLen        = maxRunLen input
       , verdictOverrunCount     = overrunCount input
       , verdictTotalNonStarters = totalNonStarters input
       }

-- | Fully-qualified reason code for a fired sub-threat, of the shape
-- @unicode.security.F.stream-safe-violation.\<subThreatTag\>@. For
-- 'StreamSafeOverrun' this is
-- @unicode.security.F.stream-safe-violation.StreamSafeOverrun@.
reasonCode :: SubThreat -> String
reasonCode sub = "unicode.security.F.stream-safe-violation." ++ subThreatTag sub
