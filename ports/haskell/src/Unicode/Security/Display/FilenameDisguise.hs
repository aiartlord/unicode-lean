{-|
Module      : Unicode.Security.Display.FilenameDisguise
Description : Detection of filename/extension disguise attacks (display-layer).

Haskell port of @Unicode.Security.Display.FilenameDisguise@ from unicode-lean,
transliterated byte-faithfully from the verified Rust reference implementation
(the display-layer detector, reason-code letter @D@).

Threat model. An adversary delivers a file whose rendered name looks like a
benign type (@document.txt@) but whose actual byte extension is executable — the
canonical attack inserts @U+202E@ RIGHT-TO-LEFT OVERRIDE so @document<RLO>txt.exe@
renders as @document exe.txt@.

What the detector draws. Detection is presentation- and language-agnostic: it
surfaces every codepoint that could cause display-vs-byte divergence in the
filename — any bidi format-control anywhere, and any fullwidth/halfwidth or
combining (grapheme @Extend@) codepoint in the extension region (after the last
@.@). Native-RTL names with no bidi controls clear. It reuses the port's own
predicates (the bidi-format-control set via 'Unicode.Security.CodepointPredicates.isBidiFormatControl',
the grapheme @Extend@ class via 'Unicode.Segmentation.Grapheme.lookupGCB', and
the inlined fullwidth range), never a host filesystem or rendering library.

Sub-threats (priority order).

  1. 'RloFlip'            — any bidi format-control in the input.
  2. 'WidthClassExt'      — a fullwidth/halfwidth codepoint in the extension.
  3. 'CombiningInExt'     — a combining (@Extend@) codepoint in the extension.
  4. 'MultipleExtensions' — @>= 3@ dots (advisory; e.g. legitimate @.tar.gz.sig@).
-}
module Unicode.Security.Display.FilenameDisguise
  ( SubThreat
      ( RloFlip, WidthClassExt, CombiningInExt, MultipleExtensions )
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classificationPositions
  , Verdict
      ( Verdict, verdictInput, verdictClassify, verdictDotPositions
      , verdictLastDotPos, verdictBidiControlCount, verdictFullwidthInExt
      , verdictCombiningInExt
      )
  , isAsciiDot
  , isFullwidthHalfwidth
  , isBidiFormatControl
  , isGraphemeExtend
  , detect
  , reasonCode
  ) where

import Data.Maybe (listToMaybe)

import Unicode.Segmentation.Grapheme (lookupGCB)
import Unicode.Segmentation.GraphemeTables (GCB (Extend))
import qualified Unicode.Security.CodepointPredicates as Predicates

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- | Sub-threat enumeration for FilenameDisguise, in priority order. Each
-- payload carries the position and codepoint values the conformance harness's
-- attribution column reads back, mirroring the Rust @SubThreat@ variants
-- field-for-field.
data SubThreat
  = -- | A bidi format-control at the given position (codepoint the second field).
    RloFlip Int Int
  | -- | A fullwidth/halfwidth codepoint in the extension. Fields: the position,
    -- then that codepoint.
    WidthClassExt Int Int
  | -- | A combining (grapheme @Extend@) codepoint in the extension. Fields: the
    -- position, then that codepoint.
    CombiningInExt Int Int
  | -- | Three or more @.@ separators (advisory); the 'Int' is the dot count.
    MultipleExtensions Int
  deriving stock (Eq, Show)

-- | Fixture-row tag string for this sub-threat (matches @SubThreat.tag@).
subThreatTag :: SubThreat -> String
subThreatTag (RloFlip _position _controlCp) = "RloFlip"
subThreatTag (WidthClassExt _position _cp)  = "WidthClassExt"
subThreatTag (CombiningInExt _position _cp) = "CombiningInExt"
subThreatTag (MultipleExtensions _dotCount) = "MultipleExtensions"

-- | Top-level classification for FilenameDisguise (no trigger = 'Clear').
data Classification
  = -- | No disguise trigger present.
    Clear
  | -- | A disguise trigger fired: the sub-threat, the implicated codepoint
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
  { verdictInput            :: ![Int]
    -- ^ The scanned input codepoints.
  , verdictClassify         :: !Classification
    -- ^ The classification verdict.
  , verdictDotPositions     :: ![Int]
    -- ^ Positions of every @.@ separator.
  , verdictLastDotPos       :: !(Maybe Int)
    -- ^ Position of the last @.@ (the extension separator), if any.
  , verdictBidiControlCount :: !Int
    -- ^ Count of bidi format-controls anywhere in the input.
  , verdictFullwidthInExt   :: !Int
    -- ^ Count of fullwidth/halfwidth codepoints in the extension region.
  , verdictCombiningInExt   :: !Int
    -- ^ Count of combining (@Extend@) codepoints in the extension region.
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- §2 Core predicates
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@ is @U+002E FULL STOP@ (the extension separator).
isAsciiDot :: Int -> Bool
isAsciiDot cp = cp == 0x002E

-- | True iff @cp@ is in the Halfwidth and Fullwidth Forms block @FF01@..@FFEF@.
isFullwidthHalfwidth :: Int -> Bool
isFullwidthHalfwidth cp = 0xFF01 <= cp && cp <= 0xFFEF

-- | True iff @cp@ is a bidi format-control — reuses the port's own predicate
-- from "Unicode.Security.CodepointPredicates".
isBidiFormatControl :: Int -> Bool
isBidiFormatControl = Predicates.isBidiFormatControl

-- | True iff @cp@ has @Grapheme_Cluster_Break = Extend@ — a combining mark that
-- stacks onto the preceding base. Reuses the port's grapheme-segmentation table
-- via 'lookupGCB'.
isGraphemeExtend :: Int -> Bool
isGraphemeExtend cp = lookupGCB cp == Extend

-- ─────────────────────────────────────────────────────────────────────
-- §3 Sub-detectors
-- ─────────────────────────────────────────────────────────────────────

-- | Positions of every @.@ in the input.
dotPositions :: [Int] -> [Int]
dotPositions input = [ idx | (idx, cp) <- zip [0 ..] input, isAsciiDot cp ]

-- | Position and codepoint of the first bidi format-control.
firstBidiControl :: [Int] -> Maybe (Int, Int)
firstBidiControl input =
  listToMaybe [ (idx, cp) | (idx, cp) <- zip [0 ..] input, isBidiFormatControl cp ]

-- | Position and codepoint of the first fullwidth/halfwidth codepoint at or
-- after @start@.
firstFullwidthFrom :: [Int] -> Int -> Maybe (Int, Int)
firstFullwidthFrom input start =
  listToMaybe
    [ (idx, cp) | (idx, cp) <- zip [0 ..] input, idx >= start, isFullwidthHalfwidth cp ]

-- | Position and codepoint of the first @Extend@ codepoint at or after @start@.
firstExtendFrom :: [Int] -> Int -> Maybe (Int, Int)
firstExtendFrom input start =
  listToMaybe
    [ (idx, cp) | (idx, cp) <- zip [0 ..] input, idx >= start, isGraphemeExtend cp ]

-- | Count of fullwidth/halfwidth codepoints at or after @start@.
countFullwidthFrom :: [Int] -> Int -> Int
countFullwidthFrom input start =
  length [ cp | (idx, cp) <- zip [0 ..] input, idx >= start, isFullwidthHalfwidth cp ]

-- | Count of @Extend@ codepoints at or after @start@.
countExtendFrom :: [Int] -> Int -> Int
countExtendFrom input start =
  length [ cp | (idx, cp) <- zip [0 ..] input, idx >= start, isGraphemeExtend cp ]

-- ─────────────────────────────────────────────────────────────────────
-- §4 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | The FilenameDisguise detection function. Priority ladder mirrors the
-- verified Rust reference exactly; see the module header for the sub-threat
-- inventory.
detect :: [Int] -> Verdict
detect input =
  Verdict
    { verdictInput            = input
    , verdictClassify         = classification
    , verdictDotPositions     = dots
    , verdictLastDotPos       = lastDot
    , verdictBidiControlCount = bidiCount
    , verdictFullwidthInExt   = fwInExt
    , verdictCombiningInExt   = extInExt
    }
  where
    dots     = dotPositions input
    lastDot  = if null dots then Nothing else Just (last dots)
    extStart = maybe (length input) (+ 1) lastDot
    bidiCount = length [ cp | cp <- input, isBidiFormatControl cp ]
    fwInExt   = countFullwidthFrom input extStart
    extInExt  = countExtendFrom input extStart

    classification =
      -- Priority 1: any bidi format-control.
      case firstBidiControl input of
        Just (pos, ctlCp) -> Hazard (RloFlip pos ctlCp) [pos] []
        Nothing ->
          -- Priority 2: fullwidth/halfwidth in the extension.
          case firstFullwidthFrom input extStart of
            Just (pos, cp) -> Hazard (WidthClassExt pos cp) [pos] []
            Nothing ->
              -- Priority 3: combining mark in the extension.
              case firstExtendFrom input extStart of
                Just (pos, cp) -> Hazard (CombiningInExt pos cp) [pos] []
                Nothing ->
                  -- Priority 4: three or more extensions (advisory).
                  if length dots >= 3
                    then Hazard (MultipleExtensions (length dots)) dots []
                    else Clear

-- | Fully-qualified reason code for a fired sub-threat, of the shape
-- @unicode.security.D.filename-disguise.\<subThreatTag\>@.
reasonCode :: SubThreat -> String
reasonCode sub = "unicode.security.D.filename-disguise." ++ subThreatTag sub
