{-# LANGUAGE StrictData #-}

{-|
Module      : Unicode.Segmentation.Grapheme
Description : UAX #29 default extended grapheme cluster segmentation.

Haskell port of the Lean algorithm
@Unicode.Segmentation.GraphemeBreak.graphemeBreaks@. The active Lean tree proves
@graphemeBreaks_eq_spec@, relating that algorithm to the declarative UAX #29
GB1-GB999 specification. The 'State' fields, rule order, and transition below
mirror that reference.

The property tables are grouped by property value (as in the UCD source), not
globally sorted by code point. Each class is a partition — no two ranges in any
of the three tables overlap — so the covering range is unique and a lookup
keyed by range start returns the same range the verified Lean @find?@ returns.
'gcbIndex', 'incbIndex' and 'extpictIndex' are those tables keyed that way,
built once; the three lookups run twice per code point (once in
'shouldBreakBefore', once in 'advance') over 1429, 505 and 451 ranges.
-}
module Unicode.Segmentation.Grapheme
  ( graphemeBreaks
  , graphemeClusters
  , lookupGCB
  , lookupInCB
  , isExtPict
  ) where

import Data.Maybe (fromMaybe)

import Unicode.RangeIndex (RangeIndex, RangeMap)
import qualified Unicode.RangeIndex as RangeIndex
  ( classOf, fromRanges, member, rangeMapOf )
import Unicode.Segmentation.GraphemeTables
  ( GCB( Prepend, Cr, Lf, Control, Extend, RegionalIndicator, SpacingMark
       , L, V, T, Lv, Lvt, Zwj, Other )
  , Incb( IncbLinker, IncbConsonant, IncbExtend, IncbNone )
  , gcbRanges
  , incbRanges
  , extpictRanges
  )

-- | Grapheme_Cluster_Break class of a code point, 'Other' when uncovered.
lookupGCB :: Int -> GCB
lookupGCB cp = fromMaybe Other (RangeIndex.classOf cp gcbIndex)

-- | The GCB table keyed by range start, built once.
gcbIndex :: RangeMap GCB
gcbIndex = RangeIndex.rangeMapOf gcbRanges
{-# NOINLINE gcbIndex #-}

-- | Indic_Conjunct_Break class of a code point, 'IncbNone' when uncovered.
lookupInCB :: Int -> Incb
lookupInCB cp = fromMaybe IncbNone (RangeIndex.classOf cp incbIndex)

-- | The InCB table keyed by range start, built once.
incbIndex :: RangeMap Incb
incbIndex = RangeIndex.rangeMapOf incbRanges
{-# NOINLINE incbIndex #-}

-- | Whether a code point has the Extended_Pictographic property.
isExtPict :: Int -> Bool
isExtPict cp = RangeIndex.member cp extpictIndex

-- | The Extended_Pictographic ranges indexed for membership, built once.
extpictIndex :: RangeIndex
extpictIndex = RangeIndex.fromRanges extpictRanges
{-# NOINLINE extpictIndex #-}

-- | GB11 left-context state, mirroring the Lean @EPicState@.
data EPicState = EpNone | AfterEp | AfterEpZwj
  deriving (Eq)

-- | GB9c left-context state, mirroring the Lean @InCBState@.
data IncbState = InNone | InConsonant | InLinker
  deriving (Eq)

-- | Running scan state, mirroring the Lean @State@.
data State = State
  { prevClass :: !(Maybe GCB)
  , epicState :: !EPicState
  , incbState :: !IncbState
  , riRun     :: !Int
  }

initialState :: State
initialState = State
  { prevClass = Nothing
  , epicState = EpNone
  , incbState = InNone
  , riRun     = 0
  }

-- | Whether a grapheme cluster break occurs immediately before @cp@ given the
-- running state. Implements UAX #29 GB1–GB999 in canonical order; first match
-- wins, the trailing GB999 breaks every otherwise-unmatched pair.
shouldBreakBefore :: Int -> State -> Bool
shouldBreakBefore cp st =
  let bc   = lookupGCB cp
      incb = lookupInCB cp
      isEP = isExtPict cp
  in case prevClass st of
       Nothing -> True                                                   -- GB1
       Just pc
         | pc == Cr && bc == Lf                                 -> False  -- GB3
         | pc == Control || pc == Cr || pc == Lf                -> True   -- GB4
         | bc == Control || bc == Cr || bc == Lf                -> True   -- GB5
         | pc == L && (bc == L || bc == V || bc == Lv || bc == Lvt)
                                                                -> False  -- GB6
         | (pc == Lv || pc == V) && (bc == V || bc == T)        -> False  -- GB7
         | (pc == Lvt || pc == T) && bc == T                    -> False  -- GB8
         | bc == Extend || bc == Zwj                            -> False  -- GB9
         | bc == SpacingMark                                    -> False  -- GB9a
         | pc == Prepend                                        -> False  -- GB9b
         | incbState st == InLinker && incb == IncbConsonant    -> False  -- GB9c
         | epicState st == AfterEpZwj && isEP                   -> False  -- GB11
         | bc == RegionalIndicator && riRun st `mod` 2 == 1     -> False  -- GB12/13
         | otherwise                                            -> True   -- GB999

-- | Update the running state after consuming @cp@. Mirrors the Lean @advance@.
advance :: Int -> State -> State
advance cp st =
  let bc   = lookupGCB cp
      incb = lookupInCB cp
      isEP = isExtPict cp
      epic'
        | isEP                                          = AfterEp
        | epicState st == AfterEp && bc == Extend       = AfterEp
        | epicState st == AfterEp && bc == Zwj          = AfterEpZwj
        | otherwise                                     = EpNone
      incb'
        | incb == IncbConsonant                              = InConsonant
        | incbState st == InConsonant && incb == IncbLinker  = InLinker
        | incbState st == InConsonant && incb == IncbExtend  = InConsonant
        | incbState st == InLinker && incb == IncbLinker     = InLinker
        | incbState st == InLinker && incb == IncbExtend      = InLinker
        | otherwise                                          = InNone
      ri'
        | bc == RegionalIndicator = riRun st + 1
        | otherwise               = 0
  in State
       { prevClass = Just bc
       , epicState = epic'
       , incbState = incb'
       , riRun     = ri'
       }

-- | Boundary mask of length @length cps + 1@. Entry @i@ is 'True' when a
-- grapheme cluster break occurs immediately before position @i@ — entry @0@ is
-- the GB1 start-of-text break, entry @length cps@ the GB2 end-of-text break,
-- both always 'True'. Mirrors the Lean @graphemeBreaks@.
graphemeBreaks :: [Int] -> [Bool]
graphemeBreaks cps =
  [ shouldBreakBefore cp st | (cp, st) <- zip cps states ] ++ [True]
  where
    states :: [State]
    states = scanl (flip advance) initialState cps

-- | Split @cps@ into grapheme clusters (the code points between consecutive
-- boundaries).
graphemeClusters :: [Int] -> [[Int]]
graphemeClusters cps = go (zip cps (drop 1 (graphemeBreaks cps))) []
  where
    go :: [(Int, Bool)] -> [Int] -> [[Int]]
    go [] acc = if null acc then [] else [reverse acc]
    go ((cp, brk) : rest) acc
      | brk       = reverse (cp : acc) : go rest []
      | otherwise = go rest (cp : acc)
