-- | @Unicode.RangeIndex@ — logarithmic membership over inclusive codepoint
-- ranges.
--
-- The UCD property tables are lists of inclusive @(lo, hi)@ ranges, and a
-- predicate over one of them answers "does this codepoint carry the property?".
-- Scanning the list answers in O(n) per codepoint, which a real-time scan pays
-- once per codepoint per property: @XID_Continue@ alone is 1,422 ranges.
--
-- A 'RangeIndex' keys each range's end by its start in an 'IntMap', so a
-- lookup is one 'IntMap.lookupLE' plus a bound check — O(log n) in the number
-- of ranges, and the map holds one entry per range rather than one per covered
-- codepoint (@XID_Continue@: 1,422 entries, not 149,221).
--
-- 'fromRanges' sorts and coalesces overlapping and adjacent ranges, so the
-- index is correct for any input list, however ordered. That matters because a
-- greatest-lower-bound lookup over raw overlapping ranges would answer False
-- for a codepoint that an earlier, wider range covers; coalescing removes the
-- overlap rather than assuming its absence.
module Unicode.RangeIndex
  ( RangeIndex
  , fromRanges
  , member
  , rangeCount
  ) where

import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IntMap
import Data.List (sortOn)

-- | Inclusive codepoint ranges, indexed for logarithmic membership. Every
-- range in the index is well-formed (@lo <= hi@) and disjoint from, and not
-- adjacent to, every other, so at most one range can contain a codepoint.
newtype RangeIndex = RangeIndex (IntMap Int)

-- | Index an inclusive-range list. Ill-formed ranges (@hi < lo@) are dropped;
-- the rest are sorted by start and coalesced, so overlapping and adjacent
-- ranges become one.
fromRanges :: [(Int, Int)] -> RangeIndex
fromRanges ranges =
  RangeIndex (IntMap.fromList (coalesce (sortOn fst (filter wellFormed ranges))))
  where
    wellFormed (lo, hi) = lo <= hi

-- | Coalesce a start-ordered range list: a range that begins at or before one
-- past the running range's end extends it, otherwise it starts a new one.
coalesce :: [(Int, Int)] -> [(Int, Int)]
coalesce [] = []
coalesce (first : rest) = go first rest
  where
    go current [] = [current]
    go (lo, hi) (next : remaining)
      | nextLo <= hi + 1 = go (lo, max hi nextHi) remaining
      | otherwise        = (lo, hi) : go next remaining
      where
        (nextLo, nextHi) = next

-- | True iff the codepoint falls inside some range of the index. The greatest
-- range start at or below the codepoint is the only candidate, because the
-- index's ranges are disjoint and non-adjacent.
member :: Int -> RangeIndex -> Bool
member cp (RangeIndex index) =
  case IntMap.lookupLE cp index of
    Just (_lo, hi) -> cp <= hi
    Nothing        -> False

-- | How many coalesced ranges the index holds. For the property tables this is
-- the lookup's log base, and it is what a test asserts against the source list.
rangeCount :: RangeIndex -> Int
rangeCount (RangeIndex index) = IntMap.size index
