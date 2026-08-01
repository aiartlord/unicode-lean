{-|
Module      : Unicode.Normalization.Reorder
Description : Canonical ordering algorithm (UAX #15 §1.3 / D109-D110).

Haskell port of @Unicode.Normalization.Reorder@ from unicode-lean.

Given a codepoint sequence, reorders consecutive non-starter runs
(@CCC > 0@) by non-decreasing Canonical_Combining_Class, preserving the
relative order of equal-CCC codepoints (stable). Starters (@CCC = 0@)
act as boundaries and never move.

Single left-to-right fold: non-starters accumulate into a pending run;
on the next starter (or end of input) the run is stably insertion-sorted
by CCC and emitted. The insertion predicate uses strict @<@, so
equal-CCC elements keep their scan order.
-}
module Unicode.Normalization.Reorder
  ( reorder
  ) where

import Unicode.Normalization.Lookup (canonicalCombiningClass)

-- | Stable insertion of a codepoint into a list already sorted by CCC.
-- Places @x@ immediately before the first element whose CCC is strictly
-- greater; equal-CCC elements already present stay ahead of @x@.
insertByCCC :: Int -> [Int] -> [Int]
insertByCCC x [] = [x]
insertByCCC x (y : ys)
  | canonicalCombiningClass x < canonicalCombiningClass y = x : y : ys
  | otherwise = y : insertByCCC x ys

-- | Stably sort a list of non-starter codepoints by CCC.
sortNonStarterRun :: [Int] -> [Int]
sortNonStarterRun = foldl (\sorted cp -> insertByCCC cp sorted) []

-- | Fold state for the reorder pass. @currentRun@ accumulates
-- non-starters in REVERSE scan order (O(1) prepend); it is reversed back
-- into scan order before sorting when flushed.
data ReorderState = ReorderState
  { emitted    :: ![Int]
  , currentRun :: ![Int]
  }

-- | Sort the accumulated non-starter run into scan-then-CCC order.
flushRun :: ReorderState -> [Int]
flushRun s = sortNonStarterRun (reverse (currentRun s))

-- | Process one codepoint: a starter flushes the pending run and emits
-- itself; a non-starter extends the pending run.
stepReorder :: ReorderState -> Int -> ReorderState
stepReorder s cp
  | canonicalCombiningClass cp == 0 =
      ReorderState { emitted = emitted s ++ flushRun s ++ [cp], currentRun = [] }
  | otherwise = s { currentRun = cp : currentRun s }

-- | Canonical reordering of a codepoint sequence per UAX #15 §1.3.
reorder :: [Int] -> [Int]
reorder cps =
  let final = foldl stepReorder (ReorderState [] []) cps
  in emitted final ++ flushRun final
