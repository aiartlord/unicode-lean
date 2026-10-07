{-|
Module      : Unicode.Normalization.Compose
Description : Canonical composition (UAX #15 §1.3 / D115-D117).

Haskell port of @Unicode.Normalization.Compose@ from unicode-lean.

Folds each codepoint of an already-decomposed, canonically-ordered sequence
into the most recent starter it is not blocked from, forming primary
composites. A candidate is blocked from the active starter when a non-starter
of greater-or-equal combining class stands between them (D115). Hangul
composition (L+V → LV, LV+T → LVT) is tried before the primary-composite
table, which is the inverse of every two-codepoint canonical decomposition
minus the @Full_Composition_Exclusion@ set.
-}
module Unicode.Normalization.Compose
  ( compose
  ) where

import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IntMap (fromListWith, lookup)

import qualified Unicode.Generated.UnicodeData as UnicodeData
import Unicode.Normalization.Hangul (composePair)
import Unicode.Normalization.Lookup (canonicalCombiningClass, isFullCompositionExclusion)

-- | The primary composite of the starter/combiner pair @(d, c)@, if one
-- exists: Hangul composition first, else the codepoint whose canonical
-- decomposition is exactly @[d, c]@ and which is not
-- @Full_Composition_Exclusion@.
primaryComposite :: Int -> Int -> Maybe Int
primaryComposite d c =
  case composePair d c of
    Just p  -> Just p
    Nothing -> IntMap.lookup (pairKey d c) compositeIndex

-- | The primary-composite table: the inverse of every two-codepoint canonical
-- decomposition, minus the @Full_Composition_Exclusion@ set, keyed by its
-- decomposition pair and built once.
--
-- This is the same relation the list comprehension over 'UnicodeData.rows'
-- expressed, and it answers the same way: where two rows decompose to the same
-- pair the earlier one wins, which is the row a left-to-right search would have
-- taken. Reading it from the table is what makes composition affordable — the
-- comprehension visited all 3045 rows for every composing pair and asked
-- 'isFullCompositionExclusion' on each matching one.
compositeIndex :: IntMap Int
compositeIndex =
  IntMap.fromListWith
    (\_later earlier -> earlier)
    [ (pairKey d c, composite)
    | r <- UnicodeData.rows
    , [d, c] <- [UnicodeData.canonicalDecomposition r]
    , let composite = UnicodeData.codepoint r
    , not (isFullCompositionExclusion composite)
    ]
{-# NOINLINE compositeIndex #-}

-- | An ordered codepoint pair packed into one key. The stride is the codespace
-- size, so distinct pairs never collide.
pairKey :: Int -> Int -> Int
pairKey d c = d * 0x110000 + c

-- | Fold state: the settled output in REVERSE scan order, the active starter
-- (if any), the buffered non-starters (nearest-first, also reverse scan
-- order), and the maximum buffered combining class.
--
-- Both lists grow by prepending, so one step costs its own length rather than
-- the length of the settled output; 'flushCompose' restores scan order once.
data ComposeState = ComposeState
  { emittedReversed :: ![Int]
  , starter         :: !(Maybe Int)
  , buffer          :: ![Int]
  , maxCCC          :: !Int
  }

initialState :: ComposeState
initialState = ComposeState [] Nothing [] 0

-- | The settled output, back in scan order.
emitted :: ComposeState -> [Int]
emitted = reverse . emittedReversed

ccc :: Int -> Int
ccc = fromIntegral . canonicalCombiningClass

-- | Process one codepoint (UAX #15 D115/D117): a starter candidate composes
-- with the active starter only when no non-starter is buffered between them; a
-- non-starter composes only when it is not blocked by a buffered non-starter of
-- greater-or-equal combining class.
stepCompose :: ComposeState -> Int -> ComposeState
stepCompose s cp =
  let c = ccc cp
  in case starter s of
       Nothing ->
         if c == 0
           then s { starter = Just cp }
           else s { emittedReversed = cp : emittedReversed s }
       Just st ->
         if c == 0
           then composeStarter s st cp
           else composeNonStarter s st c cp

-- | A new starter: compose with the active starter iff nothing is buffered.
composeStarter :: ComposeState -> Int -> Int -> ComposeState
composeStarter s st cp
  | null (buffer s) =
      case primaryComposite st cp of
        Just p  -> s { starter = Just p }
        Nothing -> ComposeState (st : emittedReversed s) (Just cp) [] 0
  | otherwise =
      -- Scan order here is @st@ then the buffer reversed, so the reverse of
      -- that — what 'emittedReversed' holds — is the buffer as stored, ahead
      -- of @st@.
      ComposeState (buffer s ++ (st : emittedReversed s)) (Just cp) [] 0

-- | A non-starter with combining class @c@: blocked (buffered) when
-- @c <= maxCCC@, else composed with the active starter if a composite exists.
composeNonStarter :: ComposeState -> Int -> Int -> Int -> ComposeState
composeNonStarter s st c cp
  | c <= maxCCC s = s { buffer = cp : buffer s, maxCCC = max (maxCCC s) c }
  | otherwise =
      case primaryComposite st cp of
        Just p  -> s { starter = Just p }
        Nothing -> s { buffer = cp : buffer s, maxCCC = max (maxCCC s) c }

-- | Emit the active starter (if any) followed by the buffered non-starters.
flushCompose :: ComposeState -> [Int]
flushCompose s =
  let bufferList = reverse (buffer s)
  in case starter s of
       Just st -> emitted s ++ [st] ++ bufferList
       Nothing -> emitted s ++ bufferList

-- | Canonical composition of a codepoint sequence per UAX #15 §1.3.
compose :: [Int] -> [Int]
compose = flushCompose . foldl stepCompose initialState
