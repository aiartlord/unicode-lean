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

import Data.Maybe (listToMaybe)

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
    Nothing ->
      listToMaybe
        [ UnicodeData.codepoint r
        | r <- UnicodeData.rows
        , UnicodeData.canonicalDecomposition r == [d, c]
        , not (isFullCompositionExclusion (UnicodeData.codepoint r))
        ]

-- | Fold state: emitted output, the active starter (if any), the buffered
-- non-starters (nearest-last), and the maximum buffered combining class.
data ComposeState = ComposeState
  { emitted :: ![Int]
  , starter :: !(Maybe Int)
  , buffer  :: ![Int]
  , maxCCC  :: !Int
  }

initialState :: ComposeState
initialState = ComposeState [] Nothing [] 0

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
           else s { emitted = emitted s ++ [cp] }
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
        Nothing -> ComposeState (emitted s ++ [st]) (Just cp) [] 0
  | otherwise =
      ComposeState (emitted s ++ [st] ++ reverse (buffer s)) (Just cp) [] 0

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
