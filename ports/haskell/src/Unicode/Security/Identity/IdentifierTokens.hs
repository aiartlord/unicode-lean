{-# LANGUAGE StrictData #-}

-- |
-- Module      : Unicode.Security.Identity.IdentifierTokens
-- Description : Identifier-shaped tokens of a running-text field.
--
-- Direct port of @Unicode/Security/Identity/IdentifierTokens.lean@. A source
-- line, a chat message or a display name is not one identifier, but the
-- identifier-shaped words inside it are the surface a homoglyph attack targets
-- (@scоpe@ with a Cyrillic о in @let scоpe = 1;@). A token is a maximal run of
-- @XID_Continue@ codepoints; everything else (space, punctuation, operators,
-- format controls) separates tokens. Each token carries its start position so
-- a finding made on the token can be reported in input coordinates.
module Unicode.Security.Identity.IdentifierTokens
  ( Token (..)
  , tokens
  , shiftPositions
  ) where

import Unicode.Security.Boundary.AdmissibilityFormDrift (isXidContinue)

-- | One identifier-shaped run: its start position in the input and its
-- codepoints. Mirrors the Lean @Token@.
data Token = Token
  { tokenStart :: Int
  , tokenCps   :: [Int]
  }
  deriving (Eq, Show)

-- | The maximal @XID_Continue@ runs of the input, in input order. Mirrors the
-- Lean @tokens@ (the @walk@ with an open run threaded through).
tokens :: [Int] -> [Token]
tokens input = walk (zip [0 ..] input) Nothing
  where
    -- The open run is carried reversed and flipped on close, as in the Lean.
    walk :: [(Int, Int)] -> Maybe (Int, [Int]) -> [Token]
    walk [] Nothing = []
    walk [] (Just (start, revCps)) = [Token start (reverse revCps)]
    walk ((idx, cp) : rest) open
      | isXidContinue cp =
          case open of
            Nothing -> walk rest (Just (idx, [cp]))
            Just (start, revCps) -> walk rest (Just (start, cp : revCps))
      | otherwise =
          case open of
            Nothing -> walk rest Nothing
            Just (start, revCps) -> Token start (reverse revCps) : walk rest Nothing

-- | Move token-local positions back into input coordinates.
shiftPositions :: Int -> [Int] -> [Int]
shiftPositions start = map (+ start)
