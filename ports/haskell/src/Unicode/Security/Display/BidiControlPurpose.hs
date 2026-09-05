{-# LANGUAGE StrictData #-}

-- |
-- Module      : Unicode.Security.Display.BidiControlPurpose
-- Description : Which bidi format controls serve a purpose, and which do not.
--
-- Direct port of @Unicode/Security/Display/BidiControlPurpose.lean@. The nine
-- UAX #9 format controls exist to manage right-to-left text: a span is doing
-- that job when the text it encloses is right-to-left, or when it forces
-- left-to-right text inside a right-to-left context. A span enclosing no strong
-- right-to-left character in a left-to-right context manages nothing (@LRI user
-- PDI@ around Latin text, @LRO return PDF@ around a keyword), and an unbalanced
-- control never manages anything. Every Trojan Source payload is a control of
-- that kind; a balanced embedding around an Arabic string literal is the
-- opposite case and renders the literal as written.
--
-- This is not source-region filtering: the question is asked of every control
-- wherever it sits, and it is decided from the codepoints the span encloses,
-- never from where a tokenizer would place it.
--
-- Rule, as the Lean @walk@ states it:
--
--   * An opener pushes a span: its position, whether it is an isolate (closed
--     by PDI) or an embedding/override (closed by PDF), and whether it is
--     right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right (LRE, LRO,
--     LRI).
--   * Every other codepoint is recorded against the innermost open span only:
--     strong right-to-left (R or AL), strong left-to-right (L), or ASCII code
--     syntax. A nested span manages its own content.
--   * PDF closes the top span when it is an embedding; against an isolate on
--     top, or an empty stack, it is an orphan. PDI closes down to the innermost
--     isolate, implicitly terminating the embeddings above it, which are thereby
--     unbalanced; with no isolate open it is an orphan.
--   * A closed span is purposeful iff its direct content is exactly its own
--     direction and carries no code syntax; a left-to-right span additionally
--     needs right-to-left context (an enclosing right-to-left span, or a
--     paragraph whose first strong character is right-to-left).
--   * Reported: every orphan, every opener still open at the end, every
--     embedding a PDI terminated implicitly, and both ends of every closed span
--     that was not purposeful.
module Unicode.Security.Display.BidiControlPurpose
  ( isCodeSyntax
  , paragraphIsRtl
  , purposelessControlPositions
  , hasPurposelessControl
  , firstPurposelessControl
  ) where

import Data.List (sort)
import Data.Maybe (listToMaybe)
import qualified Data.Set as Set

import Unicode.Security.CodepointPredicates (isStrongLtr, isStrongRtl)

-- | One open span: where it opened, how it closes, its direction in effect, and
-- what has appeared directly inside it. Mirrors @OpenSpan@.
data OpenSpan = OpenSpan
  { spanPos       :: Int
  , spanIsolate   :: Bool
  , spanRtlKind   :: Bool
  , spanSawRtl    :: Bool
  , spanSawLtr    :: Bool
  , spanSawSyntax :: Bool
  }

-- | RLE, RLO, RLI, or FSI (whose direction resolves from its content). Mirrors
-- @opensRtlKind@.
opensRtlKind :: Int -> Bool
opensRtlKind cp = cp == 0x202B || cp == 0x202E || cp == 0x2067 || cp == 0x2068

-- | LRE, LRO, LRI. Mirrors @opensLtrKind@.
opensLtrKind :: Int -> Bool
opensLtrKind cp = cp == 0x202A || cp == 0x202D || cp == 0x2066

-- | LRI, RLI, FSI. Mirrors @opensIsolateKind@.
opensIsolateKind :: Int -> Bool
opensIsolateKind cp = cp == 0x2066 || cp == 0x2067 || cp == 0x2068

-- | The ASCII codepoints a Trojan Source payload moves — quotes, brackets,
-- comment markers, statement separators, operators. Prose punctuation, space
-- and digits are not in the set. Mirrors @isCodeSyntax@.
isCodeSyntax :: Int -> Bool
isCodeSyntax cp =
  cp `elem`
    [ 0x22, 0x27, 0x60, 0x28, 0x29, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F, 0x5C, 0x2A
    , 0x23, 0x3B, 0x3C, 0x3E, 0x3D, 0x2B, 0x7C, 0x26, 0x25, 0x24, 0x40, 0x5E
    , 0x7E
    ]

-- | UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong
-- character is right-to-left. Mirrors @paragraphIsRtl@.
paragraphIsRtl :: [Int] -> Bool
paragraphIsRtl [] = False
paragraphIsRtl (cp : rest)
  | isStrongRtl cp = True
  | isStrongLtr cp = False
  | otherwise = paragraphIsRtl rest

-- | A closed span is purposeful iff its direct content is exactly its own
-- direction and carries no code syntax. Mirrors @spanPurposeful@.
spanPurposeful :: OpenSpan -> [OpenSpan] -> Bool -> Bool
spanPurposeful s enclosing paragraphRtl
  | spanRtlKind s = spanSawRtl s && not (spanSawLtr s) && not (spanSawSyntax s)
  | otherwise =
      (paragraphRtl || any spanRtlKind enclosing)
        && spanSawLtr s && not (spanSawRtl s) && not (spanSawSyntax s)

-- | Positions of the purposeless bidi format controls in the input, in input
-- order. Empty iff every control is balanced and manages right-to-left text.
-- Mirrors @purposelessControlPositions@.
purposelessControlPositions :: [Int] -> [Int]
purposelessControlPositions input = sort (Set.toList (walk (zip [0 ..] input) [] Set.empty))
  where
    paragraphRtl = paragraphIsRtl input

    -- The stack's head is the innermost open span, as in the Lean list.
    walk :: [(Int, Int)] -> [OpenSpan] -> Set.Set Int -> Set.Set Int
    walk [] stack acc = foldr (Set.insert . spanPos) acc stack
    walk ((idx, cp) : rest) stack acc
      | opensRtlKind cp || opensLtrKind cp =
          walk rest (OpenSpan idx (opensIsolateKind cp) (opensRtlKind cp) False False False : stack) acc
      | cp == 0x202C =
          case stack of
            (top : below)
              | spanIsolate top -> walk rest stack (Set.insert idx acc)
              | spanPurposeful top below paragraphRtl -> walk rest below acc
              | otherwise -> walk rest below (Set.insert (spanPos top) (Set.insert idx acc))
            [] -> walk rest [] (Set.insert idx acc)
      | cp == 0x2069 =
          case break spanIsolate stack of
            (dropped, iso : below) ->
              let acc' = foldr (Set.insert . spanPos) acc dropped
              in if spanPurposeful iso below paragraphRtl
                   then walk rest below acc'
                   else walk rest below (Set.insert (spanPos iso) (Set.insert idx acc'))
            (noIsolateAbove, []) -> walk rest noIsolateAbove (Set.insert idx acc)
      | otherwise =
          case stack of
            (top : below) ->
              walk rest
                (top { spanSawRtl = spanSawRtl top || isStrongRtl cp
                     , spanSawLtr = spanSawLtr top || isStrongLtr cp
                     , spanSawSyntax = spanSawSyntax top || isCodeSyntax cp
                     } : below)
                acc
            [] -> walk rest [] acc

-- | True iff the input carries at least one purposeless bidi format control.
hasPurposelessControl :: [Int] -> Bool
hasPurposelessControl = not . null . purposelessControlPositions

-- | Position and codepoint of the first purposeless control, if any.
firstPurposelessControl :: [Int] -> Maybe (Int, Int)
firstPurposelessControl input =
  listToMaybe [ (pos, cp) | (pos, cp) <- zip [0 ..] input, Set.member pos purposeless ]
  where
    purposeless = Set.fromList (purposelessControlPositions input)
