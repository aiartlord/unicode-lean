{-|
Module      : Unicode.Security.Crypto.Bip39Canonical
Description : BIP-39 mnemonic canonical-form detector.

Haskell port of @Unicode.Security.Crypto.Bip39Canonical@ from
unicode-lean.

A BIP-39 mnemonic is canonical when it equals its NFKD → default-locale
lowercase → whitespace-collapse → trim normal form. 'detect' runs six
probes in priority order (first hit wins) — trailing whitespace, mixed
case, whitespace anomaly, non-NFKD input, wordlist mismatch, then language
resolution over the ten 2,048-word BIP-39 wordlists — and returns a
@Verdict@ carrying the classification, the canonical form, and the word
count.

The wordlists load once, at first use, through the same NOINLINE
runtime-table idiom the rest of the security layer uses.
-}
module Unicode.Security.Crypto.Bip39Canonical
  ( Language
      ( English, Japanese, Korean, Spanish, ChineseSimplified
      , ChineseTraditional, French, Italian, Czech, Portuguese
      )
  , allLanguages
  , languageName
  , SubThreat
      ( NonCanonicalForm, WordlistMismatch, LanguageAmbiguous
      , WhitespaceAnomaly, TrailingWhitespace, NonNFKD, MixedCase
      )
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationTag
  , classificationPositions
  , Verdict (Verdict, verdictInput, verdictClassify, verdictCanonicalForm, verdictWordCount)
  , bip39Canonical
  , detect
  ) where

import Data.Set (Set)
import qualified Data.Set as Set
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe)
import System.IO.Unsafe (unsafePerformIO)

import Paths_unicode_haskell (getDataFileName)
import qualified Unicode.Casing as Casing
import qualified Unicode.Normalization.NFKD as NFKD

-- | The ten BIP-39 wordlist languages, in @allLanguages@ order (English
-- first, so a mnemonic several wordlists could cover resolves to English).
data Language
  = English
  | Japanese
  | Korean
  | Spanish
  | ChineseSimplified
  | ChineseTraditional
  | French
  | Italian
  | Czech
  | Portuguese
  deriving stock (Eq, Ord, Show)

-- | The languages in resolution order.
allLanguages :: [Language]
allLanguages =
  [ English, Japanese, Korean, Spanish, ChineseSimplified
  , ChineseTraditional, French, Italian, Czech, Portuguese
  ]

-- | The vendored wordlist filename stem for a language; also the string a
-- clear verdict reports.
languageName :: Language -> String
languageName English            = "english"
languageName Japanese           = "japanese"
languageName Korean             = "korean"
languageName Spanish            = "spanish"
languageName ChineseSimplified  = "chinese_simplified"
languageName ChineseTraditional = "chinese_traditional"
languageName French             = "french"
languageName Italian            = "italian"
languageName Czech              = "czech"
languageName Portuguese         = "portuguese"

-- | The distinguishable non-canonical conditions. A hazard carries the
-- sub-threat plus the implicated positions.
data SubThreat
  = NonCanonicalForm Int Int
  | WordlistMismatch Int
  | LanguageAmbiguous [Language]
  | WhitespaceAnomaly Int
  | TrailingWhitespace Int
  | NonNFKD Int
  | MixedCase Int
  deriving stock (Eq, Show)

-- | The stable string tag of a sub-threat, matching the Lean @tag@.
subThreatTag :: SubThreat -> String
subThreatTag (NonCanonicalForm _pre _post) = "NonCanonicalForm"
subThreatTag (WordlistMismatch _idx)       = "WordlistMismatch"
subThreatTag (LanguageAmbiguous _langs)    = "LanguageAmbiguous"
subThreatTag (WhitespaceAnomaly _pos)      = "WhitespaceAnomaly"
subThreatTag (TrailingWhitespace _count)   = "TrailingWhitespace"
subThreatTag (NonNFKD _pos)                = "NonNFKD"
subThreatTag (MixedCase _pos)              = "MixedCase"

-- | A top-level classification: clear (with the covering language) or a
-- hazard (with sub-threat and positions).
data Classification
  = Clear Language
  | Hazard SubThreat [Int]
  deriving stock (Eq, Show)

-- | The classification's sub-threat tag: 'Nothing' when clear.
classificationTag :: Classification -> Maybe String
classificationTag (Clear _lang)     = Nothing
classificationTag (Hazard sub _pos) = Just (subThreatTag sub)

-- | The classification's implicated positions ('[]' when clear).
classificationPositions :: Classification -> [Int]
classificationPositions (Clear _lang)          = []
classificationPositions (Hazard _sub positions) = positions

-- | The structured output of 'detect'.
data Verdict = Verdict
  { verdictInput         :: ![Int]
  , verdictClassify      :: !Classification
  , verdictCanonicalForm :: ![Int]
  , verdictWordCount     :: !Int
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- Wordlist tables (loaded once from the vendored data-files)
-- ─────────────────────────────────────────────────────────────────────

wordlistTable :: Map Language (Set [Int])
wordlistTable = unsafePerformIO $ do
  entries <- mapM loadWordlist allLanguages
  pure (Map.fromList entries)
  where
    loadWordlist lang = do
      path <- getDataFileName ("data/bip39/" ++ languageName lang ++ ".txt")
      contents <- readFile path
      let entries = [ map fromEnum line | line <- lines contents, not (null line) ]
      pure (lang, Set.fromList entries)
{-# NOINLINE wordlistTable #-}

-- | True iff @word@ (as codepoints) appears in @lang@'s wordlist.
isInWordlist :: Language -> [Int] -> Bool
isInWordlist lang word = Set.member word (Map.findWithDefault Set.empty lang wordlistTable)

-- | Every language whose wordlist contains @word@.
wordlistsContaining :: [Int] -> [Language]
wordlistsContaining word = filter (\lang -> isInWordlist lang word) allLanguages

-- | The first language whose wordlist covers every word, if any. Empty
-- @words@ resolves to English (every predicate holds vacuously), matching
-- the Lean @findSome?@ over @allLanguages@.
uniqueLanguage :: [[Int]] -> Maybe Language
uniqueLanguage wordSeqs =
  listToMaybe [ lang | lang <- allLanguages, all (isInWordlist lang) wordSeqs ]

-- ─────────────────────────────────────────────────────────────────────
-- Canonicalisation pipeline
-- ─────────────────────────────────────────────────────────────────────

-- | The two BIP-39 word separators: U+0020 SPACE and U+3000 IDEOGRAPHIC
-- SPACE (Japanese mnemonics).
isBip39Whitespace :: Int -> Bool
isBip39Whitespace cp = cp == 0x0020 || cp == 0x3000

-- | Replace every maximal run of BIP-39 whitespace with a single U+0020.
collapseWhitespaceToSingle :: [Int] -> [Int]
collapseWhitespaceToSingle input = reverse (fst (foldl step ([], False) input))
  where
    step (acc, inWhitespace) cp
      | isBip39Whitespace cp = (if inWhitespace then acc else 0x0020 : acc, True)
      | otherwise            = (cp : acc, False)

-- | Strip leading and trailing U+0020 (after whitespace has been collapsed).
trimLeadingTrailing :: [Int] -> [Int]
trimLeadingTrailing =
  reverse . dropWhile (== 0x0020) . reverse . dropWhile (== 0x0020)

-- | The BIP-39 canonical form: NFKD, then default-locale lowercase, then
-- whitespace collapse, then trim (spec order).
bip39Canonical :: [Int] -> [Int]
bip39Canonical =
  trimLeadingTrailing
    . collapseWhitespaceToSingle
    . Casing.toLower Casing.Default
    . NFKD.toNFKD

-- | Split a canonical-form sequence into words at U+0020 boundaries; empty
-- runs between separators contribute no word.
splitWords :: [Int] -> [[Int]]
splitWords = go []
  where
    go acc [] = if null acc then [] else [reverse acc]
    go acc (cp : rest)
      | cp == 0x0020 = (if null acc then [] else [reverse acc]) ++ go [] rest
      | otherwise    = go (cp : acc) rest

-- ─────────────────────────────────────────────────────────────────────
-- Hazard probes
-- ─────────────────────────────────────────────────────────────────────

countTrailingWhitespace :: [Int] -> Int
countTrailingWhitespace = length . takeWhile isBip39Whitespace . reverse

firstUppercasePos :: [Int] -> Maybe Int
firstUppercasePos input =
  listToMaybe [ i | (cp, i) <- zip input [0 ..], 0x41 <= cp, cp <= 0x5A ]

-- | First position of a leading or consecutive BIP-39 whitespace run; a
-- single internal separator does not fire.
firstWhitespaceRunPos :: [Int] -> Maybe Int
firstWhitespaceRunPos input =
  let nexts = map Just (drop 1 input) ++ [Nothing]
  in listToMaybe
       [ i
       | ((cp, nxt), i) <- zip (zip input nexts) [0 ..]
       , isBip39Whitespace cp
       , i == 0 || maybe False isBip39Whitespace nxt
       ]

-- | First position at which two sequences diverge (in element, or one
-- ends); 'Nothing' when identical.
firstArrayDivergence :: [Int] -> [Int] -> Maybe Int
firstArrayDivergence [] [] = Nothing
firstArrayDivergence [] (_bHead : _bTail) = Just 0
firstArrayDivergence (_aHead : _aTail) [] = Just 0
firstArrayDivergence (aHead : aTail) (bHead : bTail)
  | aHead /= bHead = Just 0
  | otherwise      = fmap (+ 1) (firstArrayDivergence aTail bTail)

-- ─────────────────────────────────────────────────────────────────────
-- Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | Detect a non-canonical or wordlist-mismatched BIP-39 mnemonic. Six
-- probes in priority order (first hit wins).
detect :: [Int] -> Verdict
detect input =
  Verdict
    { verdictInput = input
    , verdictClassify = classification
    , verdictCanonicalForm = canonical
    , verdictWordCount = length words'
    }
  where
    canonical = bip39Canonical input
    words'    = splitWords canonical

    trailingCount = countTrailingWhitespace input
    uppercasePos  = firstUppercasePos input
    whitespacePos = firstWhitespaceRunPos input

    nfkd       = NFKD.toNFKD input
    nonNfkdPos  = if input == nfkd then Nothing else firstArrayDivergence input nfkd

    wordlistsPerWord = map wordlistsContaining words'
    firstUnknownIdx  =
      listToMaybe [ i | (langs, i) <- zip wordlistsPerWord [0 ..], null langs ]
    unique = uniqueLanguage words'

    allPossible = foldl addLanguages [] wordlistsPerWord
    addLanguages acc langs =
      foldl (\seen lang -> if lang `elem` seen then seen else seen ++ [lang]) acc langs

    classification
      | trailingCount > 0 =
          Hazard (TrailingWhitespace trailingCount) [length input - trailingCount]
      | otherwise =
          case uppercasePos of
            Just p -> Hazard (MixedCase p) [p]
            Nothing ->
              case whitespacePos of
                Just p -> Hazard (WhitespaceAnomaly p) [p]
                Nothing ->
                  case nonNfkdPos of
                    Just p -> Hazard (NonNFKD p) [p]
                    Nothing ->
                      case firstUnknownIdx of
                        Just idx -> Hazard (WordlistMismatch idx) [idx]
                        Nothing ->
                          case unique of
                            Just lang -> Clear lang
                            Nothing   -> Hazard (LanguageAmbiguous allPossible) []
