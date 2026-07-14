{-|
Module      : Unicode.Normalization.Hangul
Description : Algorithmic Hangul syllable decomposition and composition.

Haskell port of @Unicode.Normalization.Hangul@ from unicode-lean.

Algorithmic Hangul syllable decomposition and composition per UAX #15
§4.2. The 11172 precomposed Hangul syllables in @U+AC00..U+D7A3@
decompose to sequences of jamo (leading consonant L, vowel V, and
optional trailing consonant T) by arithmetic on codepoint offsets,
rather than via the UnicodeData table. Keeping this logic isolated
keeps the general-purpose decomposition path small.
-}
module Unicode.Normalization.Hangul
  ( -- * Range constants
    sBase
  , lBase
  , vBase
  , tBase
  , lCount
  , vCount
  , tCount
  , nCount
  , sCount

    -- * Predicates
  , isHangulSyllable
  , isLJamo
  , isVJamo
  , isTJamo

    -- * Decomposition / composition
  , decomposeSyllable
  , composePair
  ) where

-- ─────────────────────────────────────────────────────────────────────────
-- Range constants
-- ─────────────────────────────────────────────────────────────────────────

-- | Base codepoint of precomposed Hangul syllables (HANGUL SYLLABLE GA).
sBase :: Int
sBase = 0xAC00

-- | Base codepoint of leading consonants (L jamo; HANGUL CHOSEONG KIYEOK).
lBase :: Int
lBase = 0x1100

-- | Base codepoint of vowels (V jamo; HANGUL JUNGSEONG A).
vBase :: Int
vBase = 0x1161

-- | Base codepoint of trailing consonants (T jamo), offset by one so
-- that @tBase + 0@ is the \"no trailing consonant\" sentinel rather
-- than an actual jamo. Real trailing jamo start at @tBase + 1@
-- (HANGUL JONGSEONG KIYEOK).
tBase :: Int
tBase = 0x11A7

lCount, vCount, tCount, nCount, sCount :: Int
lCount = 19
vCount = 21
tCount = 28
nCount = vCount * tCount            -- 588
sCount = lCount * nCount            -- 11172

-- ─────────────────────────────────────────────────────────────────────────
-- Predicates
-- ─────────────────────────────────────────────────────────────────────────

-- | True iff @cp@ is a precomposed Hangul syllable in @U+AC00..U+D7A3@.
isHangulSyllable :: Int -> Bool
isHangulSyllable cp = sBase <= cp && cp < sBase + sCount

-- | True iff @cp@ is a leading jamo in @U+1100..U+1112@.
isLJamo :: Int -> Bool
isLJamo cp = lBase <= cp && cp < lBase + lCount

-- | True iff @cp@ is a vowel jamo in @U+1161..U+1175@.
isVJamo :: Int -> Bool
isVJamo cp = vBase <= cp && cp < vBase + vCount

-- | True iff @cp@ is a trailing jamo in @U+11A8..U+11C2@ — the 27
-- non-filler Jongseong codepoints that can appear as the T slot of a
-- canonical LVT syllable decomposition. The @tBase@ offset places
-- @cp = tBase@ (U+11A7) outside this range intentionally; real
-- trailing jamo begin one above @tBase@. The upper bound is strict
-- (@cp < tBase + tCount@ rather than @<=@) because
-- 'decomposeSyllable' computes @tIndex = sIndex \`mod\` tCount@ in
-- @[0, 27)@, so the T slot it emits is in @[tBase+1, tBase+27] =
-- [U+11A8, U+11C2]@. Accepting @cp = U+11C3 = tBase + tCount@ would
-- break the 'composePair' / 'decomposeSyllable' round-trip at exactly
-- that edge.
isTJamo :: Int -> Bool
isTJamo cp = tBase < cp && cp < tBase + tCount

-- ─────────────────────────────────────────────────────────────────────────
-- Decomposition / composition
-- ─────────────────────────────────────────────────────────────────────────

-- | Canonical decomposition of a Hangul syllable. Produces a
-- two-element list @[L, V]@ when the syllable has no trailing
-- consonant and a three-element list @[L, V, T]@ otherwise. Returns
-- 'Nothing' when @cp@ is not a precomposed Hangul syllable.
decomposeSyllable :: Int -> Maybe [Int]
decomposeSyllable cp
  | isHangulSyllable cp =
      let sIndex = cp - sBase
          l      = lBase + sIndex `div` nCount
          v      = vBase + (sIndex `mod` nCount) `div` tCount
          tIndex = sIndex `mod` tCount
      in if tIndex == 0
           then Just [l, v]
           else Just [l, v, tBase + tIndex]
  | otherwise = Nothing

-- | Canonical composition of a Hangul jamo sequence. Attempts to pair
-- @(L, V)@ into an @LV@ syllable, or @(LV, T)@ where @LV@ is itself a
-- Hangul syllable into an @LVT@ syllable. Returns 'Nothing' when the
-- pair is not composable.
--
-- Per UAX #15 §4.2 this is the ONLY codepoint pair combination
-- allowed for Hangul composition — individual jamo do not compose via
-- the UnicodeData primary-composite table.
composePair :: Int -> Int -> Maybe Int
composePair first second
  | isLJamo first && isVJamo second =
      let lIndex = first  - lBase
          vIndex = second - vBase
      in Just (sBase + (lIndex * vCount + vIndex) * tCount)
  | isHangulSyllable first && isTJamo second =
      let sIndex = first - sBase
      in if sIndex `mod` tCount == 0
           then Just (first + (second - tBase))
           else Nothing
  | otherwise = Nothing
