{-|
  Tests for "Unicode.Normalization.Hangul" — mirrors the closed-form
  theorems in @Unicode/Normalization/Hangul.lean@.

  Each Lean @theorem ... := by decide +kernel@ becomes a HUnit case
  with the same codepoint inputs and the same expected output. A
  roundtrip QuickCheck property asserts
  @composePair . decomposeSyllable@ is the identity on every
  precomposed Hangul syllable in @U+AC00..U+D7A3@.
-}
module HangulSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)
import Test.Tasty.QuickCheck (testProperty, withMaxSuccess)
import Test.QuickCheck (Gen, choose, forAll)

import Unicode.Normalization.Hangul
  ( composePair
  , decomposeSyllable
  , isHangulSyllable
  , sBase
  , sCount
  )

tests :: TestTree
tests = testGroup "Unicode.Normalization.Hangul"
  [ unitTests
  , roundtripProps
  ]

-- ─────────────────────────────────────────────────────────────────────────
-- Unit tests — direct ports of the Lean test vectors
-- ─────────────────────────────────────────────────────────────────────────

unitTests :: TestTree
unitTests = testGroup "decompose / compose witnesses"
  [ testCase "decompose_GA — HANGUL SYLLABLE GA = [L, V]" $
      assertEqual "U+AC00"
        (Just [0x1100, 0x1161])
        (decomposeSyllable 0xAC00)

  , testCase "decompose_GAG — HANGUL SYLLABLE GAG = [L, V, T]" $
      assertEqual "U+AC01"
        (Just [0x1100, 0x1161, 0x11A8])
        (decomposeSyllable 0xAC01)

  , testCase "decompose_last — HANGUL SYLLABLE HIH = [L, V, T]" $
      assertEqual "U+D7A3"
        (Just [0x1112, 0x1175, 0x11C2])
        (decomposeSyllable 0xD7A3)

  , testCase "decompose_latin_A — non-syllable returns Nothing" $
      assertEqual "U+0041"
        Nothing
        (decomposeSyllable 0x0041)

  , testCase "compose_GA — L + V recovers HANGUL SYLLABLE GA" $
      assertEqual "L=U+1100, V=U+1161"
        (Just 0xAC00)
        (composePair 0x1100 0x1161)

  , testCase "compose_GAG — LV + T recovers HANGUL SYLLABLE GAG" $
      assertEqual "LV=U+AC00, T=U+11A8"
        (Just 0xAC01)
        (composePair 0xAC00 0x11A8)

  , testCase "compose_latin_pair — non-Hangul pairs do not compose" $
      assertEqual "A + combining-grave"
        Nothing
        (composePair 0x0041 0x0300)

  , testCase "range_low — U+AC00 is a syllable" $
      assertEqual "lower boundary"
        True
        (isHangulSyllable 0xAC00)

  , testCase "range_high — U+D7A3 is a syllable" $
      assertEqual "upper boundary"
        True
        (isHangulSyllable 0xD7A3)

  , testCase "range_out — U+D7A4 is NOT a syllable" $
      assertEqual "above upper boundary"
        False
        (isHangulSyllable 0xD7A4)
  ]

-- ─────────────────────────────────────────────────────────────────────────
-- Roundtrip — decompose then compose recovers the original syllable
-- ─────────────────────────────────────────────────────────────────────────

roundtripProps :: TestTree
roundtripProps = testGroup "roundtrip"
  [ testProperty "every precomposed syllable round-trips" $
      withMaxSuccess 2000 $
        forAll hangulSyllable $ \cp ->
            case decomposeSyllable cp of
                Just [l, v] ->
                    composePair l v == Just cp
                Just [l, v, t] ->
                    case composePair l v of
                        Just lv -> composePair lv t == Just cp
                        Nothing -> False
                _ -> False
  ]

hangulSyllable :: Gen Int
hangulSyllable = choose (sBase, sBase + sCount - 1)
