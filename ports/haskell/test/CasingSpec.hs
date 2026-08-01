{-|
  Tests for "Unicode.Casing" — mirrors the @toLower@ ground-truth theorems
  in @Unicode/Casing.lean@.

  The dotted and dotless I cases exercise the locale-conditional
  SpecialCasing rows; @HELLO@ and the default @I@ exercise the simple
  lowercase fallback.
-}
module CasingSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Unicode.Casing (Locale (Default, Turkish, Azeri), toLower)

tests :: TestTree
tests = testGroup "Unicode.Casing"
  [ testCase "toLower_hello — HELLO lowercases to hello (Default)" $
      assertEqual "HELLO"
        [0x68, 0x65, 0x6C, 0x6C, 0x6F]
        (toLower Default [0x48, 0x65, 0x6C, 0x6C, 0x6F])

  , testCase "toLower_I_default — U+0049 to U+0069 (Default)" $
      assertEqual "I default" [0x0069] (toLower Default [0x0049])

  , testCase "toLower_I_turkish — U+0049 to U+0131 (Turkish)" $
      assertEqual "I turkish" [0x0131] (toLower Turkish [0x0049])

  , testCase "toLower_I_azeri — U+0049 to U+0131 (Azeri)" $
      assertEqual "I azeri" [0x0131] (toLower Azeri [0x0049])

  , testCase "toLower_dotted_I_turkish — U+0130 to U+0069 (Turkish)" $
      assertEqual "dotted I turkish" [0x0069] (toLower Turkish [0x0130])

  , testCase "toLower_dotted_I_default — U+0130 to U+0069 U+0307 (Default)" $
      assertEqual "dotted I default" [0x0069, 0x0307] (toLower Default [0x0130])
  ]
