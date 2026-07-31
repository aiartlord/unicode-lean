module ConfusableBidiCompoundSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertEqual, testCase)

import qualified Unicode.Security.Policy as Policy

tests :: TestTree
tests = testGroup "Unicode.Security.Boundary.ConfusableBidiCompound"
  [ testCase "confusable-bidi-compound vectors" confusableBidiCompoundVectors
  ]

-- Ground truth: the @detect_*@ spot-check theorems in
-- @Unicode/Security/Boundary/ConfusableBidiCompound.lean@, each proven by
-- @decide@, mirrored by the Rust port's @confusable_bidi_compound@ tests.
-- 'Nothing' means the input is clear of any confusable-bidi-compound
-- finding.
confusableBidiCompoundVectors :: Assertion
confusableBidiCompoundVectors =
  mapM_ check
    [ ([], Nothing)
    , ([0x48, 0x65, 0x6C, 0x6C, 0x6F], Nothing)
    , ([0x202E, 0x0041, 0x0042, 0x0043], Nothing)
    , ([0x0430], Nothing)
    , ([0x202E, 0x0430], Just "ConfusableInOverride")
    , ([0x2066, 0x03BF], Just "ConfusableInIsolate")
    ]
  where
    check :: ([Int], Maybe String) -> Assertion
    check (input, expected) =
      let verdict = Policy.scan Policy.ProfileGatewayHeader Policy.ModeObserve input
          subThreats =
            [ Policy.findingSubThreat finding
            | finding <- Policy.verdictFindings verdict
            , Policy.findingFamily finding == Policy.FamilyConfusableBidiCompound
            ]
      in assertEqual (show input) (maybe [] (: []) expected) subThreats
