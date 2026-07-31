module CovertDisplayCompoundSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertEqual, testCase)

import qualified Unicode.Security.Policy as Policy

tests :: TestTree
tests = testGroup "Unicode.Security.Boundary.CovertDisplayCompound"
  [ testCase "covert-display-compound vectors" covertDisplayCompoundVectors
  ]

-- Ground truth: the @detect_*@ spot-check theorems in
-- @Unicode/Security/Boundary/CovertDisplayCompound.lean@, each proven by
-- @decide +kernel@, mirrored by the Rust port's @covert_display_compound@
-- tests. 'Nothing' means the input is clear of any covert-display-compound
-- finding.
covertDisplayCompoundVectors :: Assertion
covertDisplayCompoundVectors =
  mapM_ check
    [ ([], Nothing)
    , ([0x48, 0x65, 0x6C, 0x6C, 0x6F], Nothing)
    , ([0x202E], Nothing)
    , ([0x0041, 0xFE00], Nothing)
    , ([0x202E, 0x0041, 0xFE00], Just "BidiPlusUnregisteredVs")
    , ([0x202E, 0x0041, 0xE0001], Just "BidiPlusTagBlock")
    ]
  where
    check :: ([Int], Maybe String) -> Assertion
    check (input, expected) =
      let verdict = Policy.scan Policy.ProfileGatewayHeader Policy.ModeObserve input
          subThreats =
            [ Policy.findingSubThreat finding
            | finding <- Policy.verdictFindings verdict
            , Policy.findingFamily finding == Policy.FamilyCovertDisplayCompound
            ]
      in assertEqual (show input) (maybe [] (: []) expected) subThreats
