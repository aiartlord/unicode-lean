module PolicySpec (tests) where

import Control.Applicative ((<|>))
import Data.Char (isDigit)
import qualified Data.ByteString as BS
import Data.List (intercalate)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit
  ( Assertion
  , assertBool
  , assertEqual
  , assertFailure
  , testCase
  )
import Text.ParserCombinators.ReadP
  ( ReadP
  , char
  , eof
  , many
  , munch1
  , readP_to_S
  , satisfy
  , sepBy
  , skipSpaces
  , string
  )

import qualified Unicode.Security.Policy as Policy

tests :: TestTree
tests = testGroup "Unicode.Security.Policy"
  [ testCase "reason codes are stable" reasonCodesStable
  , testCase "policy contract fixture" policyContractFixture
  , testCase "decode contract fixture" decodeContractFixture
  , testCase "multi-encoding decode contract fixture" multiencodingDecodeContractFixture
  , testCase "verdict JSON contract fixture" verdictContractFixture
  , testCase "detector fixtures" detectorFixtures
  ]

reasonCodesStable :: Assertion
reasonCodesStable = do
  assertEqual ""
    "unicode.security.C.tag-block-payload.DirectAscii"
    (Policy.reasonCode Policy.FamilyTagBlockPayload "DirectAscii")
  assertEqual ""
    "unicode.security.C.bidi-control-balance.UnbalancedEmbedding"
    (Policy.reasonCode Policy.FamilyBidiControlBalance "UnbalancedEmbedding")
  assertEqual ""
    "unicode.security.C.noncharacter-control.Noncharacter"
    (Policy.reasonCode Policy.FamilyNoncharacterControl "Noncharacter")
  assertEqual ""
    "unicode.security.C.malformed-utf8.InvalidStartByte"
    (Policy.reasonCode Policy.FamilyMalformedUtf8 "InvalidStartByte")
  assertEqual ""
    "unicode.security.C.malformed-utf16.TruncatedCodeUnit"
    (Policy.reasonCode Policy.FamilyMalformedUtf16 "TruncatedCodeUnit")
  assertEqual ""
    "unicode.security.C.malformed-utf32.CodepointBeyondMax"
    (Policy.reasonCode Policy.FamilyMalformedUtf32 "CodepointBeyondMax")
  assertEqual ""
    "unicode.security.I.homoglyph-confusable.MathAlpha"
    (Policy.reasonCode Policy.FamilyHomoglyphConfusable "MathAlpha")

fixturePath :: FilePath -> FilePath
fixturePath rel = "testdata/fixtures/security/" ++ rel

policyContractFixture :: Assertion
policyContractFixture = do
  value <- parseJsonFile (fixturePath "policy_contract.json")
  assertEqual "" "unicode-security-policy-v0" (fieldString "contract" value)
  mapM_ checkPolicyCase (fieldArray "cases" value)

verdictContractFixture :: Assertion
verdictContractFixture = do
  value <- parseJsonFile (fixturePath "verdict_contract.json")
  assertEqual "" "unicode-security-verdict-v0" (fieldString "contract" value)
  mapM_ checkVerdictCase (fieldArray "cases" value)

detectorFixtures :: Assertion
detectorFixtures =
  mapM_
    checkDetectorFixture
    [ fixturePath "detectors/tag_block_payload.json"
    , fixturePath "detectors/variation_selector_payload.json"
    , fixturePath "detectors/zero_width_payload.json"
    , fixturePath "detectors/bidi_control_balance.json"
    , fixturePath "detectors/noncharacter_control.json"
    , fixturePath "detectors/homoglyph_confusable.json"
    , fixturePath "detectors/mixed_script_admissibility.json"
    ]

checkPolicyCase :: Json -> Assertion
checkPolicyCase value = do
  let name = fieldString "name" value
      profile = parseProfile (fieldString "profile" value)
      mode = parseMode (fieldString "mode" value)
      input = fieldIntArray "input" value
      expectedAction = parseAction (fieldString "action" value)
      requiredFindings = fieldStringArray "required_findings" value
      verdict = Policy.scan profile mode input
      actualCodes = map Policy.findingCode (Policy.verdictFindings verdict)
  assertEqual (name ++ ": action") expectedAction (Policy.verdictAction verdict)
  mapM_
    (\code -> assertBool (name ++ ": missing " ++ code) (code `elem` actualCodes))
    requiredFindings

decodeContractFixture :: Assertion
decodeContractFixture = do
  value <- parseJsonFile (fixturePath "decode_contract.json")
  assertEqual "" "unicode-security-decode-v0" (fieldString "contract" value)
  mapM_ checkDecodeCase (fieldArray "cases" value)

multiencodingDecodeContractFixture :: Assertion
multiencodingDecodeContractFixture = do
  value <- parseJsonFile (fixturePath "decode_multiencoding_contract.json")
  assertEqual "" "unicode-security-multiencoding-decode-v0" (fieldString "contract" value)
  mapM_ checkEncodedDecodeCase (fieldArray "cases" value)

checkDecodeCase :: Json -> Assertion
checkDecodeCase value = do
  let name = fieldString "name" value
      profile = parseProfile (fieldString "profile" value)
      mode = parseMode (fieldString "mode" value)
      inputBytes = BS.pack (map fromIntegral (fieldIntArray "input_bytes" value))
      expectedInput = fieldIntArray "input" value
      expectedAction = parseAction (fieldString "action" value)
      requiredFindings = fieldStringArray "required_findings" value
      verdict = Policy.scanUtf8 profile mode inputBytes
      actualCodes = map Policy.findingCode (Policy.verdictFindings verdict)
  assertEqual (name ++ ": action") expectedAction (Policy.verdictAction verdict)
  assertEqual (name ++ ": input") expectedInput (Policy.verdictInput verdict)
  mapM_
    (\code -> assertBool (name ++ ": missing " ++ code) (code `elem` actualCodes))
    requiredFindings
  mapM_ (checkRequiredPositions name verdict) (fieldArray "required_positions" value)

checkEncodedDecodeCase :: Json -> Assertion
checkEncodedDecodeCase value = do
  let name = fieldString "name" value
      profile = parseProfile (fieldString "profile" value)
      mode = parseMode (fieldString "mode" value)
      inputBytes = BS.pack (map fromIntegral (fieldIntArray "input_bytes" value))
      expectedInput = fieldIntArray "input" value
      expectedAction = parseAction (fieldString "action" value)
      requiredFindings = fieldStringArray "required_findings" value
      verdict = scanEncoded (fieldString "encoding" value) profile mode inputBytes
      actualCodes = map Policy.findingCode (Policy.verdictFindings verdict)
  assertEqual (name ++ ": action") expectedAction (Policy.verdictAction verdict)
  assertEqual (name ++ ": input") expectedInput (Policy.verdictInput verdict)
  mapM_
    (\code -> assertBool (name ++ ": missing " ++ code) (code `elem` actualCodes))
    requiredFindings
  mapM_ (checkRequiredPositions name verdict) (fieldArray "required_positions" value)

scanEncoded :: String -> Policy.Profile -> Policy.Mode -> BS.ByteString -> Policy.Verdict
scanEncoded "utf-8" = Policy.scanUtf8
scanEncoded "utf-16be" = Policy.scanUtf16BE
scanEncoded "utf-16le" = Policy.scanUtf16LE
scanEncoded "utf-32be" = Policy.scanUtf32BE
scanEncoded "utf-32le" = Policy.scanUtf32LE
scanEncoded encoding = error ("unknown encoding: " ++ encoding)

checkRequiredPositions :: String -> Policy.Verdict -> Json -> Assertion
checkRequiredPositions name verdict expected = do
  let code = fieldString "code" expected
      positions = fieldIntArray "positions" expected
      matches =
        [ Policy.findingPositions finding
        | finding <- Policy.verdictFindings verdict
        , Policy.findingCode finding == code
        ]
  case matches of
    actual : _ -> assertEqual (name ++ ": positions for " ++ code) positions actual
    [] -> assertFailure (name ++ ": missing positions for " ++ code)

checkVerdictCase :: Json -> Assertion
checkVerdictCase value = do
  let name = fieldString "name" value
      profile = parseProfile (fieldString "profile" value)
      mode = parseMode (fieldString "mode" value)
      input = fieldIntArray "input" value
      expected = compactJson (fieldValue "verdict" value)
      actual = Policy.verdictJson (Policy.scan profile mode input)
  assertEqual name expected actual

checkDetectorFixture :: FilePath -> Assertion
checkDetectorFixture path = do
  value <- parseJsonFile path
  let family = parseFamily (fieldString "family" value)
  mapM_ (checkDetectorCase path family) (fieldArray "cases" value)

checkDetectorCase :: FilePath -> Policy.Family -> Json -> Assertion
checkDetectorCase path family value = do
  let name = fieldString "name" value
      input = fieldIntArray "input" value
      requiredFindings = fieldStringArray "required_findings" value
      verdict = Policy.scan Policy.ProfileGatewayHeader Policy.ModeObserve input
      actualCodes = map Policy.findingCode (Policy.verdictFindings verdict)
      familyFindings =
        [ finding
        | finding <- Policy.verdictFindings verdict
        , Policy.findingFamily finding == family
        ]
  mapM_
    (\code -> assertBool (path ++ ":" ++ name ++ ": missing " ++ code) (code `elem` actualCodes))
    requiredFindings
  case requiredFindings of
    [] ->
      assertEqual
        (path ++ ":" ++ name ++ ": unexpected " ++ Policy.familyTag family ++ " finding")
        []
        familyFindings
    _ -> pure ()

parseProfile :: String -> Policy.Profile
parseProfile "gateway-header" = Policy.ProfileGatewayHeader
parseProfile "domain-name" = Policy.ProfileDomainName
parseProfile "dns-label" = Policy.ProfileDnsLabel
parseProfile "url" = Policy.ProfileUrl
parseProfile "username" = Policy.ProfileUsername
parseProfile "display-name" = Policy.ProfileDisplayName
parseProfile "chat-message" = Policy.ProfileChatMessage
parseProfile "source-code" = Policy.ProfileSourceCode
parseProfile "opaque-secret" = Policy.ProfileOpaqueSecret
parseProfile "binary-blob" = Policy.ProfileBinaryBlob
parseProfile tag = error ("unknown profile tag: " ++ tag)

parseMode :: String -> Policy.Mode
parseMode "observe" = Policy.ModeObserve
parseMode "warn" = Policy.ModeWarn
parseMode "enforce" = Policy.ModeEnforce
parseMode "strict" = Policy.ModeStrict
parseMode tag = error ("unknown mode tag: " ++ tag)

parseAction :: String -> Policy.Action
parseAction "allow" = Policy.ActionAllow
parseAction "reject" = Policy.ActionReject
parseAction "quarantine" = Policy.ActionQuarantine
parseAction "rewrite" = Policy.ActionRewrite
parseAction "observe" = Policy.ActionObserve
parseAction tag = error ("unknown action tag: " ++ tag)

parseFamily :: String -> Policy.Family
parseFamily "malformed-utf8" = Policy.FamilyMalformedUtf8
parseFamily "malformed-utf16" = Policy.FamilyMalformedUtf16
parseFamily "malformed-utf32" = Policy.FamilyMalformedUtf32
parseFamily "tag-block-payload" = Policy.FamilyTagBlockPayload
parseFamily "variation-selector-payload" = Policy.FamilyVariationSelectorPayload
parseFamily "zero-width-payload" = Policy.FamilyZeroWidthPayload
parseFamily "bidi-control-balance" = Policy.FamilyBidiControlBalance
parseFamily "noncharacter-control" = Policy.FamilyNoncharacterControl
parseFamily "homoglyph-confusable" = Policy.FamilyHomoglyphConfusable
parseFamily tag = error ("unknown family tag: " ++ tag)

data Json
  = JObject [(String, Json)]
  | JArray [Json]
  | JString String
  | JNumber Int
  | JNull
  deriving stock (Eq, Show)

compactJson :: Json -> String
compactJson (JObject fields) =
  "{" ++ intercalate "," [compactJsonString key ++ ":" ++ compactJson value | (key, value) <- fields] ++ "}"
compactJson (JArray values) =
  "[" ++ intercalate "," (map compactJson values) ++ "]"
compactJson (JString text) = compactJsonString text
compactJson (JNumber number) = show number
compactJson JNull = "null"

compactJsonString :: String -> String
compactJsonString text = "\"" ++ concatMap escape text ++ "\""
  where
    escape '"'  = "\\\""
    escape '\\' = "\\\\"
    escape '\n' = "\\n"
    escape '\r' = "\\r"
    escape '\t' = "\\t"
    escape c    = [c]

parseJsonFile :: FilePath -> IO Json
parseJsonFile path = do
  text <- readFile path
  case readP_to_S (skipSpaces *> jsonValue <* skipSpaces <* eof) text of
    [(value, "")] -> pure value
    _ -> assertFailure ("failed to parse JSON fixture: " ++ path)

jsonValue :: ReadP Json
jsonValue =
  jsonObject
    <|> jsonArray
    <|> jsonString
    <|> jsonNull
    <|> jsonNumber

jsonObject :: ReadP Json
jsonObject = do
  _ <- char '{'
  skipSpaces
  fields <- jsonPair `sepBy` comma
  skipSpaces
  _ <- char '}'
  pure (JObject fields)

jsonPair :: ReadP (String, Json)
jsonPair = do
  JString key <- jsonString
  skipSpaces
  _ <- char ':'
  skipSpaces
  value <- jsonValue
  skipSpaces
  pure (key, value)

jsonArray :: ReadP Json
jsonArray = do
  _ <- char '['
  skipSpaces
  values <- jsonValue `sepBy` comma
  skipSpaces
  _ <- char ']'
  pure (JArray values)

jsonString :: ReadP Json
jsonString = do
  _ <- char '"'
  chars <- many jsonStringChar
  _ <- char '"'
  skipSpaces
  pure (JString chars)

jsonStringChar :: ReadP Char
jsonStringChar =
  satisfy (\c -> c /= '"' && c /= '\\')
    <|> (char '\\' *> escapedChar)

escapedChar :: ReadP Char
escapedChar =
  (char '"' *> pure '"')
    <|> (char '\\' *> pure '\\')
    <|> (char '/' *> pure '/')
    <|> (char 'n' *> pure '\n')
    <|> (char 'r' *> pure '\r')
    <|> (char 't' *> pure '\t')

jsonNull :: ReadP Json
jsonNull = string "null" *> skipSpaces *> pure JNull

jsonNumber :: ReadP Json
jsonNumber = do
  digits <- munch1 (\c -> isDigit c || c == '-')
  skipSpaces
  pure (JNumber (read digits))

comma :: ReadP Char
comma = skipSpaces *> char ',' <* skipSpaces

fieldValue :: String -> Json -> Json
fieldValue key (JObject fields) =
  case lookup key fields of
    Just value -> value
    Nothing -> error ("missing JSON field: " ++ key)
fieldValue key _ = error ("expected object for field: " ++ key)

fieldString :: String -> Json -> String
fieldString key value =
  case fieldValue key value of
    JString text -> text
    other -> error ("expected string field " ++ key ++ ", got " ++ show other)

fieldArray :: String -> Json -> [Json]
fieldArray key value =
  case fieldValue key value of
    JArray values -> values
    other -> error ("expected array field " ++ key ++ ", got " ++ show other)

fieldIntArray :: String -> Json -> [Int]
fieldIntArray key value =
  [ number | JNumber number <- fieldArray key value ]

fieldStringArray :: String -> Json -> [String]
fieldStringArray key value =
  [ text | JString text <- fieldArray key value ]
