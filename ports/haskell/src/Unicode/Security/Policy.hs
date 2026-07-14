{-|
Module      : Unicode.Security.Policy
Description : Product-facing runtime security policy contract.

This module is the Haskell runtime surface for the shared
@scan(profile, mode, input) -> verdict@ contract.  The current v0 slice covers
only the detector families represented in the shared policy fixtures.
-}
module Unicode.Security.Policy
  ( Action (..)
  , Mode (..)
  , Profile (..)
  , PolicyLevel (..)
  , Family (..)
  , ProfilePolicy (..)
  , Finding (..)
  , Verdict (..)
  , actionTag
  , modeTag
  , profileTag
  , familyTag
  , policyOfProfile
  , scan
  , scanUtf8
  , scanUtf16BE
  , scanUtf16LE
  , scanUtf32BE
  , scanUtf32LE
  , reasonCode
  , findingJson
  , verdictJson
  ) where

import Data.Bits (shiftL, xor, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char (chr, isSpace, ord, toLower)
import Data.List (dropWhileEnd, intercalate)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust, mapMaybe)
import Numeric (readHex)
import System.IO.Unsafe (unsafePerformIO)

import qualified Unicode.Codec.Utf8 as Utf8
import Unicode.Codec.Strict
  ( Utf8RejectKind
      ( CodepointBeyondMax
      , InvalidContinuationByte
      , InvalidStartByte
      , OverlongEncoding
      , SurrogateCodepoint
      , TruncatedSequence
      )
  )
import qualified Unicode.Normalization.Lookup as NormalizationLookup
import qualified Unicode.Generated.UnicodeData as UnicodeData
import qualified Unicode.Normalization.Hangul as Hangul

import Paths_unicode_haskell (getDataFileName)

data Action
  = ActionAllow
  | ActionReject
  | ActionQuarantine
  | ActionRewrite
  | ActionObserve
  deriving stock (Eq, Show, Ord)

actionTag :: Action -> String
actionTag ActionAllow      = "allow"
actionTag ActionReject     = "reject"
actionTag ActionQuarantine = "quarantine"
actionTag ActionRewrite    = "rewrite"
actionTag ActionObserve    = "observe"

data Mode
  = ModeObserve
  | ModeWarn
  | ModeEnforce
  | ModeStrict
  deriving stock (Eq, Show, Ord)

modeTag :: Mode -> String
modeTag ModeObserve = "observe"
modeTag ModeWarn    = "warn"
modeTag ModeEnforce = "enforce"
modeTag ModeStrict  = "strict"

data Profile
  = ProfileGatewayHeader
  | ProfileDomainName
  | ProfileDnsLabel
  | ProfileUrl
  | ProfileUsername
  | ProfileDisplayName
  | ProfileChatMessage
  | ProfileSourceCode
  | ProfileOpaqueSecret
  | ProfileBinaryBlob
  deriving stock (Eq, Show, Ord)

profileTag :: Profile -> String
profileTag ProfileGatewayHeader = "gateway-header"
profileTag ProfileDomainName    = "domain-name"
profileTag ProfileDnsLabel      = "dns-label"
profileTag ProfileUrl           = "url"
profileTag ProfileUsername      = "username"
profileTag ProfileDisplayName   = "display-name"
profileTag ProfileChatMessage   = "chat-message"
profileTag ProfileSourceCode    = "source-code"
profileTag ProfileOpaqueSecret  = "opaque-secret"
profileTag ProfileBinaryBlob    = "binary-blob"

data PolicyLevel
  = PolicyRestrictive
  | PolicyModerate
  | PolicyMinimal
  deriving stock (Eq, Show, Ord)

data Family
  = FamilyMalformedUtf8
  | FamilyMalformedUtf16
  | FamilyMalformedUtf32
  | FamilyTagBlockPayload
  | FamilyVariationSelectorPayload
  | FamilyZeroWidthPayload
  | FamilyBidiControlBalance
  | FamilyNoncharacterControl
  | FamilyHomoglyphConfusable
  | FamilyMixedScriptAdmissibility
  deriving stock (Eq, Show, Ord)

familyTag :: Family -> String
familyTag FamilyMalformedUtf8 = "malformed-utf8"
familyTag FamilyMalformedUtf16 = "malformed-utf16"
familyTag FamilyMalformedUtf32 = "malformed-utf32"
familyTag FamilyTagBlockPayload    = "tag-block-payload"
familyTag FamilyVariationSelectorPayload = "variation-selector-payload"
familyTag FamilyZeroWidthPayload   = "zero-width-payload"
familyTag FamilyBidiControlBalance = "bidi-control-balance"
familyTag FamilyNoncharacterControl = "noncharacter-control"
familyTag FamilyHomoglyphConfusable = "homoglyph-confusable"
familyTag FamilyMixedScriptAdmissibility = "mixed-script-admissibility"

data ProfilePolicy = ProfilePolicy
  { policyLevel      :: PolicyLevel
  , policyQuarantine :: Bool
  }
  deriving stock (Eq, Show)

data Finding = Finding
  { findingCode      :: String
  , findingFamily    :: Family
  , findingSeverity  :: Int
  , findingPositions :: [Int]
  , findingSubThreat :: String
  , findingDetail    :: String
  }
  deriving stock (Eq, Show)

data Verdict = Verdict
  { verdictInput      :: [Int]
  , verdictProfile    :: Profile
  , verdictMode       :: Mode
  , verdictAction     :: Action
  , verdictFindings   :: [Finding]
  , verdictNormalized :: Maybe [Int]
  }
  deriving stock (Eq, Show)

findingJson :: Finding -> String
findingJson finding =
  "{"
    ++ "\"code\":" ++ jsonString (findingCode finding)
    ++ ",\"family\":" ++ jsonString (familyTag (findingFamily finding))
    ++ ",\"severity\":" ++ show (findingSeverity finding)
    ++ ",\"positions\":" ++ intArrayJson (findingPositions finding)
    ++ ",\"sub_threat\":" ++ jsonString (findingSubThreat finding)
    ++ ",\"detail\":" ++ jsonString (findingDetail finding)
    ++ "}"

verdictJson :: Verdict -> String
verdictJson verdict =
  "{"
    ++ "\"action\":" ++ jsonString (actionTag (verdictAction verdict))
    ++ ",\"profile\":" ++ jsonString (profileTag (verdictProfile verdict))
    ++ ",\"mode\":" ++ jsonString (modeTag (verdictMode verdict))
    ++ ",\"input\":" ++ intArrayJson (verdictInput verdict)
    ++ ",\"findings\":[" ++ intercalate "," (map findingJson (verdictFindings verdict)) ++ "]"
    ++ ",\"normalized\":" ++ maybe "null" intArrayJson (verdictNormalized verdict)
    ++ "}"

jsonString :: String -> String
jsonString text = "\"" ++ concatMap escapeJsonChar text ++ "\""
  where
    escapeJsonChar '"'  = "\\\""
    escapeJsonChar '\\' = "\\\\"
    escapeJsonChar '\n' = "\\n"
    escapeJsonChar '\r' = "\\r"
    escapeJsonChar '\t' = "\\t"
    escapeJsonChar c    = [c]

intArrayJson :: [Int] -> String
intArrayJson values = "[" ++ intercalate "," (map show values) ++ "]"

policyOfProfile :: Profile -> ProfilePolicy
policyOfProfile ProfileGatewayHeader = ProfilePolicy PolicyRestrictive False
policyOfProfile ProfileDomainName    = ProfilePolicy PolicyRestrictive False
policyOfProfile ProfileDnsLabel      = ProfilePolicy PolicyRestrictive False
policyOfProfile ProfileSourceCode    = ProfilePolicy PolicyRestrictive False
policyOfProfile ProfileUrl           = ProfilePolicy PolicyModerate False
policyOfProfile ProfileUsername      = ProfilePolicy PolicyModerate True
policyOfProfile ProfileDisplayName   = ProfilePolicy PolicyMinimal True
policyOfProfile ProfileChatMessage   = ProfilePolicy PolicyMinimal True
policyOfProfile ProfileOpaqueSecret  = ProfilePolicy PolicyMinimal False
policyOfProfile ProfileBinaryBlob    = ProfilePolicy PolicyMinimal False

scan :: Profile -> Mode -> [Int] -> Verdict
scan profile mode input =
  let findings = detect input
  in Verdict
       { verdictInput = input
       , verdictProfile = profile
       , verdictMode = mode
       , verdictAction = decide profile mode findings
       , verdictFindings = findings
       , verdictNormalized = Nothing
       }

scanUtf8 :: Profile -> Mode -> ByteString -> Verdict
scanUtf8 profile mode bytes =
  case Utf8.firstInvalidUtf8Offset bytes of
    Just (offset, kind) ->
      malformedDecodeVerdict profile mode FamilyMalformedUtf8 (utf8RejectTag kind) offset
    Nothing -> scan profile mode (Utf8.decodeToCodepoints bytes)

scanUtf16BE :: Profile -> Mode -> ByteString -> Verdict
scanUtf16BE profile mode bytes = scanUtf16 profile mode True bytes

scanUtf16LE :: Profile -> Mode -> ByteString -> Verdict
scanUtf16LE profile mode bytes = scanUtf16 profile mode False bytes

scanUtf32BE :: Profile -> Mode -> ByteString -> Verdict
scanUtf32BE profile mode bytes = scanUtf32 profile mode True bytes

scanUtf32LE :: Profile -> Mode -> ByteString -> Verdict
scanUtf32LE profile mode bytes = scanUtf32 profile mode False bytes

malformedDecodeVerdict :: Profile -> Mode -> Family -> String -> Int -> Verdict
malformedDecodeVerdict profile mode family subThreat offset =
  let findings =
        [ Finding
            { findingCode = reasonCode family subThreat
            , findingFamily = family
            , findingSeverity = 2
            , findingPositions = [offset]
            , findingSubThreat = subThreat
            , findingDetail = familyTag family
            }
        ]
  in Verdict
       { verdictInput = []
       , verdictProfile = profile
       , verdictMode = mode
       , verdictAction = decide profile mode findings
       , verdictFindings = findings
       , verdictNormalized = Nothing
       }

scanUtf16 :: Profile -> Mode -> Bool -> ByteString -> Verdict
scanUtf16 profile mode bigEndian bytes =
  case decodeUtf16 bigEndian bytes of
    Left (subThreat, offset) ->
      malformedDecodeVerdict profile mode FamilyMalformedUtf16 subThreat offset
    Right input -> scan profile mode input

scanUtf32 :: Profile -> Mode -> Bool -> ByteString -> Verdict
scanUtf32 profile mode bigEndian bytes =
  case decodeUtf32 bigEndian bytes of
    Left (subThreat, offset) ->
      malformedDecodeVerdict profile mode FamilyMalformedUtf32 subThreat offset
    Right input -> scan profile mode input

decodeUtf16 :: Bool -> ByteString -> Either (String, Int) [Int]
decodeUtf16 bigEndian bytes = go 0 []
  where
    len = BS.length bytes
    go offset acc
      | offset >= len = Right (reverse acc)
      | offset + 2 > len = Left ("TruncatedCodeUnit", len)
      | otherwise =
          let unit = readWord16 bigEndian bytes offset
              nextOffset = offset + 2
          in if unit >= 0xD800 && unit <= 0xDBFF
               then
                 if nextOffset + 2 > len
                   then Left ("TruncatedSurrogatePair", len)
                   else
                     let low = readWord16 bigEndian bytes nextOffset
                     in if low < 0xDC00 || low > 0xDFFF
                          then Left ("InvalidSurrogatePair", nextOffset)
                          else
                            let cp = 0x10000 + ((unit - 0xD800) `shiftL` 10) + (low - 0xDC00)
                            in go (nextOffset + 2) (cp : acc)
               else if unit >= 0xDC00 && unit <= 0xDFFF
                 then Left ("LoneSurrogate", offset)
                 else go nextOffset (unit : acc)

decodeUtf32 :: Bool -> ByteString -> Either (String, Int) [Int]
decodeUtf32 bigEndian bytes
  | BS.length bytes `mod` 4 /= 0 = Left ("TruncatedCodeUnit", BS.length bytes)
  | otherwise = go 0 []
  where
    len = BS.length bytes
    go offset acc
      | offset >= len = Right (reverse acc)
      | otherwise =
          let cp = readWord32 bigEndian bytes offset
          in if cp >= 0xD800 && cp <= 0xDFFF
               then Left ("SurrogateCodepoint", offset)
               else if cp > 0x10FFFF
                 then Left ("CodepointBeyondMax", offset)
                 else go (offset + 4) (cp : acc)

readWord16 :: Bool -> ByteString -> Int -> Int
readWord16 bigEndian bytes offset =
  let b0 = fromIntegral (BS.index bytes offset) :: Int
      b1 = fromIntegral (BS.index bytes (offset + 1)) :: Int
  in if bigEndian then (b0 `shiftL` 8) .|. b1 else b0 .|. (b1 `shiftL` 8)

readWord32 :: Bool -> ByteString -> Int -> Int
readWord32 bigEndian bytes offset =
  let b0 = fromIntegral (BS.index bytes offset) :: Int
      b1 = fromIntegral (BS.index bytes (offset + 1)) :: Int
      b2 = fromIntegral (BS.index bytes (offset + 2)) :: Int
      b3 = fromIntegral (BS.index bytes (offset + 3)) :: Int
  in if bigEndian
       then (b0 `shiftL` 24) .|. (b1 `shiftL` 16) .|. (b2 `shiftL` 8) .|. b3
       else b0 .|. (b1 `shiftL` 8) .|. (b2 `shiftL` 16) .|. (b3 `shiftL` 24)

detect :: [Int] -> [Finding]
detect input =
  tagBlockFinding input
    ++ variationSelectorFinding input
    ++ zeroWidthFinding input
    ++ bidiFinding input
    ++ noncharacterControlFindings input
    ++ homoglyphFinding input
    ++ mixedScriptAdmissibilityFinding input

tagBlockFinding :: [Int] -> [Finding]
tagBlockFinding input =
  case positionsWhere isTagBlockAsciiPayload input of
    [] -> []
    positions ->
      [ Finding
          { findingCode = reasonCode FamilyTagBlockPayload "DirectAscii"
          , findingFamily = FamilyTagBlockPayload
          , findingSeverity = 2
          , findingPositions = positions
          , findingSubThreat = "DirectAscii"
          , findingDetail = familyTag FamilyTagBlockPayload
          }
      ]

zeroWidthFinding :: [Int] -> [Finding]
zeroWidthFinding input =
  case positionsWhere isZeroWidthPayload input of
    [] -> []
    positions ->
      [ Finding
          { findingCode = reasonCode FamilyZeroWidthPayload "BareZeroWidth"
          , findingFamily = FamilyZeroWidthPayload
          , findingSeverity = 2
          , findingPositions = positions
          , findingSubThreat = "BareZeroWidth"
          , findingDetail = familyTag FamilyZeroWidthPayload
          }
      ]

variationSelectorFinding :: [Int] -> [Finding]
variationSelectorFinding input =
  case positionsWhere isVariationSelector input of
    [] -> []
    positions ->
      let subThreat = variationSelectorSubThreat input positions
      in [ Finding
             { findingCode = reasonCode FamilyVariationSelectorPayload subThreat
             , findingFamily = FamilyVariationSelectorPayload
             , findingSeverity = 2
             , findingPositions = positions
             , findingSubThreat = subThreat
             , findingDetail = familyTag FamilyVariationSelectorPayload
             }
         ]

bidiFinding :: [Int] -> [Finding]
bidiFinding input =
  case positionsWhere isBidiEmbeddingControl input of
    [] -> []
    positions ->
      [ Finding
          { findingCode = reasonCode FamilyBidiControlBalance "UnbalancedEmbedding"
          , findingFamily = FamilyBidiControlBalance
          , findingSeverity = 2
          , findingPositions = positions
          , findingSubThreat = "UnbalancedEmbedding"
          , findingDetail = familyTag FamilyBidiControlBalance
          }
      ]

noncharacterControlFindings :: [Int] -> [Finding]
noncharacterControlFindings input =
  makeFinding "Noncharacter" (positionsWhere isNoncharacter input)
    ++ makeFinding "C0Control" (positionsWhere isC0Control input)
    ++ makeFinding "C1Control" (positionsWhere isC1Control input)
  where
    makeFinding :: String -> [Int] -> [Finding]
    makeFinding _subThreat [] = []
    makeFinding subThreat positions =
      [ Finding
          { findingCode = reasonCode FamilyNoncharacterControl subThreat
          , findingFamily = FamilyNoncharacterControl
          , findingSeverity = 2
          , findingPositions = positions
          , findingSubThreat = subThreat
          , findingDetail = familyTag FamilyNoncharacterControl
          }
      ]

decide :: Profile -> Mode -> [Finding] -> Action
decide _profile _mode [] = ActionAllow
decide _profile ModeObserve _findings = ActionObserve
decide _profile ModeWarn _findings = ActionObserve
decide _profile ModeStrict _findings = ActionReject
decide profile ModeEnforce findings =
  let policy = policyOfProfile profile
  in if any (blocks (policyLevel policy) . findingFamily) findings
       then if policyQuarantine policy then ActionQuarantine else ActionReject
       else ActionAllow

blocks :: PolicyLevel -> Family -> Bool
blocks PolicyRestrictive FamilyTagBlockPayload    = True
blocks PolicyRestrictive FamilyMalformedUtf8      = True
blocks PolicyRestrictive FamilyMalformedUtf16     = True
blocks PolicyRestrictive FamilyMalformedUtf32     = True
blocks PolicyRestrictive FamilyVariationSelectorPayload = True
blocks PolicyRestrictive FamilyZeroWidthPayload   = True
blocks PolicyRestrictive FamilyBidiControlBalance = True
blocks PolicyRestrictive FamilyNoncharacterControl = True
blocks PolicyRestrictive FamilyHomoglyphConfusable = True
blocks PolicyRestrictive FamilyMixedScriptAdmissibility = True
blocks PolicyModerate FamilyTagBlockPayload       = True
blocks PolicyModerate FamilyMalformedUtf8         = True
blocks PolicyModerate FamilyMalformedUtf16        = True
blocks PolicyModerate FamilyMalformedUtf32        = True
blocks PolicyModerate FamilyVariationSelectorPayload = True
blocks PolicyModerate FamilyZeroWidthPayload      = True
blocks PolicyModerate FamilyBidiControlBalance    = True
blocks PolicyModerate FamilyNoncharacterControl = True
blocks PolicyModerate FamilyHomoglyphConfusable = True
blocks PolicyModerate FamilyMixedScriptAdmissibility = True
blocks PolicyMinimal FamilyBidiControlBalance     = True
blocks PolicyMinimal FamilyMalformedUtf8          = True
blocks PolicyMinimal FamilyMalformedUtf16         = True
blocks PolicyMinimal FamilyMalformedUtf32         = True
blocks PolicyMinimal FamilyNoncharacterControl    = True
blocks PolicyMinimal FamilyTagBlockPayload        = False
blocks PolicyMinimal FamilyVariationSelectorPayload = False
blocks PolicyMinimal FamilyZeroWidthPayload       = False
blocks PolicyMinimal FamilyHomoglyphConfusable    = False
blocks PolicyMinimal FamilyMixedScriptAdmissibility = False

positionsWhere :: (Int -> Bool) -> [Int] -> [Int]
positionsWhere predicate input =
  [ index | (index, cp) <- zip [0..] input, predicate cp ]

isTagBlockAsciiPayload :: Int -> Bool
isTagBlockAsciiPayload cp = cp >= 0xE0020 && cp <= 0xE007E

isZeroWidthPayload :: Int -> Bool
isZeroWidthPayload cp =
  cp == 0x200B
    || cp == 0x200C
    || cp == 0x200D
    || cp == 0x2060
    || cp == 0xFEFF

isVariationSelector :: Int -> Bool
isVariationSelector cp =
  (cp >= 0xFE00 && cp <= 0xFE0F)
    || (cp >= 0xE0100 && cp <= 0xE01EF)
    || (cp >= 0x180B && cp <= 0x180D)

variationSelectorSubThreat :: [Int] -> [Int] -> String
variationSelectorSubThreat input positions
  | length positions >= 4 && allSameAt input positions = "RepeatedBase"
  | not (null (decodeVariationSelectorRun input positions)) = "DirectPayload"
  | otherwise = "IllegalTarget"

variationSelectorNibble :: Int -> Maybe Int
variationSelectorNibble cp
  | cp >= 0xFE00 && cp <= 0xFE0F = Just (cp - 0xFE00)
  | cp >= 0xE0100 && cp <= 0xE01EF = Just (cp - 0xE0100 + 16)
  | otherwise = Nothing

decodeVariationSelectorRun :: [Int] -> [Int] -> [Int]
decodeVariationSelectorRun input positions =
  go Nothing [ n | position <- positions, Just n <- [variationSelectorNibble (input !! position)] ]
  where
    go :: Maybe Int -> [Int] -> [Int]
    go _ [] = []
    go Nothing (n:ns) = go (Just n) ns
    go (Just high) (n:ns) = ((high * 16) + n) : go Nothing ns

allSameAt :: [Int] -> [Int] -> Bool
allSameAt _input [] = True
allSameAt input (position:positions) =
  all (\p -> input !! p == input !! position) positions

isBidiEmbeddingControl :: Int -> Bool
isBidiEmbeddingControl cp = cp >= 0x202A && cp <= 0x202E

isNoncharacter :: Int -> Bool
isNoncharacter cp
  | cp < 0 = False
  | cp >= 0xFDD0 && cp <= 0xFDEF = True
  | cp > 0x10FFFF = False
  | otherwise = low16 == 0xFFFE || low16 == 0xFFFF
  where
    low16 = cp `mod` 0x10000

isC0Control :: Int -> Bool
isC0Control cp =
  (cp >= 0 && cp <= 0x1F && cp /= 0x09 && cp /= 0x0A && cp /= 0x0D)
    || cp == 0x7F

isC1Control :: Int -> Bool
isC1Control cp = cp >= 0x80 && cp <= 0x9F

homoglyphFinding :: [Int] -> [Finding]
homoglyphFinding input
  | Just _target <- findTargetMatch input =
      [ makeHomoglyphFinding "TargetMatch" ]
  | any isMathAlphanumeric input =
      [ makeHomoglyphFinding "MathAlpha" ]
  | any isFullwidthHalfwidth input =
      [ makeHomoglyphFinding "WidthClass" ]
  | hasDecompositionSwap input =
      [ makeHomoglyphFinding "DecompositionSwap" ]
  | otherwise = []
  where
    makeHomoglyphFinding :: String -> Finding
    makeHomoglyphFinding subThreat =
      Finding
        { findingCode = reasonCode FamilyHomoglyphConfusable subThreat
        , findingFamily = FamilyHomoglyphConfusable
        , findingSeverity = 2
        , findingPositions = [0 .. length input - 1]
        , findingSubThreat = subThreat
        , findingDetail = familyTag FamilyHomoglyphConfusable
        }

mixedScriptAdmissibilityFinding :: [Int] -> [Finding]
mixedScriptAdmissibilityFinding input
  | hasCrossScriptMix input =
      [ Finding
          { findingCode = reasonCode FamilyMixedScriptAdmissibility "CrossScriptMix"
          , findingFamily = FamilyMixedScriptAdmissibility
          , findingSeverity = 2
          , findingPositions = [0 .. length input - 1]
          , findingSubThreat = "CrossScriptMix"
          , findingDetail = familyTag FamilyMixedScriptAdmissibility
          }
      ]
  | otherwise = []

isMathAlphanumeric :: Int -> Bool
isMathAlphanumeric cp = cp >= 0x1D400 && cp <= 0x1D7FF

isFullwidthHalfwidth :: Int -> Bool
isFullwidthHalfwidth cp = cp >= 0xFF01 && cp <= 0xFFEF

hasDecompositionSwap :: [Int] -> Bool
hasDecompositionSwap input =
  hasComposableAdjacent input || hasOutOfOrderNonStarters input

hasComposableAdjacent :: [Int] -> Bool
hasComposableAdjacent (a:b:rest) =
  isJust (Hangul.composePair a b)
    || Map.member (a, b) primaryCompositionMap
    || hasComposableAdjacent (b:rest)
hasComposableAdjacent _ = False

hasOutOfOrderNonStarters :: [Int] -> Bool
hasOutOfOrderNonStarters (a:b:rest) =
  let ca = fromIntegral (NormalizationLookup.canonicalCombiningClass a) :: Int
      cb = fromIntegral (NormalizationLookup.canonicalCombiningClass b) :: Int
  in (ca /= 0 && cb /= 0 && ca > cb) || hasOutOfOrderNonStarters (b:rest)
hasOutOfOrderNonStarters _ = False

primaryCompositionMap :: Map (Int, Int) Int
primaryCompositionMap =
  Map.fromList
    [ ((a, b), UnicodeData.codepoint row)
    | row <- UnicodeData.rows
    , let cp = UnicodeData.codepoint row
    , [a, b] <- [UnicodeData.canonicalDecomposition row]
    , not (NormalizationLookup.isCompositionExclusion cp)
    , NormalizationLookup.canonicalCombiningClass a == 0
    ]

hasCrossScriptMix :: [Int] -> Bool
hasCrossScriptMix =
  (>= 2) . length . foldl addUnique [] . mapMaybe scriptClass
  where
    addUnique acc script
      | script `elem` acc = acc
      | otherwise = script : acc

scriptClass :: Int -> Maybe String
scriptClass cp
  | isLatinScript cp = Just "Latn"
  | isGreekScript cp = Just "Grek"
  | isCyrillicScript cp = Just "Cyrl"
  | otherwise = Nothing

isLatinScript :: Int -> Bool
isLatinScript cp =
  (0x0041 <= cp && cp <= 0x005A)
    || (0x0061 <= cp && cp <= 0x007A)
    || (0x00C0 <= cp && cp <= 0x024F)
    || (0x1E00 <= cp && cp <= 0x1EFF)

isGreekScript :: Int -> Bool
isGreekScript cp =
  (0x0370 <= cp && cp <= 0x03FF)
    || (0x1F00 <= cp && cp <= 0x1FFF)

isCyrillicScript :: Int -> Bool
isCyrillicScript cp =
  (0x0400 <= cp && cp <= 0x052F)
    || (0x2DE0 <= cp && cp <= 0x2DFF)
    || (0xA640 <= cp && cp <= 0xA69F)

findTargetMatch :: [Int] -> Maybe String
findTargetMatch input =
  foldl' step Nothing knownAttackTargets
  where
    inputLetters = letterSkeleton input

    step :: Maybe String -> String -> Maybe String
    step firstMatch target =
      let targetCps = asciiCodepoints target
          targetLetters = letterSkeleton targetCps
          isMatch = targetCps /= input && ctListEq targetLetters inputLetters
      in case (firstMatch, isMatch) of
           (Nothing, True) -> Just target
           _               -> firstMatch

letterSkeleton :: [Int] -> [Int]
letterSkeleton =
  filter (\cp -> NormalizationLookup.canonicalCombiningClass cp == 0
              && not (isDefaultIgnorableCodepoint cp)
              && not (isWhiteSpaceCodepoint cp))
    . iteratedSkeleton

iteratedSkeleton :: [Int] -> [Int]
iteratedSkeleton = go (8 :: Int)
  where
    go 0 current = current
    go fuel current =
      let next = skeleton current
      in if next == current then current else go (fuel - 1) next

skeleton :: [Int] -> [Int]
skeleton =
  toNfdCodepoints
    . map caseFoldCodepoint
    . substituteConfusables
    . map caseFoldCodepoint
    . toNfdCodepoints

toNfdCodepoints :: [Int] -> [Int]
toNfdCodepoints = concatMap decompose
  where
    decompose cp =
      case NormalizationLookup.canonicalDecomposition cp of
        [] -> [cp]
        xs -> concatMap decompose xs

substituteConfusables :: [Int] -> [Int]
substituteConfusables =
  concatMap (\cp -> Map.findWithDefault [cp] cp confusablesMap)

caseFoldCodepoint :: Int -> Int
caseFoldCodepoint cp
  | cp < 0 || cp > 0x10FFFF = cp
  | otherwise = ord (toLower (chr cp))

asciiCodepoints :: String -> [Int]
asciiCodepoints = map ord

ctListEq :: [Int] -> [Int] -> Bool
ctListEq xs ys =
  length xs == length ys
    && foldl' (\acc (x, y) -> acc .|. (x `xor` y)) 0 (zip xs ys) == 0

isDefaultIgnorableCodepoint :: Int -> Bool
isDefaultIgnorableCodepoint cp =
  cp == 0x00AD
    || cp == 0x034F
    || cp == 0x061C
    || inRange 0x115F 0x1160
    || inRange 0x17B4 0x17B5
    || inRange 0x180B 0x180F
    || inRange 0x200B 0x200F
    || inRange 0x202A 0x202E
    || inRange 0x2060 0x206F
    || inRange 0xFE00 0xFE0F
    || cp == 0xFEFF
    || inRange 0xFFF0 0xFFF8
    || inRange 0xE0000 0xE0FFF
  where
    inRange lo hi = lo <= cp && cp <= hi

isWhiteSpaceCodepoint :: Int -> Bool
isWhiteSpaceCodepoint cp =
  cp == 0x0009
    || cp == 0x000A
    || cp == 0x000B
    || cp == 0x000C
    || cp == 0x000D
    || cp == 0x0020
    || cp == 0x0085
    || cp == 0x00A0
    || cp == 0x1680
    || (0x2000 <= cp && cp <= 0x200A)
    || cp == 0x2028
    || cp == 0x2029
    || cp == 0x202F
    || cp == 0x205F
    || cp == 0x3000

confusablesMap :: Map Int [Int]
confusablesMap = unsafePerformIO $ do
  path <- getDataFileName "data/confusables.txt"
  parseConfusables <$> readFile path
{-# NOINLINE confusablesMap #-}

knownAttackTargets :: [String]
knownAttackTargets = unsafePerformIO $ do
  path <- getDataFileName "data/KnownAttackTargets.txt"
  mapMaybe parseTargetLine . lines <$> readFile path
{-# NOINLINE knownAttackTargets #-}

parseConfusables :: String -> Map Int [Int]
parseConfusables =
  Map.fromList . mapMaybe parseConfusableLine . lines

parseConfusableLine :: String -> Maybe (Int, [Int])
parseConfusableLine raw =
  case splitSemicolonFields (stripComment raw) of
    (srcField, tgtField) -> do
      src <- parseHexInt (trim srcField)
      let tgt = mapMaybe parseHexInt (words tgtField)
      if null tgt then Nothing else Just (src, tgt)

splitSemicolonFields :: String -> (String, String)
splitSemicolonFields text =
  let (srcField, rest) = break (== ';') text
  in case rest of
       [] -> ("", "")
       (_:afterFirst) ->
         let (targetField, _) = break (== ';') afterFirst
         in (srcField, targetField)

parseTargetLine :: String -> Maybe String
parseTargetLine raw =
  case trim raw of
    []      -> Nothing
    ('#':_) -> Nothing
    target  -> Just target

stripComment :: String -> String
stripComment = takeWhile (/= '#')

trim :: String -> String
trim = dropWhileEnd isSpace . dropWhile isSpace

parseHexInt :: String -> Maybe Int
parseHexInt text =
  case readHex text of
    [(value, rest)] | all isSpace rest -> Just value
    _                                 -> Nothing

reasonCode :: Family -> String -> String
reasonCode family subThreat =
  "unicode.security." ++ layer family ++ "." ++ familyTag family ++ "." ++ subThreat

layer :: Family -> String
layer FamilyTagBlockPayload    = "C"
layer FamilyMalformedUtf8      = "C"
layer FamilyMalformedUtf16     = "C"
layer FamilyMalformedUtf32     = "C"
layer FamilyVariationSelectorPayload = "C"
layer FamilyZeroWidthPayload   = "C"
layer FamilyBidiControlBalance = "C"
layer FamilyNoncharacterControl = "C"
layer FamilyHomoglyphConfusable = "I"
layer FamilyMixedScriptAdmissibility = "I"

utf8RejectTag :: Utf8RejectKind -> String
utf8RejectTag InvalidStartByte = "InvalidStartByte"
utf8RejectTag TruncatedSequence = "TruncatedSequence"
utf8RejectTag OverlongEncoding = "OverlongEncoding"
utf8RejectTag SurrogateCodepoint = "SurrogateCodepoint"
utf8RejectTag CodepointBeyondMax = "CodepointBeyondMax"
utf8RejectTag InvalidContinuationByte = "InvalidContinuationByte"
