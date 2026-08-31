{-|
Module      : Unicode.Security.Policy
Description : Product-facing runtime security policy contract.

This module is the Haskell runtime surface for the shared
@scan(profile, mode, input) -> verdict@ contract, plus the byte-level
@scanUtf8@ / @scanUtf16BE|LE@ / @scanUtf32BE|LE@ entry points that decode and
enforce the wire encoding first.

Eleven detector families are dispatched from 'detect' here and emit the shared
reason-code namespace: tag-block-payload, variation-selector-payload,
zero-width-payload, surrogate-reassembly, bidi-control-balance,
noncharacter-control, homoglyph-confusable, mixed-script-admissibility,
rtl-injection, confusable-bidi-compound and covert-display-compound.

The remaining sixteen families are implemented as standalone modules under
@Unicode.Security.@ -- each exporting its own @detect@ and each covered by its
own tests -- but this module imports none of them, so they do not currently
reach a caller of 'scan'.  The Rust reference dispatches twenty-four families
on plain input, excluding only the three context-specific crypto families, so
this surface is thirteen families short of that reference.  Wiring them is
mechanical rather than new detection logic, since the implementations already
exist; it is not done here yet, and this note is the record of that gap rather
than a claim that it is closed.
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
  , isConfusableSource
  , isDefaultIgnorableCodepoint
  , isVariationSelector
  , isBidiFormatControl
  , isStrongLtr
  , isStrongRtl
  , policyOfProfile
  , tagBlockFinding
  , variationSelectorFinding
  , zeroWidthFinding
  , bidiFinding
  , homoglyphFinding
  , homoglyphConstituentFinding
  , FieldDirection (FieldLTR, FieldRTL)
  , rtlInjectionFindingWithContext
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
import Data.Char (isSpace, ord)
import Data.List (dropWhileEnd, intercalate)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, isJust, listToMaybe, mapMaybe)
import Data.Set (Set)
import qualified Data.Set as Set
import Numeric (readHex)
import System.IO.Unsafe (unsafePerformIO)

import qualified Unicode.Codec.Utf8 as Utf8
import qualified Unicode.Security.Display.SourceDisplayAggregate as SourceDisplay
import qualified Unicode.Security.Boundary.AdmissibilityFormDrift as AdmissibilityDrift
import qualified Unicode.Security.Boundary.IdentifierFormDrift as IdentifierDrift
import qualified Unicode.Security.Display.FilenameDisguise as FilenameDisguise
import qualified Unicode.Security.Display.RendererDivergence as RendererDiv
import qualified Unicode.Security.Form.CaseExpansionMismatch as CaseExpansion
import qualified Unicode.Security.Form.LocaleCaseInversion as LocaleCase
import qualified Unicode.Security.Form.NfcIdempotenceWitness as NfcWitness
import qualified Unicode.Security.Form.NormalizationBomb as NormBomb
import qualified Unicode.Security.Form.StreamSafeViolation as StreamSafe
import qualified Unicode.Security.Form.WidthClassConfusion as WidthClass
import qualified Unicode.Security.Identity.EmojiZwjIntegrity as EmojiZwj
import qualified Unicode.Security.Identity.SkinToneVariationForgery as SkinTone
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
import Unicode.Security.CodepointPredicates
  ( isBidiFormatControl
  , isStrongLtr
  , isStrongRtl
  , isVariationSelector
  )
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
  | FamilySurrogateReassembly
  | FamilyBidiControlBalance
  | FamilyNoncharacterControl
  | FamilyHomoglyphConfusable
  | FamilyMixedScriptAdmissibility
  | FamilyRtlInjection
  | FamilyConfusableBidiCompound
  | FamilyCovertDisplayCompound
  | FamilyEmojiZwjIntegrity
  | FamilySkinToneVariationForgery
  | FamilyFilenameDisguise
  | FamilyRendererDivergence
  | FamilyStreamSafeViolation
  | FamilyCaseExpansionMismatch
  | FamilyIdentifierFormDrift
  | FamilyAdmissibilityFormDrift
  | FamilyNormalizationBomb
  | FamilyLocaleCaseInversion
  | FamilyNfcIdempotenceWitness
  | FamilyWidthClassConfusion
  | FamilySourceDisplayDivergence
  -- The three crypto families judge a candidate against a wordlist, a hashing
  -- rule or a watermark cue, none of which a plain scan supplies. They are
  -- named so the reason-code namespace is complete and are deliberately not
  -- dispatched from 'detect', which is what the reference does on plain input.
  | FamilyBip39Canonical
  | FamilyHashInputStability
  | FamilyAiWatermarkDetectability
  deriving stock (Eq, Show, Ord)

familyTag :: Family -> String
familyTag FamilyMalformedUtf8 = "malformed-utf8"
familyTag FamilyMalformedUtf16 = "malformed-utf16"
familyTag FamilyMalformedUtf32 = "malformed-utf32"
familyTag FamilyTagBlockPayload    = "tag-block-payload"
familyTag FamilyVariationSelectorPayload = "variation-selector-payload"
familyTag FamilyZeroWidthPayload   = "zero-width-payload"
familyTag FamilySurrogateReassembly = "surrogate-reassembly"
familyTag FamilyBidiControlBalance = "bidi-control-balance"
familyTag FamilyNoncharacterControl = "noncharacter-control"
familyTag FamilyHomoglyphConfusable = "homoglyph-confusable"
familyTag FamilyMixedScriptAdmissibility = "mixed-script-admissibility"
familyTag FamilyRtlInjection = "rtl-injection"
familyTag FamilyConfusableBidiCompound = "confusable-bidi-compound"
familyTag FamilyCovertDisplayCompound = "covert-display-compound"
familyTag FamilyEmojiZwjIntegrity = "emoji-zwj-integrity"
familyTag FamilySkinToneVariationForgery = "skin-tone-variation-forgery"
familyTag FamilyFilenameDisguise = "filename-disguise"
familyTag FamilyRendererDivergence = "renderer-divergence"
familyTag FamilySourceDisplayDivergence = "source-display-divergence"
familyTag FamilyStreamSafeViolation = "stream-safe-violation"
familyTag FamilyCaseExpansionMismatch = "case-expansion-mismatch"
familyTag FamilyNormalizationBomb = "normalization-bomb"
familyTag FamilyLocaleCaseInversion = "locale-case-inversion"
familyTag FamilyNfcIdempotenceWitness = "nfc-idempotence-witness"
familyTag FamilyWidthClassConfusion = "width-class-confusion"
familyTag FamilyIdentifierFormDrift = "identifier-form-drift"
familyTag FamilyAdmissibilityFormDrift = "admissibility-form-drift"
familyTag FamilyBip39Canonical = "bip39-canonical"
familyTag FamilyHashInputStability = "hash-input-stability"
familyTag FamilyAiWatermarkDetectability = "ai-watermark-detectability"

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
-- Source files legitimately carry right-to-left string literals, comments
-- written in Hebrew or Arabic, and emoji. Restrictive admits RtlInjection,
-- whose contract treats its input as a declared-LTR field, so under it an
-- ordinary Hebrew comment is rejected. Moderate retains every detector that
-- catches the Trojan Source class while dropping the field-direction
-- assumption a source file does not satisfy.
policyOfProfile ProfileSourceCode    = ProfilePolicy PolicyModerate False
policyOfProfile ProfileUrl           = ProfilePolicy PolicyModerate False
policyOfProfile ProfileUsername      = ProfilePolicy PolicyModerate True
policyOfProfile ProfileDisplayName   = ProfilePolicy PolicyMinimal True
policyOfProfile ProfileChatMessage   = ProfilePolicy PolicyMinimal True
policyOfProfile ProfileOpaqueSecret  = ProfilePolicy PolicyMinimal False
policyOfProfile ProfileBinaryBlob    = ProfilePolicy PolicyMinimal False

-- | True iff the profile names a field that holds one identifier rather than
-- running text.
--
-- A username, a registrable domain and a DNS label are single identifiers, so a
-- codepoint outside the General Security Profile is a hazard in them. The
-- remaining profiles carry prose, source, URLs or opaque bytes, where a space
-- and a punctuation mark are ordinary content. Mirrors @profileIsIdentifierField@
-- in @Unicode/Security/Policy.lean@.
profileIsIdentifierField :: Profile -> Bool
profileIsIdentifierField ProfileDomainName = True
profileIsIdentifierField ProfileDnsLabel = True
profileIsIdentifierField ProfileUsername = True
profileIsIdentifierField _ = False

scan :: Profile -> Mode -> [Int] -> Verdict
scan profile mode input =
  let findings = detect input (profileIsIdentifierField profile)
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

-- | Run every family over @input@. @identifierField@ carries what the caller
-- knows about the field, mirroring @Unicode.Security.RunAll@'s @Context@: a
-- family scoped to identifiers needs to know whether it is holding one.
detect :: [Int] -> Bool -> [Finding]
detect input identifierField =
  tagBlockFinding input
    ++ variationSelectorFinding input
    ++ zeroWidthFinding input
    ++ surrogateReassemblyFinding input
    ++ bidiFinding input
    ++ noncharacterControlFindings input
    ++ homoglyphFinding input
    ++ mixedScriptAdmissibilityFinding input identifierField
    ++ rtlInjectionFinding input
    ++ confusableBidiCompoundFinding input
    ++ covertDisplayCompoundFinding input
    ++ emojiZwjIntegrityFinding input
    ++ skinToneVariationForgeryFinding input
    ++ filenameDisguiseFinding input
    ++ rendererDivergenceFinding input
    ++ streamSafeViolationFinding input
    ++ caseExpansionMismatchFinding input
    ++ identifierFormDriftFinding input
    ++ admissibilityFormDriftFinding input
    ++ normalizationBombFinding input
    ++ localeCaseInversionFinding input
    ++ nfcIdempotenceWitnessFinding input
    ++ widthClassConfusionFinding input
    ++ sourceDisplayDivergenceFinding input

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
-- The sanctioning model: a ZWJ inside a registered emoji sequence and a ZWNJ in
-- an RFC 5892 CONTEXTJ-valid position both carry meaning a reader depends on,
-- so they are recorded as present but not treated as suspicious. An input whose
-- zero-width characters are all sanctioned raises nothing.
zeroWidthFinding input
  | null positions = []
  | not (hasSuspiciousZeroWidth input positions) = []
  | otherwise =
      [ Finding
          { findingCode = reasonCode FamilyZeroWidthPayload "BareZeroWidth"
          , findingFamily = FamilyZeroWidthPayload
          , findingSeverity = 2
          , findingPositions = positions
          , findingSubThreat = "BareZeroWidth"
          , findingDetail = familyTag FamilyZeroWidthPayload
          }
      ]
  where
    positions = positionsWhere isZeroWidthPayload input

-- | Surrogate-reassembly \/ malformed-byte-stream detection (layer C).
-- Direct port of @Unicode.Security.Covert.SurrogateReassembly@. The
-- codepoint list is treated as a byte stream (one octet per entry); the
-- family only applies when every entry is a byte (@< 0x100@), matching the
-- @looksLikeByteStream@ gate. When the shared strict UTF-8 decoder rejects
-- the byte stream, the first violation is projected onto a covert-layer
-- sub-threat at its byte offset. A well-formed stream — or an input that is
-- not a byte stream — is clear.
-- | Module-faithful detect, mirroring
-- @Unicode.Security.Covert.SurrogateReassembly.detect@. Any value @> 0xFF@ is
-- clamped to @0xFF@ (never a valid UTF-8 start byte), exactly as the Lean
-- @toBytes@ helper does, so out-of-range values surface as a malformed stream
-- rather than being dropped. The byte-stream gate lives in the scan
-- orchestrator (@looksLikeByteStream@), mirroring @runAll@.
surrogateReassemblyDetect :: [Int] -> Maybe (String, [Int])
surrogateReassemblyDetect input =
  case Utf8.firstInvalidUtf8Offset (BS.pack (map clampByte input)) of
    Nothing -> Nothing
    Just (offset, kind) -> Just (surrogateReassemblySubThreat kind, [offset])
  where
    clampByte cp = fromIntegral (min cp 0xFF)

-- | Scan-orchestrator wrapper. Mirrors @runAll@: SurrogateReassembly only
-- applies to byte-stream input (every codepoint @<= 0xFF@); on codepoint-array
-- input the family is clear.
surrogateReassemblyFinding :: [Int] -> [Finding]
surrogateReassemblyFinding input
  | not (looksLikeByteStream input) = []
  | otherwise =
      case surrogateReassemblyDetect input of
        Nothing -> []
        Just (subThreat, positions) ->
          [ Finding
              { findingCode = reasonCode FamilySurrogateReassembly subThreat
              , findingFamily = FamilySurrogateReassembly
              , findingSeverity = 2
              , findingPositions = positions
              , findingSubThreat = subThreat
              , findingDetail = familyTag FamilySurrogateReassembly
              }
          ]

-- | True iff every entry fits in one octet — the @looksLikeByteStream@
-- gate. A codepoint list containing any value @>= 0x100@ is not a byte
-- stream, so running the UTF-8 decoder on it would be meaningless.
looksLikeByteStream :: [Int] -> Bool
looksLikeByteStream = all (\cp -> cp >= 0 && cp < 0x100)

-- | Project a 'Utf8RejectKind' onto its surrogate-reassembly sub-threat
-- tag. These tags DIFFER from the malformed-utf8 reject tags emitted by
-- 'utf8RejectTag'; mirrors @subThreatOfRejectKind@ in the Lean spec.
surrogateReassemblySubThreat :: Utf8RejectKind -> String
surrogateReassemblySubThreat OverlongEncoding        = "Overlong"
surrogateReassemblySubThreat SurrogateCodepoint      = "Cesu8"
surrogateReassemblySubThreat TruncatedSequence       = "Truncated"
surrogateReassemblySubThreat InvalidStartByte        = "InvalidStartByte"
surrogateReassemblySubThreat InvalidContinuationByte = "InvalidContinuation"
surrogateReassemblySubThreat CodepointBeyondMax      = "CodepointBeyondMax"

variationSelectorFinding :: [Int] -> [Finding]
variationSelectorFinding input =
  case positionsWhere isVariationSelector input of
    [] -> []
    [position]
      | isRegisteredVariationPosition input position -> []
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
blocks PolicyRestrictive FamilySurrogateReassembly = True
blocks PolicyRestrictive FamilyBidiControlBalance = True
blocks PolicyRestrictive FamilyNoncharacterControl = True
blocks PolicyRestrictive FamilyHomoglyphConfusable = True
blocks PolicyRestrictive FamilyMixedScriptAdmissibility = True
blocks PolicyRestrictive FamilyRtlInjection = True
blocks PolicyRestrictive FamilyConfusableBidiCompound = True
blocks PolicyRestrictive FamilyCovertDisplayCompound = True
blocks PolicyRestrictive FamilyEmojiZwjIntegrity        = True
blocks PolicyRestrictive FamilySkinToneVariationForgery = True
blocks PolicyRestrictive FamilyFilenameDisguise         = True
blocks PolicyRestrictive FamilyRendererDivergence       = True
blocks PolicyRestrictive FamilySourceDisplayDivergence  = True
blocks PolicyRestrictive FamilyStreamSafeViolation      = True
blocks PolicyRestrictive FamilyCaseExpansionMismatch    = True
blocks PolicyRestrictive FamilyNormalizationBomb        = True
blocks PolicyRestrictive FamilyLocaleCaseInversion      = True
blocks PolicyRestrictive FamilyNfcIdempotenceWitness    = True
blocks PolicyRestrictive FamilyWidthClassConfusion      = True
blocks PolicyRestrictive FamilyIdentifierFormDrift      = True
blocks PolicyRestrictive FamilyAdmissibilityFormDrift   = True
blocks PolicyRestrictive FamilyBip39Canonical           = False
blocks PolicyRestrictive FamilyHashInputStability       = False
blocks PolicyRestrictive FamilyAiWatermarkDetectability = False
blocks PolicyModerate FamilyTagBlockPayload       = True
blocks PolicyModerate FamilyMalformedUtf8         = True
blocks PolicyModerate FamilyMalformedUtf16        = True
blocks PolicyModerate FamilyMalformedUtf32        = True
blocks PolicyModerate FamilyVariationSelectorPayload = True
blocks PolicyModerate FamilyZeroWidthPayload      = True
blocks PolicyModerate FamilySurrogateReassembly   = True
blocks PolicyModerate FamilyBidiControlBalance    = True
blocks PolicyModerate FamilyNoncharacterControl = True
blocks PolicyModerate FamilyHomoglyphConfusable = True
blocks PolicyModerate FamilyMixedScriptAdmissibility = True
-- RtlInjection's contract treats its input as a declared-LTR field, which a
-- source file or a display string does not satisfy, so Moderate drops it while
-- keeping every detector that catches the Trojan Source class.
blocks PolicyModerate FamilyRtlInjection = False
blocks PolicyModerate FamilyConfusableBidiCompound = True
blocks PolicyModerate FamilyCovertDisplayCompound = True
blocks PolicyModerate FamilyEmojiZwjIntegrity        = False
blocks PolicyModerate FamilySkinToneVariationForgery = True
blocks PolicyModerate FamilyFilenameDisguise         = True
blocks PolicyModerate FamilyRendererDivergence       = False
blocks PolicyModerate FamilySourceDisplayDivergence  = True
blocks PolicyModerate FamilyStreamSafeViolation      = True
blocks PolicyModerate FamilyCaseExpansionMismatch    = True
blocks PolicyModerate FamilyNormalizationBomb        = False
blocks PolicyModerate FamilyLocaleCaseInversion      = True
blocks PolicyModerate FamilyNfcIdempotenceWitness    = True
blocks PolicyModerate FamilyWidthClassConfusion      = True
blocks PolicyModerate FamilyIdentifierFormDrift      = True
blocks PolicyModerate FamilyAdmissibilityFormDrift   = True
blocks PolicyModerate FamilyBip39Canonical           = False
blocks PolicyModerate FamilyHashInputStability       = False
blocks PolicyModerate FamilyAiWatermarkDetectability = False
blocks PolicyMinimal FamilyBidiControlBalance     = True
blocks PolicyMinimal FamilySurrogateReassembly    = True
blocks PolicyMinimal FamilyMalformedUtf8          = True
blocks PolicyMinimal FamilyMalformedUtf16         = True
blocks PolicyMinimal FamilyMalformedUtf32         = True
blocks PolicyMinimal FamilyNoncharacterControl    = True
blocks PolicyMinimal FamilyTagBlockPayload        = False
blocks PolicyMinimal FamilyVariationSelectorPayload = False
blocks PolicyMinimal FamilyZeroWidthPayload       = False
blocks PolicyMinimal FamilyHomoglyphConfusable    = False
blocks PolicyMinimal FamilyMixedScriptAdmissibility = False
blocks PolicyMinimal FamilyRtlInjection           = False
blocks PolicyMinimal FamilyConfusableBidiCompound = False
blocks PolicyMinimal FamilyCovertDisplayCompound  = False
blocks PolicyMinimal FamilyEmojiZwjIntegrity        = False
blocks PolicyMinimal FamilySkinToneVariationForgery = False
blocks PolicyMinimal FamilyFilenameDisguise         = False
blocks PolicyMinimal FamilyRendererDivergence       = False
blocks PolicyMinimal FamilySourceDisplayDivergence  = False
blocks PolicyMinimal FamilyStreamSafeViolation      = True
blocks PolicyMinimal FamilyCaseExpansionMismatch    = False
blocks PolicyMinimal FamilyNormalizationBomb        = False
blocks PolicyMinimal FamilyLocaleCaseInversion      = False
blocks PolicyMinimal FamilyNfcIdempotenceWitness    = False
blocks PolicyMinimal FamilyWidthClassConfusion      = False
blocks PolicyMinimal FamilyIdentifierFormDrift      = False
blocks PolicyMinimal FamilyAdmissibilityFormDrift   = False
blocks PolicyMinimal FamilyBip39Canonical           = False
blocks PolicyMinimal FamilyHashInputStability       = False
blocks PolicyMinimal FamilyAiWatermarkDetectability = False

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

isRegisteredVariationPosition :: [Int] -> Int -> Bool
isRegisteredVariationPosition input position =
  position > 0
    && Set.member
      (input !! (position - 1), input !! position)
      legalVariationPairs

legalVariationPairs :: Set (Int, Int)
legalVariationPairs = unsafePerformIO $ do
  standardized <- getDataFileName "data/StandardizedVariants.txt" >>= readFile
  emoji <- getDataFileName "data/emoji-variation-sequences.txt" >>= readFile
  pure (parseLegalVariationPairs standardized <> parseLegalVariationPairs emoji)
{-# NOINLINE legalVariationPairs #-}

parseLegalVariationPairs :: String -> Set (Int, Int)
parseLegalVariationPairs =
  Set.fromList . mapMaybe parseLegalVariationPair . lines

parseLegalVariationPair :: String -> Maybe (Int, Int)
parseLegalVariationPair raw =
  case words (takeWhile (/= ';') (stripComment raw)) of
    [baseField, vsField] -> do
      base <- parseHexInt baseField
      vs <- parseHexInt vsField
      pure (base, vs)
    [] -> Nothing
    [_baseOnly] -> Nothing
    _tooManyFields -> Nothing

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

-- | Build the finding list for a family from a sub-threat tag and its
-- positions. Every detector below reports the same shape -- 'Nothing' for a
-- clear input, 'Just' the sub-threat tag otherwise -- so the record is built
-- here once rather than repeated per family. The severity is 2 because each of
-- these classifications is a hazard, matching the reference's Hazard-to-Moderate
-- mapping and the twelve findings already built above.
findingFromTag :: Family -> Maybe String -> [Int] -> [Finding]
findingFromTag _ Nothing _ = []
findingFromTag family (Just subThreat) positions =
  [ Finding
      { findingCode = reasonCode family subThreat
      , findingFamily = family
      , findingSeverity = 2
      , findingPositions = positions
      , findingSubThreat = subThreat
      , findingDetail = familyTag family
      }
  ]

emojiZwjIntegrityFinding :: [Int] -> [Finding]
emojiZwjIntegrityFinding input =
  findingFromTag
    FamilyEmojiZwjIntegrity
    (EmojiZwj.classificationTag classification)
    (EmojiZwj.classificationPositions classification)
  where
    classification = EmojiZwj.verdictClassify (EmojiZwj.detect input)

skinToneVariationForgeryFinding :: [Int] -> [Finding]
skinToneVariationForgeryFinding input =
  findingFromTag
    FamilySkinToneVariationForgery
    (SkinTone.classificationTag classification)
    (SkinTone.classificationPositions classification)
  where
    classification = SkinTone.verdictClassify (SkinTone.detect input)

filenameDisguiseFinding :: [Int] -> [Finding]
filenameDisguiseFinding input =
  findingFromTag
    FamilyFilenameDisguise
    (FilenameDisguise.classificationTag classification)
    (FilenameDisguise.classificationPositions classification)
  where
    classification = FilenameDisguise.verdictClassify (FilenameDisguise.detect input)

rendererDivergenceFinding :: [Int] -> [Finding]
rendererDivergenceFinding input =
  findingFromTag
    FamilyRendererDivergence
    (RendererDiv.classificationTag classification)
    (RendererDiv.classificationPositions classification)
  where
    classification = RendererDiv.verdictClassify (RendererDiv.detect input)

streamSafeViolationFinding :: [Int] -> [Finding]
streamSafeViolationFinding input =
  findingFromTag
    FamilyStreamSafeViolation
    (StreamSafe.classificationTag classification)
    (StreamSafe.classificationPositions classification)
  where
    classification = StreamSafe.verdictClassify (StreamSafe.detect input)

caseExpansionMismatchFinding :: [Int] -> [Finding]
caseExpansionMismatchFinding input =
  findingFromTag
    FamilyCaseExpansionMismatch
    (CaseExpansion.classificationTag classification)
    (CaseExpansion.classificationPositions classification)
  where
    classification = CaseExpansion.verdictClassify (CaseExpansion.detect input)

identifierFormDriftFinding :: [Int] -> [Finding]
identifierFormDriftFinding input =
  findingFromTag
    FamilyIdentifierFormDrift
    (IdentifierDrift.classificationTag classification)
    (IdentifierDrift.classificationPositions classification)
  where
    classification = IdentifierDrift.verdictClassify (IdentifierDrift.detect input)

admissibilityFormDriftFinding :: [Int] -> [Finding]
admissibilityFormDriftFinding input =
  findingFromTag
    FamilyAdmissibilityFormDrift
    (AdmissibilityDrift.classificationTag classification)
    (AdmissibilityDrift.classificationPositions classification)
  where
    classification = AdmissibilityDrift.verdictClassify (AdmissibilityDrift.detect input)

normalizationBombFinding :: [Int] -> [Finding]
normalizationBombFinding input =
  findingFromTag FamilyNormalizationBomb (NormBomb.detectionSub detection) (NormBomb.detectionPositions detection)
  where
    detection = NormBomb.detect input

localeCaseInversionFinding :: [Int] -> [Finding]
localeCaseInversionFinding input =
  findingFromTag FamilyLocaleCaseInversion (LocaleCase.detectionSub detection) (LocaleCase.detectionPositions detection)
  where
    detection = LocaleCase.detect input

nfcIdempotenceWitnessFinding :: [Int] -> [Finding]
nfcIdempotenceWitnessFinding input =
  findingFromTag FamilyNfcIdempotenceWitness (NfcWitness.detectionSub detection) (NfcWitness.detectionPositions detection)
  where
    detection = NfcWitness.detect input

widthClassConfusionFinding :: [Int] -> [Finding]
widthClassConfusionFinding input =
  findingFromTag FamilyWidthClassConfusion (WidthClass.detectionSub detection) (WidthClass.detectionPositions detection)
  where
    detection = WidthClass.detect input

-- | The source-display-divergence aggregate over this scan's own constituent
-- findings. The detector module runs the same five builders itself, but it
-- imports this module to reach them, so importing it back would close a cycle.
-- Both callers share the order and the aggregation rule through
-- "Unicode.Security.Display.SourceDisplayAggregate"; only the way the fired
-- constituents are discovered differs. The family judges the input as a unit,
-- so it localises nothing and carries an empty position list.
sourceDisplayDivergenceFinding :: [Int] -> [Finding]
sourceDisplayDivergenceFinding input =
  findingFromTag
    FamilySourceDisplayDivergence
    (SourceDisplay.classificationTag classification)
    []
  where
    classification =
      SourceDisplay.classify
        (SourceDisplay.firedFrom
          (map (not . null)
            [ tagBlockFinding input
            , variationSelectorFinding input
            , zeroWidthFinding input
            , bidiFinding input
            , homoglyphConstituentFinding input
            ]))

-- | The homoglyph constituent as source-display-divergence sees it. The
-- reference runs one homoglyph detector whose priority ladder ends in a
-- CrossScriptMix branch, so a cross-script identifier fires it; this port
-- splits that ladder, reporting the script mix under
-- mixed-script-admissibility. Consulting only 'homoglyphFinding' misses every
-- input whose sole homoglyph signal is the script mix, so the constituent is
-- defined once here and used by both this module's aggregate and the detector
-- module's own run.
homoglyphConstituentFinding :: [Int] -> [Finding]
homoglyphConstituentFinding input =
  -- The constituent asks the script question about a source file, which is not
  -- an identifier field, so the Restricted-status rung does not apply.
  homoglyphFinding input ++ mixedScriptAdmissibilityFinding input False

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
  -- The last two rungs of the Lean ladder, in its order: a cross-script mix
  -- that is not Highly Restrictive, then a string failing every restriction
  -- level. Both need real script resolution.
  | hasCrossScriptMix input =
      [ makeHomoglyphFinding "CrossScriptMix" ]
  | restrictionLevel input `elem` [RestrictionMinimallyRestrictive, RestrictionUnrestricted] =
      [ makeHomoglyphFinding "RestrictionLow" ]
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

mixedScriptAdmissibilityFinding :: [Int] -> Bool -> [Finding]
mixedScriptAdmissibilityFinding input identifierField
  | Just sub <- mixedScriptVerdict input identifierField =
      [ Finding
          { findingCode = reasonCode FamilyMixedScriptAdmissibility sub
          , findingFamily = FamilyMixedScriptAdmissibility
          , findingSeverity = 2
          , findingPositions = [0 .. length input - 1]
          , findingSubThreat = sub
          , findingDetail = familyTag FamilyMixedScriptAdmissibility
          }
      ]
  | otherwise = []

-- The specific script-collision sub-threat, matching the Lean source of truth:
-- Latin/Cyrillic and Latin/Greek are named explicitly (Cyrillic before Greek);
-- every other multi-script mix is ScriptMixOther.
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

-- UTS #39 §5.1 restriction levels, mirroring @Unicode/Restriction.lean@.
--
-- Script resolution reads the vendored @Scripts.txt@ and @ScriptExtensions.txt@:
-- a codepoint's @Script_Extensions@ where the file gives one, otherwise the
-- abbreviation of its primary @Script@. The abbreviation vocabulary is exactly
-- the set occurring in @ScriptExtensions.txt@, which is what
-- @Unicode/ResolvedScripts.lean@ models as its @ScriptAbbrev@ enum, so a
-- primary script outside it resolves to nothing on both sides. Returning a
-- singleton there instead would make every unknown-script codepoint look
-- Single-Script, putting 'restrictionLevel' one rung too strict and hiding
-- @RestrictionLow@.

data RestrictionLevel
  = RestrictionAsciiOnly
  | RestrictionSingleScript
  | RestrictionHighlyRestrictive
  | RestrictionModeratelyRestrictive
  | RestrictionMinimallyRestrictive
  | RestrictionUnrestricted
  deriving (Eq, Show)

-- | Parse a @"RANGE ; VALUE"@ table into ranges. The value field splits on
-- whitespace, so a @Scripts.txt@ row yields one long name and a
-- @ScriptExtensions.txt@ row yields its abbreviation list.
parseScriptRanges :: String -> [(Int, Int, [String])]
parseScriptRanges raw = mapMaybe parseLine (lines raw)
  where
    parseLine rawLine =
      let body = takeWhile (/= '#') rawLine
          (rangeField, rest) = break (== ';') body
      in case rest of
           (_ : valueField) ->
             let value = words valueField
                 field = trim rangeField
             in case (value, parseRangeField field) of
                  ([], _) -> Nothing
                  (_, Nothing) -> Nothing
                  (_, Just (lo, hi)) -> Just (lo, hi, value)
           [] -> Nothing

    parseRangeField field = case breakOnDots field of
      Just (loText, hiText) -> (,) <$> parseHexInt loText <*> parseHexInt hiText
      Nothing -> (\cp -> (cp, cp)) <$> parseHexInt field

    breakOnDots s = case break (== '.') s of
      (before, '.' : '.' : after) -> Just (before, after)
      _ -> Nothing

scriptRanges :: [(Int, Int, [String])]
scriptRanges = unsafePerformIO $ do
  path <- getDataFileName "data/Scripts.txt"
  parseScriptRanges <$> readFile path
{-# NOINLINE scriptRanges #-}

scriptExtRanges :: [(Int, Int, [String])]
scriptExtRanges = unsafePerformIO $ do
  path <- getDataFileName "data/ScriptExtensions.txt"
  parseScriptRanges <$> readFile path
{-# NOINLINE scriptExtRanges #-}

-- | @DerivedJoiningType.txt@ shares the @"RANGE ; VALUE"@ shape, so it reuses
-- the same parser. RFC 5892 Appendix A.1 reads @Joining_Type@ to decide whether
-- a ZERO WIDTH NON-JOINER sits in a position its script actually requires.
joiningTypeRanges :: [(Int, Int, [String])]
joiningTypeRanges = unsafePerformIO $ do
  path <- getDataFileName "data/DerivedJoiningType.txt"
  parseScriptRanges <$> readFile path
{-# NOINLINE joiningTypeRanges #-}

-- | @Joining_Type@ for one codepoint, as its single-letter token. The file's
-- @\@missing@ line declares @Non_Joining@ over the whole space, so an unlisted
-- codepoint is @\"U\"@.
joiningTypeOf :: Int -> String
joiningTypeOf cp = normalizeToken (listToMaybe matchingTokens)
  where
    matchingTokens =
      concat [value | (lo, hi, value) <- joiningTypeRanges, lo <= cp, cp <= hi]
    normalizeToken Nothing = "U"
    normalizeToken (Just token)
      | token `elem` ["C", "D", "L", "R", "T"] = token
      | otherwise = "U"

-- | True iff the codepoint has Canonical_Combining_Class 9, the Virama used to
-- request an explicit conjunct in scripts like Devanagari.
isViramaCp :: Int -> Bool
isViramaCp cp = NormalizationLookup.canonicalCombiningClass cp == 9

-- | The @Joining_Type@ of the first non-Transparent codepoint before an index.
joiningTypeBefore :: [Int] -> Int -> Maybe String
joiningTypeBefore input i =
  listToMaybe
    [jt | cp <- reverse (take i input), let jt = joiningTypeOf cp, jt /= "T"]

-- | The @Joining_Type@ of the first non-Transparent codepoint after an index.
joiningTypeAfter :: [Int] -> Int -> Maybe String
joiningTypeAfter input i =
  listToMaybe
    [jt | cp <- drop (i + 1) input, let jt = joiningTypeOf cp, jt /= "T"]

-- | True iff the ZWNJ at the given index occupies a position where it is
-- orthographically required, by RFC 5892 Appendix A.1: it follows a Virama,
-- which is how a Devanagari conjunct is suppressed, or it sits between a left-
-- or dual-joining character and a right- or dual-joining one, skipping
-- Transparent characters on both sides, which is how a Persian word boundary is
-- written inside a cursive run.
--
-- A ZWNJ outside such a position carries no orthographic duty and stays
-- reportable.
isLegitimateZwnjContext :: [Int] -> Int -> Bool
isLegitimateZwnjContext input i
  | i > 0 && isViramaCp (input !! (i - 1)) = True
  | otherwise = joinsOnBothSides
  where
    joinsOnBothSides =
      fromMaybe False $ do
        left <- joiningTypeBefore input i
        right <- joiningTypeAfter input i
        pure (left `elem` ["L", "D"] && right `elem` ["R", "D"])

-- | True iff the ZWJ at the given index is flanked by two codepoints that both
-- participate in some registered RGI emoji ZWJ sequence. Strictly narrower than
-- \"is an emoji\": a codepoint carrying the Emoji property but appearing in no
-- registered sequence does not sanction a ZWJ beside it. A ZWJ in head or tail
-- position is never legitimate.
isLegitimateZwjContext :: [Int] -> Int -> Bool
isLegitimateZwjContext input i
  | i == 0 || i + 1 >= length input = False
  | otherwise =
      EmojiZwj.isEmojiTarget (input !! (i - 1))
        && EmojiZwj.isEmojiTarget (input !! (i + 1))

-- | True iff at least one zero-width position of the input is unsanctioned. A
-- ZWJ inside a registered emoji sequence and a ZWNJ in an RFC 5892
-- CONTEXTJ-valid position both carry meaning a reader depends on, so they are
-- recorded as present but do not make the family fire.
hasSuspiciousZeroWidth :: [Int] -> [Int] -> Bool
hasSuspiciousZeroWidth input = any (not . sanctioned)
  where
    sanctioned i =
      let cp = input !! i
      in (cp == 0x200D && isLegitimateZwjContext input i)
           || (cp == 0x200C && isLegitimateZwnjContext input i)

-- | Every abbreviation occurring in @ScriptExtensions.txt@, the resolver's
-- whole vocabulary.
scriptExtAbbrevs :: Set String
scriptExtAbbrevs = Set.fromList [abbrev | (_, _, value) <- scriptExtRanges, abbrev <- value]
{-# NOINLINE scriptExtAbbrevs #-}

-- | Script long name to four-letter abbreviation, from the @sc@ rows of
-- @PropertyValueAliases.txt@.
scriptAliasMap :: Map String String
scriptAliasMap = unsafePerformIO $ do
  path <- getDataFileName "data/PropertyValueAliases.txt"
  Map.fromList . mapMaybe parseAlias . lines <$> readFile path
  where
    parseAlias rawLine = case splitOnSemis (takeWhile (/= '#') rawLine) of
      (prop : abbrev : name : _)
        | trim prop == "sc"
        , not (null (trim abbrev))
        , not (null (trim name)) -> Just (trim name, trim abbrev)
      _ -> Nothing
    splitOnSemis s = case break (== ';') s of
      (before, ';' : after) -> before : splitOnSemis after
      (before, _) -> [before]
{-# NOINLINE scriptAliasMap #-}

findScriptRange :: [(Int, Int, [String])] -> Int -> Maybe [String]
findScriptRange ranges cp =
  case [value | (lo, hi, value) <- ranges, lo <= cp, cp <= hi] of
    (value : _) -> Just value
    [] -> Nothing

scriptOf :: Int -> String
scriptOf cp = case findScriptRange scriptRanges cp of
  Just (name : _) -> name
  _ -> "Unknown"

resolveScripts :: Int -> [String]
resolveScripts cp = case findScriptRange scriptExtRanges cp of
  Just value -> value
  Nothing -> case Map.lookup (scriptOf cp) scriptAliasMap of
    Just abbrev | Set.member abbrev scriptExtAbbrevs -> [abbrev]
    _ -> []

isIgnoredForIntersection :: Int -> Bool
isIgnoredForIntersection cp = scriptOf cp == "Common" || scriptOf cp == "Inherited"

stringScriptUnion :: [Int] -> [String]
stringScriptUnion input =
  foldl addUnique [] (concatMap resolveScripts (filter (not . isIgnoredForIntersection) input))
  where
    addUnique acc s = if s `elem` acc then acc else acc ++ [s]

stringResolvedScripts :: [Int] -> [String]
stringResolvedScripts input =
  case filter (not . isIgnoredForIntersection) input of
    [] -> []
    (first : rest) -> foldl intersect (resolveScripts first) (map resolveScripts rest)
  where
    intersect acc resolved = filter (`elem` resolved) acc

isAsciiOnly :: [Int] -> Bool
isAsciiOnly = all (< 0x80)

isSingleScript :: [Int] -> Bool
isSingleScript input = not (isAsciiOnly input) && not (null (stringResolvedScripts input))

allWithinCovered :: [Int] -> [String] -> Bool
allWithinCovered input covered = all withinCovered (filter (not . isIgnoredForIntersection) input)
  where
    withinCovered cp =
      let resolved = resolveScripts cp
      in not (null resolved) && any (`elem` covered) resolved

isCoveredCjk :: [Int] -> Bool
isCoveredCjk input =
  allWithinCovered input ["Latn", "Hani", "Hira", "Kana"]
    || allWithinCovered input ["Latn", "Hani", "Bopo"]
    || allWithinCovered input ["Latn", "Hani", "Hang"]

isHighlyRestrictive :: [Int] -> Bool
isHighlyRestrictive input = isSingleScript input || isCoveredCjk input

-- | Every codepoint resolves to Latin or to one fixed other Recommended script,
-- with that other script neither Cyrillic nor Greek.
isModeratelyRestrictiveShape :: [Int] -> Bool
isModeratelyRestrictiveShape input = go (filter (not . isIgnoredForIntersection) input) Nothing
  where
    go [] other = isJust other
    go (cp : rest) other =
      let resolved = resolveScripts cp
      in case resolved of
           [] -> False
           (s : _)
             | "Latn" `elem` resolved -> go rest other
             | s == "Cyrl" || s == "Grek" -> False
             | otherwise -> case other of
                 Nothing -> go rest (Just s)
                 Just committed -> s == committed && go rest other

isMinimallyRestrictive :: [Int] -> Bool
isMinimallyRestrictive = all IdentifierDrift.isIdAllowed

restrictionLevel :: [Int] -> RestrictionLevel
restrictionLevel input
  | isAsciiOnly input = RestrictionAsciiOnly
  | isSingleScript input = RestrictionSingleScript
  | isHighlyRestrictive input = RestrictionHighlyRestrictive
  | isModeratelyRestrictiveShape input = RestrictionModeratelyRestrictive
  | isMinimallyRestrictive input = RestrictionMinimallyRestrictive
  | otherwise = RestrictionUnrestricted

hasCrossScriptMix :: [Int] -> Bool
hasCrossScriptMix input =
  length (stringScriptUnion input) >= 2 && not (isHighlyRestrictive input)

-- | The mixed-script sub-threat for @input@, or 'Nothing' when it is
-- admissible.
--
-- The rung order is @MixedScriptAdmissibility.lean@'s: a Restricted-status
-- codepoint outranks every script question, then the two named Latin pairs,
-- then a multi-script mix split by whether it stays inside a CJK covered set,
-- and finally an Unrestricted level with no script mix.
--
-- @identifierField@ carries what the caller knows about the field, mirroring
-- that module's @Context@. Phase 1 is sound for an identifier, which cannot
-- contain a space, and unsound for a document, where every space and every
-- punctuation mark is Restricted.
mixedScriptVerdict :: [Int] -> Bool -> Maybe String
mixedScriptVerdict input identifierField
  | identifierField && any (not . IdentifierDrift.isIdAllowed) input = Just "RestrictedStatusCp"
  | has "Latn" && has "Cyrl" = Just "LatinCyrillic"
  | has "Latn" && has "Grek" = Just "LatinGreek"
  | length union_ >= 2 && not (isHighlyRestrictive input) =
      Just (if isCoveredCjk input then "CjkMix" else "ScriptMixOther")
  | identifierField && restrictionLevel input == RestrictionUnrestricted = Just "UnrestrictedLevel"
  | otherwise = Nothing
  where
    union_ = stringScriptUnion input
    has s = s `elem` union_

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
    . caseFoldCodepoints
    . substituteConfusables
    . caseFoldCodepoints
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

caseFoldCodepoints :: [Int] -> [Int]
caseFoldCodepoints =
  concatMap (\cp -> Map.findWithDefault [cp] cp caseFoldingMap)

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

caseFoldingMap :: Map Int [Int]
caseFoldingMap = unsafePerformIO $ do
  path <- getDataFileName "data/CaseFolding.txt"
  parseCaseFolding <$> readFile path
{-# NOINLINE caseFoldingMap #-}

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

parseCaseFolding :: String -> Map Int [Int]
parseCaseFolding =
  Map.fromList . mapMaybe parseCaseFoldingLine . lines

parseCaseFoldingLine :: String -> Maybe (Int, [Int])
parseCaseFoldingLine raw = do
  (cpField, statusField, mappingField) <- firstThreeSemicolonFields (stripComment raw)
  if trim statusField == "C" || trim statusField == "F"
    then do
      cp <- parseHexInt (trim cpField)
      let mapping = mapMaybe parseHexInt (words mappingField)
      if null mapping then Nothing else Just (cp, mapping)
    else Nothing

firstThreeSemicolonFields :: String -> Maybe (String, String, String)
firstThreeSemicolonFields text =
  case splitAllSemicolonFields text of
    cpField:statusField:mappingField:_remainingFields ->
      Just (cpField, statusField, mappingField)
    [] -> Nothing
    [_cpField] -> Nothing
    [_cpField, _statusField] -> Nothing

splitSemicolonFields :: String -> (String, String)
splitSemicolonFields text =
  let (srcField, rest) = break (== ';') text
  in case rest of
       [] -> ("", "")
       (_:afterFirst) ->
         let (targetField, _) = break (== ';') afterFirst
         in (srcField, targetField)

splitAllSemicolonFields :: String -> [String]
splitAllSemicolonFields text =
  case break (== ';') text of
    (field, []) -> [field]
    (field, _semicolon:rest) -> field : splitAllSemicolonFields rest

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

-- ─────────────────────────────────────────────────────────────────────
-- Right-to-left injection (display layer, reason-code letter "D").
--
-- Direct port of @Unicode/Security/Display/RtlInjection.lean@. Strong
-- Bidi_Class is read from the bundled DerivedBidiClass.txt via
-- 'Unicode.Generated.DerivedBidiClass', mirroring the spec's lookup:
-- an explicit range wins; otherwise the last matching @\@missing@
-- default wins; otherwise the codepoint is @L@.
-- ─────────────────────────────────────────────────────────────────────

-- | Strong Bidi_Class of a codepoint: explicit range first, then the
-- last matching @\@missing@ default, then @L@.
-- | True iff the codepoint's Bidi_Class is strong RTL (R or AL).
-- | Length of the longest consecutive run of strong-RTL codepoints,
-- together with that run's starting index; @(0, 0)@ when there are
-- none.
longestRtlRun :: [Int] -> (Int, Int)
longestRtlRun input =
  let (_index, _current, _currentStart, longest, longestStart) =
        foldl step (0, 0, 0, 0, 0) input
  in (longest, longestStart)
  where
    step (index, current, currentStart, longest, longestStart) cp =
      if isStrongRtl cp
        then
          let newStart = if current == 0 then index else currentStart
              current' = current + 1
          in if current' > longest
               then (index + 1, current', newStart, current', newStart)
               else (index + 1, current', newStart, longest, longestStart)
        else (index + 1, 0, currentStart, longest, longestStart)

-- | The declared display direction of the field holding an input.
--
-- A caller handling Hebrew, Arabic or Persian UI text declares its field
-- right-to-left. Every other reading treats the input as a declared-LTR
-- string, under which right-to-left content is itself the hazard.
--
-- Mirrors @FieldDirection@ in @Unicode\/Security\/Display\/RtlInjection.lean@,
-- that spec's alias for the UAX #9 paragraph-direction vocabulary.
data FieldDirection = FieldLTR | FieldRTL
  deriving (Eq, Show)

-- | Detect right-to-left injection in a field whose declared display direction
-- is the first argument.
--
-- A bidi format control reorders what a reviewer sees whichever way the field
-- runs, so Phase 1 holds unconditionally and trumps all.
--
-- Phases 2 and 3 ask whether right-to-left text has taken over or been spliced
-- into a left-to-right field. That question has no premise in a right-to-left
-- field, where right-to-left text is the content. The mirror-image hazard,
-- strong-LTR injection into a right-to-left field, belongs to the separate
-- detector the scope note assigns it to.
--
-- Within a left-to-right field: (1) any bidi format-control anywhere fires
-- @BidiControlInLTRField@; otherwise (2) a leading strong-RTL codepoint fires
-- @FieldTakeover@; otherwise (3) mid-stream strong-RTL is classified by
-- run length — a run of four or more is @MixedOverflow@ at the run
-- start, a shorter run is @StrongRTLInLTR@ at the first strong-RTL
-- codepoint.
rtlInjectionFindingWithContext :: FieldDirection -> [Int] -> [Finding]
rtlInjectionFindingWithContext direction input =
  case firstBidiControlPos input of
    Just pos -> [makeFinding "BidiControlInLTRField" [pos]]
    Nothing ->
      case direction of
        -- A right-to-left field carrying right-to-left text carries its
        -- content.
        FieldRTL -> []
        FieldLTR ->
          case firstStrongChar input of
            Just (pos, True) -> [makeFinding "FieldTakeover" [pos]]
            _leadingLtrOrNone -> phase3
  where
    strongRtlCount = length (filter isStrongRtl input)
    (runLen, runStart) = longestRtlRun input

    phase3
      | strongRtlCount == 0 = []
      | runLen >= 4 = [makeFinding "MixedOverflow" [runStart]]
      | otherwise =
          case firstStrongRtlPos input of
            Just pos -> [makeFinding "StrongRTLInLTR" [pos]]
            Nothing  -> []

    makeFinding :: String -> [Int] -> Finding
    makeFinding subThreat positions =
      Finding
        { findingCode = reasonCode FamilyRtlInjection subThreat
        , findingFamily = FamilyRtlInjection
        , findingSeverity = 2
        , findingPositions = positions
        , findingSubThreat = subThreat
        , findingDetail = familyTag FamilyRtlInjection
        }

-- | Detect right-to-left injection in a field declared left-to-right, the
-- reading the module scope note fixes for an undeclared field.
rtlInjectionFinding :: [Int] -> [Finding]
rtlInjectionFinding = rtlInjectionFindingWithContext FieldLTR

firstBidiControlPos :: [Int] -> Maybe Int
firstBidiControlPos input =
  listToMaybe [ index | (index, cp) <- zip [0 ..] input, isBidiFormatControl cp ]

firstStrongRtlPos :: [Int] -> Maybe Int
firstStrongRtlPos input =
  listToMaybe [ index | (index, cp) <- zip [0 ..] input, isStrongRtl cp ]

-- | Index and RTL-ness of the first strong (L, R, or AL) codepoint.
firstStrongChar :: [Int] -> Maybe (Int, Bool)
firstStrongChar input =
  listToMaybe
    [ (index, isRtl)
    | (index, cp) <- zip [0 ..] input
    , Just isRtl <- [strongDirection cp]
    ]
  where
    strongDirection cp
      | isStrongRtl cp = Just True
      | isStrongLtr cp = Just False
      | otherwise = Nothing

-- ─────────────────────────────────────────────────────────────────────
-- Confusable-in-bidi-context compound (boundary layer, reason-code
-- letter "X").
--
-- Direct port of @Unicode/Security/Boundary/ConfusableBidiCompound.lean@.
-- A confusable (homoglyph) codepoint co-located with a bidi format-control
-- is materially more dangerous than either alone: the homoglyph disguises
-- an identifier while the bidi control reorders how a reviewer reads it.
-- This detector fires only when both are present, reusing the same
-- 'confusablesMap' the homoglyph detector consults.
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@ is a confusable source per UTS #39 §4 — it has a row in
-- confusables.txt mapping it to a different skeleton sequence. Plain ASCII
-- letters return 'False'; homoglyph forms (Cyrillic а, Greek ο, 'm'→"rn",
-- etc.) return 'True'.
isConfusableSource :: Int -> Bool
isConfusableSource cp = Map.member cp confusablesMap

-- | True iff @cp@ is an override-class bidi control (LRE, RLE, LRO, RLO, PDF).
isOverride :: Int -> Bool
isOverride cp = cp >= 0x202A && cp <= 0x202E

-- | True iff @cp@ is an isolate-class bidi control (LRI, RLI, FSI, PDI).
isIsolate :: Int -> Bool
isIsolate cp = cp >= 0x2066 && cp <= 0x2069

-- | Detect a confusable codepoint sharing the input with a bidi control.
-- Priority mirrors the spec: with a confusable present, an override-class
-- control fires @ConfusableInOverride@; otherwise an isolate-class control
-- fires @ConfusableInIsolate@; otherwise clear. Positions are
-- @[confusablePos, bidiPos]@.
confusableBidiCompoundFinding :: [Int] -> [Finding]
confusableBidiCompoundFinding input =
  case firstPos isConfusableSource input of
    Nothing -> []
    Just confusablePos ->
      case firstPos isOverride input of
        Just bidiPos -> [makeFinding "ConfusableInOverride" [confusablePos, bidiPos]]
        Nothing ->
          case firstPos isIsolate input of
            Just bidiPos -> [makeFinding "ConfusableInIsolate" [confusablePos, bidiPos]]
            Nothing -> []
  where
    makeFinding :: String -> [Int] -> Finding
    makeFinding subThreat positions =
      Finding
        { findingCode = reasonCode FamilyConfusableBidiCompound subThreat
        , findingFamily = FamilyConfusableBidiCompound
        , findingSeverity = 2
        , findingPositions = positions
        , findingSubThreat = subThreat
        , findingDetail = familyTag FamilyConfusableBidiCompound
        }

-- | First input position whose codepoint satisfies the predicate.
firstPos :: (Int -> Bool) -> [Int] -> Maybe Int
firstPos predicate input =
  listToMaybe [ index | (index, cp) <- zip [0 ..] input, predicate cp ]

-- ─────────────────────────────────────────────────────────────────────
-- Covert-display compound (boundary layer, reason-code letter "X").
--
-- Direct port of @Unicode/Security/Boundary/CovertDisplayCompound.lean@.
-- A bidi format-control that reorders the visible glyphs is materially
-- more dangerous when the same input also carries a covert channel — an
-- unregistered variation selector or a tag-block character — because the
-- reorder hides where the covert payload sits. This detector fires only
-- when a bidi control coincides with one of those covert classes,
-- reusing 'isBidiFormatControl', 'isVariationSelector', and
-- 'isRegisteredVariationPosition'.
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@ is in the tag-block range U+E0000..U+E007F.
isTagBlockChar :: Int -> Bool
isTagBlockChar cp = cp >= 0xE0000 && cp <= 0xE007F

-- | First input position holding a suspicious variation selector — a VS
-- that does not form a registered (base, VS) pair with its predecessor.
-- Mirrors the @.suspicious@ case of the Lean @classifyPositions@.
firstSuspiciousVsPos :: [Int] -> Maybe Int
firstSuspiciousVsPos input =
  listToMaybe
    [ index
    | (index, cp) <- zip [0 ..] input
    , isVariationSelector cp
    , not (isRegisteredVariationPosition input index)
    ]

-- | Detect a bidi control co-located with a covert channel. Priority
-- mirrors the spec: a bidi format-control must be present; then a
-- suspicious VS fires @BidiPlusUnregisteredVs@; otherwise a tag-block
-- character fires @BidiPlusTagBlock@; otherwise clear. Positions are
-- @[bidiPos, covertPos]@.
covertDisplayCompoundFinding :: [Int] -> [Finding]
covertDisplayCompoundFinding input =
  case firstPos isBidiFormatControl input of
    Nothing -> []
    Just bidiPos ->
      case firstSuspiciousVsPos input of
        Just vsPos -> [makeFinding "BidiPlusUnregisteredVs" [bidiPos, vsPos]]
        Nothing ->
          case firstPos isTagBlockChar input of
            Just tagPos -> [makeFinding "BidiPlusTagBlock" [bidiPos, tagPos]]
            Nothing -> []
  where
    makeFinding :: String -> [Int] -> Finding
    makeFinding subThreat positions =
      Finding
        { findingCode = reasonCode FamilyCovertDisplayCompound subThreat
        , findingFamily = FamilyCovertDisplayCompound
        , findingSeverity = 2
        , findingPositions = positions
        , findingSubThreat = subThreat
        , findingDetail = familyTag FamilyCovertDisplayCompound
        }

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
layer FamilySurrogateReassembly = "C"
layer FamilyBidiControlBalance = "C"
layer FamilyNoncharacterControl = "C"
layer FamilyHomoglyphConfusable = "I"
layer FamilyMixedScriptAdmissibility = "I"
layer FamilyRtlInjection = "D"
layer FamilyConfusableBidiCompound = "X"
layer FamilyCovertDisplayCompound = "X"
layer FamilyEmojiZwjIntegrity = "I"
layer FamilySkinToneVariationForgery = "I"
layer FamilyFilenameDisguise = "D"
layer FamilyRendererDivergence = "D"
layer FamilySourceDisplayDivergence = "D"
layer FamilyStreamSafeViolation = "F"
layer FamilyCaseExpansionMismatch = "F"
layer FamilyNormalizationBomb = "F"
layer FamilyLocaleCaseInversion = "F"
layer FamilyNfcIdempotenceWitness = "F"
layer FamilyWidthClassConfusion = "F"
layer FamilyIdentifierFormDrift = "X"
layer FamilyAdmissibilityFormDrift = "X"
layer FamilyBip39Canonical = "K"
layer FamilyHashInputStability = "K"
layer FamilyAiWatermarkDetectability = "K"

utf8RejectTag :: Utf8RejectKind -> String
utf8RejectTag InvalidStartByte = "InvalidStartByte"
utf8RejectTag TruncatedSequence = "TruncatedSequence"
utf8RejectTag OverlongEncoding = "OverlongEncoding"
utf8RejectTag SurrogateCodepoint = "SurrogateCodepoint"
utf8RejectTag CodepointBeyondMax = "CodepointBeyondMax"
utf8RejectTag InvalidContinuationByte = "InvalidContinuationByte"
