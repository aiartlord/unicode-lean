/-
  Unicode.Security.Policy

  Product-facing runtime policy layer over the Security Conformance detectors.
  This module turns per-family detector output into profile-aware decisions with
  stable reason codes. It is part of the runtime `Unicode` root and must not
  import assurance or full-conformance modules.
-/

import Unicode.Security.RunAll
import Unicode.Security.Level

namespace Unicode.Security.Policy

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- Runtime decision vocabulary
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Action the policy engine recommends for the current payload. -/
inductive Action where
  | allow
  | reject
  | quarantine
  | rewrite
  | observe
  deriving DecidableEq, Repr, Inhabited

/-- Runtime mode selected by the operator. -/
inductive Mode where
  | observe
  | warn
  | enforce
  | strict
  deriving DecidableEq, Repr, Inhabited

/-- Context profile. Unicode security is profile-dependent: the same codepoint
    can be acceptable in one context and dangerous in another. -/
inductive Profile where
  | gatewayHeader
  | domainName
  | dnsLabel
  | url
  | username
  | displayName
  | chatMessage
  | sourceCode
  | opaqueSecret
  | binaryBlob
  deriving DecidableEq, Repr, Inhabited

/-- Stable, product-facing finding. `code` is the externally visible reason
    code; `family` remains typed so downstream Lean callers can pattern-match
    without parsing strings. -/
structure Finding where
  code      : String
  family    : Family
  severity  : Severity
  positions : List Nat
  subThreat : Option String
  detail    : String
  deriving Repr, Inhabited

/-- Runtime verdict returned by `scan`. -/
structure Verdict where
  input       : List Nat
  profile     : Profile
  mode        : Mode
  action      : Action
  findings    : List Finding
  normalized? : Option (List Nat)
  deriving Repr, Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- Stable names and reason-code namespaces
-- ═══════════════════════════════════════════════════════════════════════════════

namespace Profile

def tag : Profile → String
  | .gatewayHeader => "gateway-header"
  | .domainName    => "domain-name"
  | .dnsLabel      => "dns-label"
  | .url           => "url"
  | .username      => "username"
  | .displayName   => "display-name"
  | .chatMessage   => "chat-message"
  | .sourceCode    => "source-code"
  | .opaqueSecret  => "opaque-secret"
  | .binaryBlob    => "binary-blob"

end Profile

namespace Mode

def tag : Mode → String
  | .observe => "observe"
  | .warn    => "warn"
  | .enforce => "enforce"
  | .strict  => "strict"

end Mode

namespace Action

def tag : Action → String
  | .allow      => "allow"
  | .reject     => "reject"
  | .quarantine => "quarantine"
  | .rewrite    => "rewrite"
  | .observe    => "observe"

end Action

namespace Family

/-- Stable short layer code used in reason codes. -/
def layerCode : Family → String
  | .tagBlockPayload
  | .variationSelectorPayload
  | .zeroWidthPayload
  | .surrogateReassembly
  | .noncharacterControl
  | .bidiControlBalance       => "C"
  | .homoglyphConfusable
  | .mixedScriptAdmissibility
  | .emojiZwjIntegrity
  | .skinToneVariationForgery => "I"
  | .sourceDisplayDivergence
  | .filenameDisguise
  | .rtlInjection
  | .rendererDivergence       => "D"
  | .normalizationBomb
  | .streamSafeViolation
  | .localeCaseInversion
  | .caseExpansionMismatch
  | .widthClassConfusion
  | .nfcIdempotenceWitness    => "F"
  | .identifierFormDrift
  | .covertDisplayCompound
  | .confusableBidiCompound
  | .admissibilityFormDrift   => "X"
  | .bip39Canonical
  | .hashInputStability
  | .aiWatermarkDetectability => "K"

/-- Stable family slug used in reason codes. -/
def slug : Family → String
  | .tagBlockPayload          => "tag-block-payload"
  | .variationSelectorPayload => "variation-selector-payload"
  | .zeroWidthPayload         => "zero-width-payload"
  | .surrogateReassembly      => "surrogate-reassembly"
  | .noncharacterControl      => "noncharacter-control"
  | .bidiControlBalance       => "bidi-control-balance"
  | .homoglyphConfusable      => "homoglyph-confusable"
  | .mixedScriptAdmissibility => "mixed-script-admissibility"
  | .emojiZwjIntegrity        => "emoji-zwj-integrity"
  | .skinToneVariationForgery => "skin-tone-variation-forgery"
  | .sourceDisplayDivergence  => "source-display-divergence"
  | .filenameDisguise         => "filename-disguise"
  | .rtlInjection             => "rtl-injection"
  | .rendererDivergence       => "renderer-divergence"
  | .normalizationBomb        => "normalization-bomb"
  | .streamSafeViolation      => "stream-safe-violation"
  | .localeCaseInversion      => "locale-case-inversion"
  | .caseExpansionMismatch    => "case-expansion-mismatch"
  | .widthClassConfusion      => "width-class-confusion"
  | .nfcIdempotenceWitness    => "nfc-idempotence-witness"
  | .identifierFormDrift      => "identifier-form-drift"
  | .covertDisplayCompound    => "covert-display-compound"
  | .confusableBidiCompound   => "confusable-bidi-compound"
  | .admissibilityFormDrift   => "admissibility-form-drift"
  | .bip39Canonical           => "bip39-canonical"
  | .hashInputStability       => "hash-input-stability"
  | .aiWatermarkDetectability => "ai-watermark-detectability"

/-- Stable reason-code base for a detector family. -/
def reasonBase (family : Family) : String :=
  "unicode.security." ++ Family.layerCode family ++ "." ++ Family.slug family

end Family

/-- Stable reason code for a detector result. -/
def reasonCode (family : Family) (subThreat : Option String) : String :=
  match subThreat with
  | none     => Family.reasonBase family ++ ".hazard"
  | some tag => Family.reasonBase family ++ "." ++ tag

-- ═══════════════════════════════════════════════════════════════════════════════
-- Profile configuration
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Runtime policy parameters derived from a named profile. -/
structure ProfilePolicy where
  level         : Unicode.Security.Level.Level
  cryptoContext : Unicode.Security.Level.CryptoContext
  quarantine    : Bool
  deriving Repr, Inhabited

/-- Default policy for each profile. This is the product-level starting point;
    callers can later get an explicit configuration surface if they need custom
    policy. -/
def policyOfProfile : Profile → ProfilePolicy
  | .gatewayHeader => ⟨.restrictive, .nonCrypto, false⟩
  | .domainName    => ⟨.restrictive, .nonCrypto, false⟩
  | .dnsLabel      => ⟨.restrictive, .nonCrypto, false⟩
  | .url           => ⟨.moderate,    .nonCrypto, false⟩
  | .username      => ⟨.moderate,    .nonCrypto, true⟩
  | .displayName   => ⟨.minimal,     .nonCrypto, true⟩
  | .chatMessage   => ⟨.minimal,     .nonCrypto, true⟩
  | .sourceCode    => ⟨.restrictive, .nonCrypto, false⟩
  | .opaqueSecret  => ⟨.minimal,     .hashInput, false⟩
  | .binaryBlob    => ⟨.minimal,     .nonCrypto, false⟩

/-- Families whose hazards are admission-relevant under a profile. All detector
    findings remain reportable; this set only drives `Action` selection. -/
def effectiveRejectionSet (profile : Profile) : List Family :=
  let p := policyOfProfile profile
  Unicode.Security.Level.rejectionSet p.level ++ p.cryptoContext.toFamilies

def familyAdmissionRelevant (profile : Profile) (family : Family) : Bool :=
  (effectiveRejectionSet profile).contains family

def findingAdmissionRelevant (profile : Profile) (finding : Finding) : Bool :=
  familyAdmissionRelevant profile finding.family

-- ═══════════════════════════════════════════════════════════════════════════════
-- Scan result conversion and action selection
-- ═══════════════════════════════════════════════════════════════════════════════

def resultToFinding? (r : Unicode.Security.RunAll.FamilyResult) : Option Finding :=
  match r.classification with
  | .clear => none
  | .informational =>
      some {
        code      := reasonCode r.family r.subThreat,
        family    := r.family,
        severity  := ClassificationKind.informational.defaultSeverity,
        positions := r.positions,
        subThreat := r.subThreat,
        detail    := Family.slug r.family
      }
  | .hazard =>
      some {
        code      := reasonCode r.family r.subThreat,
        family    := r.family,
        severity  := ClassificationKind.hazard.defaultSeverity,
        positions := r.positions,
        subThreat := r.subThreat,
        detail    := Family.slug r.family
      }
  | .compound =>
      let sub := r.subThreat
      some {
        code      := reasonCode r.family sub,
        family    := r.family,
        severity  := ClassificationKind.compound.defaultSeverity,
        positions := r.positions,
        subThreat := sub,
        detail    := Family.slug r.family
      }

def findingsOfResults (results : List Unicode.Security.RunAll.FamilyResult) : List Finding :=
  results.foldl
    (fun acc r =>
      match resultToFinding? r with
      | none   => acc
      | some f => acc ++ [f])
    []

def blockingFindings (profile : Profile) (findings : List Finding) :
    List Finding :=
  findings.filter (findingAdmissionRelevant profile)

def actionForBlocking (profile : Profile) : Action :=
  if (policyOfProfile profile).quarantine then .quarantine else .reject

def selectAction (profile : Profile) (mode : Mode)
    (findings : List Finding) : Action :=
  let blocking := blockingFindings profile findings
  match mode with
  | .observe =>
      if findings.isEmpty then .allow else .observe
  | .warn =>
      if findings.isEmpty then .allow else .observe
  | .enforce =>
      if blocking.isEmpty then .allow else actionForBlocking profile
  | .strict =>
      if findings.isEmpty then .allow else .reject

/-- Runtime scan over a codepoint array. Byte decoding and wire-format framing
    belong one layer above this function; this is the profile/policy decision
    over already-decoded codepoints. -/
def scan (profile : Profile) (mode : Mode) (input : List Nat) : Verdict :=
  let results := Unicode.Security.RunAll.runAll input
  let findings := findingsOfResults results
  {
    input       := input,
    profile     := profile,
    mode        := mode,
    action      := selectAction profile mode findings,
    findings    := findings,
    normalized? := none
  }

def scanDefault (profile : Profile) (input : List Nat) : Verdict :=
  scan profile .enforce input

/-- Runtime admission predicate derived from `scan`. -/
def admits (profile : Profile) (mode : Mode) (input : List Nat) : Bool :=
  match (scan profile mode input).action with
  | .allow => true
  | .observe => true
  | .rewrite => true
  | .reject => false
  | .quarantine => false

end Unicode.Security.Policy
