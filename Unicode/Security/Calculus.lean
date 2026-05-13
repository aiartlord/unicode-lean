/-
  Unicode.Security.Calculus

  Foundation types for the Security Conformance Layer. Every per-family
  module (Unicode.Security.{Covert,Identity,Display,Form,Boundary,Crypto}.*)
  imports this module and refines the shared vocabulary into a family-
  specific verdict structure.

  The calculus follows the precedent set by `Unicode.Invariants` (refinement-
  type predicates) and `Unicode.Codec.Strict` (inductive rejection vocabulary,
  parametric strict-result monad). Per-family verdicts mirror the
  `RejectReason` / `StrictParseResult` shape but specialize to the family's
  threat model.

  ## What this file defines

    * `Family`            — enumeration of the 26 fixture families
    * `Layer`             — six-layer grouping over `Family`
    * `Severity`          — ordered severity vocabulary
    * `AdversaryTier`     — five-tier adversary capability hierarchy
    * `ClassificationKind` — verdict shape sans family-specific payload
    * `ConformanceLevel`  — Basic / Strict / Full conformance tiers
    * `HazardPosition`    — line/column attribution for source-shaped inputs
    * `KeyValueAttribution` — flexible attribution dictionary

  ## What this file does NOT define

  Family-specific classification inductives, sub-threat enumerations, and
  detection algorithms — those live in each family's own module. The calculus
  is the *vocabulary*, not the *content*.
-/

namespace Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Family enumeration
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Enumeration of the 26 fixture families across six layers. Layer
    membership is given by `Layer.of` below. Each family is a separate
    sub-project; this enum gives them a single shared name. -/
inductive Family where
  -- Layer 1 — Covert Channels
  | tagBlockPayload
  | variationSelectorPayload    -- GlassWorm class
  | zeroWidthPayload
  | surrogateReassembly         -- byte-stream bypass
  | bidiControlBalance
  -- Layer 2 — Identity Spoofing
  | homoglyphConfusable         -- Nethereum class
  | mixedScriptAdmissibility
  | emojiZwjIntegrity
  | skinToneVariationForgery
  -- Layer 3 — Display Integrity
  | sourceDisplayDivergence
  | filenameDisguise
  | rtlInjection
  | rendererDivergence
  -- Layer 4 — Form Stability
  | normalizationBomb
  | streamSafeViolation
  | localeCaseInversion
  | caseExpansionMismatch
  | widthClassConfusion
  | nfcIdempotenceWitness
  -- Layer 5 — Cross-Layer Boundaries
  | identifierFormDrift
  | covertDisplayCompound
  | confusableBidiCompound
  | admissibilityFormDrift
  -- Layer 6 — Cryptographic Stability
  | bip39Canonical
  | hashInputStability
  | aiWatermarkDetectability
  deriving DecidableEq, Repr, Inhabited

/-- Six-layer grouping over the 26 families. -/
inductive Layer where
  | covert        -- L1: TagBlockPayload .. BidiControlBalance (5)
  | identity      -- L2: HomoglyphConfusable .. SkinToneVariationForgery (4)
  | display       -- L3: SourceDisplayDivergence .. RendererDivergence (4)
  | form          -- L4: NormalizationBomb .. NfcIdempotenceWitness (6)
  | boundary      -- L5: IdentifierFormDrift .. AdmissibilityFormDrift (4)
  | crypto        -- L6: Bip39Canonical .. AiWatermarkDetectability (3)
  deriving DecidableEq, Repr, Inhabited

namespace Layer

/-- The layer a family belongs to. Total function. -/
def of : Family → Layer
  | .tagBlockPayload | .variationSelectorPayload | .zeroWidthPayload
  | .surrogateReassembly | .bidiControlBalance
    => .covert
  | .homoglyphConfusable | .mixedScriptAdmissibility
  | .emojiZwjIntegrity | .skinToneVariationForgery
    => .identity
  | .sourceDisplayDivergence | .filenameDisguise
  | .rtlInjection | .rendererDivergence
    => .display
  | .normalizationBomb | .streamSafeViolation | .localeCaseInversion
  | .caseExpansionMismatch | .widthClassConfusion
  | .nfcIdempotenceWitness
    => .form
  | .identifierFormDrift | .covertDisplayCompound
  | .confusableBidiCompound | .admissibilityFormDrift
    => .boundary
  | .bip39Canonical | .hashInputStability | .aiWatermarkDetectability
    => .crypto

end Layer

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Severity, adversary tier, conformance level
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Ordered severity vocabulary. Strictly less-than: `informational <
    low < moderate < high < critical`. -/
inductive Severity where
  | informational
  | low
  | moderate
  | high
  | critical
  deriving DecidableEq, Repr, Inhabited

namespace Severity

/-- Severity as a natural number for ordering. -/
def toNat : Severity → Nat
  | .informational => 0
  | .low           => 1
  | .moderate      => 2
  | .high          => 3
  | .critical      => 4

/-- Total ordering induced by `toNat`. -/
instance : LE Severity := ⟨fun a b => a.toNat ≤ b.toNat⟩
instance : LT Severity := ⟨fun a b => a.toNat < b.toNat⟩

/-- Pointwise max over severities (lattice join). -/
def max : Severity → Severity → Severity
  | a, b => if a.toNat ≥ b.toNat then a else b

/-- Pointwise min over severities (lattice meet). -/
def min : Severity → Severity → Severity
  | a, b => if a.toNat ≤ b.toNat then a else b

end Severity

/-- Five-tier adversary capability hierarchy per the calculus §4.
    A tier-N adversary has all capabilities of tier (N-1) plus the
    tier-N-specific additions. -/
inductive AdversaryTier where
  | A0  -- Passive observer (read-only public outputs)
  | A1  -- Local injector (single-input attack)
  | A2  -- Pipeline injector (browser → API → DB → AI)
  | A3  -- Supply-chain injector (registers a package/identifier)
  | A4  -- Model-adaptive (tokenizer-query capable)
  deriving DecidableEq, Repr, Inhabited

namespace AdversaryTier

/-- Tier as a natural number. -/
def toNat : AdversaryTier → Nat
  | .A0 => 0
  | .A1 => 1
  | .A2 => 2
  | .A3 => 3
  | .A4 => 4

instance : LE AdversaryTier := ⟨fun a b => a.toNat ≤ b.toNat⟩
instance : LT AdversaryTier := ⟨fun a b => a.toNat < b.toNat⟩

end AdversaryTier

/-- Conformance level for a per-family fixture row. Higher levels include
    everything below. -/
inductive ConformanceLevel where
  | basic   -- Level 1: in-the-wild attacks at fixture-authorship time
  | strict  -- Level 2: theorized but not-yet-observed within threat model
  | full    -- Level 3: research-grade adversarial edge cases
  deriving DecidableEq, Repr, Inhabited

namespace ConformanceLevel

def toNat : ConformanceLevel → Nat
  | .basic  => 1
  | .strict => 2
  | .full   => 3

instance : LE ConformanceLevel := ⟨fun a b => a.toNat ≤ b.toNat⟩
instance : LT ConformanceLevel := ⟨fun a b => a.toNat < b.toNat⟩

end ConformanceLevel

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Classification kind (verdict shape, sans family payload)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The verdict kind, independent of any family-specific sub-threat payload.
    Family modules define their own `<F>Classification` inductives carrying
    sub-threat data; this enum is the shape they all share. -/
inductive ClassificationKind where
  | clear                           -- input passes the family's predicate
  | hazard                          -- single-sub-threat hazard
  | compound                        -- multiple sub-threats fired
  | informational                   -- advisory / report-only (e.g. IdentifierFormDrift)
  deriving DecidableEq, Repr, Inhabited

namespace ClassificationKind

/-- The default severity associated with each classification kind.
    Families can override at the verdict level. -/
def defaultSeverity : ClassificationKind → Severity
  | .clear         => .informational
  | .hazard        => .moderate
  | .compound      => .high
  | .informational => .informational

end ClassificationKind

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Hazard-site attribution
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A position within a codepoint sequence, optionally enriched with a
    line / column when the input is source-code shaped. -/
structure HazardPosition where
  cpOffset : Nat                    -- 0-indexed codepoint position
  line     : Option Nat             -- 1-indexed line (for source-code inputs)
  column   : Option Nat             -- 1-indexed column
  deriving DecidableEq, Repr, Inhabited

/-- A flexible attribution dictionary — string keys to string values.
    Each family defines its own attribution schema; this is the shared
    container. Used in fixture rows' column 4. -/
structure KeyValueAttribution where
  entries : List (String × String)
  deriving Repr, Inhabited

namespace KeyValueAttribution

/-- Empty attribution. -/
def empty : KeyValueAttribution := ⟨[]⟩

/-- Look up a key. Returns the first match (linear scan; attribution maps
    are small per row). -/
def get? (kv : KeyValueAttribution) (key : String) : Option String :=
  kv.entries.find? (·.1 = key) |>.map (·.2)

/-- Add a key-value pair. -/
def push (kv : KeyValueAttribution) (key value : String) : KeyValueAttribution :=
  ⟨kv.entries ++ [(key, value)]⟩

/-- Validate a `Nat`-valued attribution key against an actual
    value.  Missing key passes leniently (the fixture row didn't
    pin this field).  Present-but-malformed key fails (the
    fixture claims a value the parser can't read as `Nat`).
    Present and well-formed: equality with `actual`. -/
@[inline]
def checkNatKey (kv : KeyValueAttribution) (key : String) (actual : Nat) : Bool :=
  match kv.get? key with
  | none      => true
  | some raw  =>
    match raw.toNat? with
    | some expected => decide (actual = expected)
    | none          => Function.const String false raw

/-- Validate a `String`-valued attribution key against an actual
    value.  Same lenient-on-missing, strict-on-present semantics
    as `checkNatKey`. -/
@[inline]
def checkStringKey (kv : KeyValueAttribution) (key : String) (actual : String) :
    Bool :=
  match kv.get? key with
  | none           => true
  | some expected  => decide (actual = expected)

/-- Validate a `Bool`-valued attribution key.  The fixture writes
    the literal strings `true` / `false`; any other value present
    is a parse error and fails the check.  Missing key passes. -/
@[inline]
def checkBoolKey (kv : KeyValueAttribution) (key : String) (actual : Bool) :
    Bool :=
  match kv.get? key with
  | none      => true
  | some raw  =>
    match raw with
    | "true"  => actual
    | "false" => !actual
    | other   => Function.const String false other

end KeyValueAttribution

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks (sanity for the deriving instances)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every family belongs to exactly one layer; layer assignment is total. -/
theorem layer_of_tagBlockPayload :
    Layer.of .tagBlockPayload = .covert := rfl
theorem layer_of_homoglyphConfusable :
    Layer.of .homoglyphConfusable = .identity := rfl
theorem layer_of_sourceDisplayDivergence :
    Layer.of .sourceDisplayDivergence = .display := rfl
theorem layer_of_normalizationBomb :
    Layer.of .normalizationBomb = .form := rfl
theorem layer_of_identifierFormDrift :
    Layer.of .identifierFormDrift = .boundary := rfl
theorem layer_of_bip39Canonical :
    Layer.of .bip39Canonical = .crypto := rfl

/-- Severity ordering is well-defined. -/
theorem severity_informational_lt_critical :
    Severity.informational.toNat < Severity.critical.toNat := by decide

/-- Adversary tier ordering is well-defined. -/
theorem adversary_A0_lt_A4 :
    AdversaryTier.A0.toNat < AdversaryTier.A4.toNat := by decide

/-- Conformance level ordering: basic < strict < full. -/
theorem conformance_basic_lt_full :
    ConformanceLevel.basic.toNat < ConformanceLevel.full.toNat := by decide

/-- Severity.max is idempotent. -/
theorem severity_max_idempotent (s : Severity) : s.max s = s := by
  cases s <;> rfl

/-- Severity.min ≤ Severity.max pointwise. -/
theorem severity_min_le_max (a b : Severity) :
    (a.min b).toNat ≤ (a.max b).toNat := by
  cases a <;> cases b <;> decide

/-- Empty key-value attribution lookups return none. -/
theorem kv_empty_get : KeyValueAttribution.empty.get? "any" = none := rfl

/-- Push-then-get returns the value. -/
theorem kv_push_get :
    (KeyValueAttribution.empty.push "k" "v").get? "k" = some "v" := rfl

end Unicode.Security.Calculus
