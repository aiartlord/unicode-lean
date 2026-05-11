/-
  Unicode.Security.Display.SourceDisplayDivergence

  D1 — Detection of source-code-context attacks where the bytes a
  compiler executes diverge from what a human reviewer sees on
  screen.  Compound detector that composes the codepoint-level
  Layer-1 covert-channel detectors (C1 tag-block, C2 variation-
  selector, C3 zero-width, C5 bidi-balance) with the
  Layer-2 identity detector (I1 homoglyph).

  Threat model.  Tier A₂ (pipeline injector) / A₃ (supply-chain
  injector).  Adversary commits source code whose visible glyph
  stream looks innocuous (or matches an honest reference) but
  whose byte stream contains an embedded payload, a reordering
  control, an invisible operator, or a homoglyph identifier
  substitution.  Real-world adversaries combine: bidi-balanced +
  VS-payload + homoglyph-identifier in one file.

  Scope.

    * v1 was language-agnostic: the whole codepoint sequence
      was treated as one stream.  v1.5 adds an optional
      `Language` parameter that dispatches to
      `Unicode.Security.Display.SourceCodeTokenize` to partition
      the stream into code / string-literal / line-comment /
      block-comment regions.  Sub-detector firing is then scoped
      to the regions where each hazard class is meaningful —
      bidi controls inside a string literal are data, not display
      deception; an unregistered VS inside a `// comment` is a
      documentation choice, not a payload.  Two grammars ship in
      v1.5: `cStyleGeneric` (covers C / C++ / Java / Go / JS / TS
      / Kotlin / Swift / C# at first approximation) and `rust`
      (cStyleGeneric plus nestable block comments and raw
      strings).  `Language.none` retains the v1 language-agnostic
      behaviour and is the default, so callers that did not pass
      a language continue to receive the v1 verdict.

    * C4 (byte-level surrogate-reassembly / UTF-8 anomaly) is NOT
      composed here — by the time the byte stream has been
      decoded to a codepoint sequence, the C4 check has already
      happened (or should have).  C4 must be run on the *byte*
      stream BEFORE this detector.

  Compound classification rule.

    * No sub-detector fires    → `.clear`.
    * Exactly one fires         → `.hazard` with the single-family
                                  sub-threat passed through.
    * Two or more fire         → `.compound` with the constituent
                                  family tags collected.
-/

import Unicode.Security.Calculus
import Unicode.Security.Covert.TagBlockPayload
import Unicode.Security.Covert.VariationSelectorPayload
import Unicode.Security.Covert.ZeroWidthPayload
import Unicode.Security.Covert.BidiControlBalance
import Unicode.Security.Identity.HomoglyphConfusable
import Unicode.Security.Display.SourceCodeTokenize

namespace Unicode.Security.Display.SourceDisplayDivergence

open Unicode.Security.Calculus
open Unicode.Security.Display.SourceCodeTokenize (Language positionInCode)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- D1 sub-threats — one per constituent family plus a `compound`
    variant for the multi-mechanism attack class. -/
inductive D1SubThreat where
  | tagBlock            (innerTag : String)
  | variationSelector   (innerTag : String)
  | zeroWidth           (innerTag : String)
  | bidiControl         (innerTag : String)
  | identifierHomoglyph (innerTag : String)
  | compound            (constituents : Array String)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for D1. -/
inductive D1Classification where
  | clear
  | hazard (sub : D1SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

/-- D1 verdict — carries all five sub-detector verdicts so a
    reviewer can drill into any specific family if interested. -/
structure D1Verdict where
  input              : Array Nat
  classify           : D1Classification
  c1Tag              : Option String        -- TagBlockPayload
  c2Tag              : Option String        -- VariationSelectorPayload
  c3Tag              : Option String        -- ZeroWidthPayload
  c5Tag              : Option String        -- BidiControlBalance
  i1Tag              : Option String        -- HomoglyphConfusable
  firedFamilies      : Array String         -- non-clear family names
  safeForReview      : Bool
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Sub-verdict aggregation
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Compose the five constituent verdicts into a single D1 verdict.
    The single-fire case threads the inner sub-threat tag through
    so a downstream reviewer can see *which* family fired without
    cross-referencing the per-family verdicts. -/
private def buildClassification
    (c1Tag c2Tag c3Tag c5Tag i1Tag : Option String) : D1Classification :=
  let fires : Array (String × String) :=
    #[("C1", c1Tag.getD ""), ("C2", c2Tag.getD ""), ("C3", c3Tag.getD ""),
      ("C5", c5Tag.getD ""), ("I1", i1Tag.getD "")]
    |>.filter (fun pair => pair.2 ≠ "")
  match fires.size with
  | 0 => .clear
  | 1 =>
    let pair := fires[0]!
    let sub : D1SubThreat := match pair.1 with
      | "C1" => .tagBlock pair.2
      | "C2" => .variationSelector pair.2
      | "C3" => .zeroWidth pair.2
      | "C5" => .bidiControl pair.2
      | "I1" => .identifierHomoglyph pair.2
      | other => Function.const String (.compound #[other]) other
    .hazard sub #[] ByteArray.empty
  | _ =>
    .hazard (.compound (fires.map (fun pair => pair.1))) #[] ByteArray.empty

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The D1 detection function.  Runs all five constituent
    detectors on the same codepoint stream, scopes their hits to
    code regions under `lang`, and aggregates the results into a
    compound verdict.

    `lang` defaults to `Language.none`, which treats the whole
    input as one code region — equivalent to the v1
    language-agnostic behaviour.  Callers passing
    `Language.cStyleGeneric` or `Language.rust` get region-aware
    filtering: a sub-detector that fires only at positions
    inside string literals, line comments, or block comments
    does not contribute to the D1 verdict because the hit is
    data or documentation, not display deception in code. -/
def detect (input : Array Nat) (lang : Language := .none) : D1Verdict :=
  let c1 := Unicode.Security.Covert.TagBlockPayload.detect input
  let c2 := Unicode.Security.Covert.VariationSelectorPayload.detect input
  let c3 := Unicode.Security.Covert.ZeroWidthPayload.detect input
  let c5 := Unicode.Security.Covert.BidiControlBalance.detect input
  let i1 := Unicode.Security.Identity.HomoglyphConfusable.detect input
  let inCode (p : Nat) : Bool := positionInCode lang input p
  let firesIfInCode (tag : Option String) (positions : Array Nat) :
      Option String :=
    match tag with
    | none      => none
    | some hit  =>
      if positions.isEmpty ∨ positions.any inCode then some hit else none
  let c1Tag := firesIfInCode c1.classify.tag c1.classify.positions
  let c2Tag := firesIfInCode c2.classify.tag c2.classify.positions
  let c3Tag := firesIfInCode c3.classify.tag c3.classify.positions
  let c5Tag := firesIfInCode c5.classify.tag c5.classify.positions
  let i1Tag := firesIfInCode i1.classify.tag i1.classify.positions
  let classify := buildClassification c1Tag c2Tag c3Tag c5Tag i1Tag
  let firedFamilies : Array String :=
    #[("C1", c1Tag), ("C2", c2Tag), ("C3", c3Tag),
      ("C5", c5Tag), ("I1", i1Tag)]
    |>.filterMap (fun pair => match pair.2 with
                              | some hit  => Function.const String (some pair.1) hit
                              | none      => none)
  { input := input,
    classify := classify,
    c1Tag := c1Tag, c2Tag := c2Tag, c3Tag := c3Tag,
    c5Tag := c5Tag, i1Tag := i1Tag,
    firedFamilies := firedFamilies,
    safeForReview := firedFamilies.isEmpty }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `D1SubThreat` constructor. -/
def D1SubThreat.tag : D1SubThreat → String
  | .tagBlock            innerTag      =>
      Function.const String "TagBlock" innerTag
  | .variationSelector   innerTag      =>
      Function.const String "VariationSelector" innerTag
  | .zeroWidth           innerTag      =>
      Function.const String "ZeroWidth" innerTag
  | .bidiControl         innerTag      =>
      Function.const String "BidiControl" innerTag
  | .identifierHomoglyph innerTag      =>
      Function.const String "IdentifierHomoglyph" innerTag
  | .compound            constituents  =>
      Function.const (Array String) "Compound" constituents

/-- True iff the classification is `.clear`. -/
def D1Classification.isClear : D1Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (D1SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def D1Classification.tag : D1Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def D1Classification.positions : D1Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (D1SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear (every sub-detector clears). -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII "Hello world" is clear. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64]).classify.isClear
      = true := by native_decide

/-- A pure-C1 attack — tag-encoded "AB" — fires `.tagBlock`. -/
theorem detect_tag_only :
    (detect #[0xE0041, 0xE0042]).classify.tag = some "TagBlock" := by
  native_decide

/-- A pure-C2 attack — Latin A + VS16 — fires `.variationSelector`. -/
theorem detect_vs_only :
    (detect #[0x0041, 0xFE0F]).classify.tag = some "VariationSelector" := by
  native_decide

/-- A pure-C3 attack — Latin H + ZWSP + i — fires `.zeroWidth`. -/
theorem detect_zw_only :
    (detect #[0x0048, 0x200B, 0x69]).classify.tag = some "ZeroWidth" := by
  native_decide

/-- A pure-C5 attack — lone RLO — fires `.bidiControl`. -/
theorem detect_bidi_only :
    (detect #[0x202E, 0x41]).classify.tag = some "BidiControl" := by
  native_decide

/-- A pure-I1 attack — Nethereum typosquat — fires `.identifierHomoglyph`. -/
theorem detect_homoglyph_only :
    (detect #[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]).classify.tag
      = some "IdentifierHomoglyph" := by native_decide

/-- A compound attack — Latin A + VS16 + ZWSP — fires `.compound`. -/
theorem detect_compound_vs_plus_zw :
    (detect #[0x0041, 0xFE0F, 0x200B]).classify.tag = some "Compound" := by
  native_decide

/-- Tag + zero-width — also `.compound`. -/
theorem detect_compound_tag_plus_zw :
    (detect #[0xE0041, 0xE0042, 0x200B]).classify.tag = some "Compound" := by
  native_decide

/-- A clean code snippet "let x = 1;" is clear. -/
theorem detect_clean_code :
    (detect #[0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B]).classify.isClear
      = true := by native_decide

/-- `safeForReview` mirrors `isClear`. -/
theorem safeForReview_matches_clear_empty :
    (detect #[]).safeForReview = true := by native_decide

theorem safeForReview_matches_hazard_VS :
    (detect #[0x0041, 0xFE0F]).safeForReview = false := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 v1.5 region-aware spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A VS attached to a Latin letter inside a Rust string literal
    fires D1 under `Language.none` (whole input is code) but
    clears under `Language.rust` (the VS position is inside a
    string region, so the C2 hit is filtered out). -/
theorem detect_vs_inside_rust_string_clear :
    (detect #[0x22, 0x41, 0xFE00, 0x22] .rust).classify.isClear = true := by
  native_decide

theorem detect_vs_inside_string_under_none_fires :
    (detect #[0x22, 0x41, 0xFE00, 0x22] .none).classify.tag
      = some "VariationSelector" := by native_decide

/-- The same VS attached to a Latin letter immediately AFTER the
    closing quote sits in a code region under Rust, so D1 still
    fires. -/
theorem detect_vs_after_rust_string_fires :
    (detect #[0x22, 0x41, 0x22, 0xFE00] .rust).classify.tag
      = some "VariationSelector" := by native_decide

/-- Bidi control inside a Rust line comment clears under
    `Language.rust`. -/
theorem detect_rlo_inside_rust_line_comment_clear :
    (detect #[0x2F, 0x2F, 0x202E] .rust).classify.isClear = true := by
  native_decide

/-- Same bidi control before the line comment marker is in
    code under Rust → fires. -/
theorem detect_rlo_before_rust_line_comment_fires :
    (detect #[0x202E, 0x2F, 0x2F] .rust).classify.tag
      = some "BidiControl" := by native_decide

end Unicode.Security.Display.SourceDisplayDivergence
