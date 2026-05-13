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

    * Language-agnostic by design (v0.12.0).  Earlier prereleases
      experimented with a `Language` parameter that filtered hits
      by source-region grammar (code vs. string-literal vs.
      comment).  That filtering surface has been retracted: it
      assumed a grammar's region partition makes some source
      bytes safer than others, an assumption the broader
      ecosystem evidence contradicts (tj-actions/changed-files
      March 2025 supply-chain attack; CVE-2025-29927 Next.js
      middleware bypass; LLM code-assistant prompt injection
      via JSDoc/docstring comments; npm-metadata-string supply-
      chain backdoors).  Source bytes are uniformly suspect
      regardless of which source-region a tokenizer would
      assign them to.  Every sub-detector hit therefore fires
      unconditionally.

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

namespace Unicode.Security.Display.SourceDisplayDivergence

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- D1 sub-threats — one per constituent family plus a `compound`
    variant for the multi-mechanism attack class. -/
inductive SubThreat where
  | tagBlock            (innerTag : String)
  | variationSelector   (innerTag : String)
  | zeroWidth           (innerTag : String)
  | bidiControl         (innerTag : String)
  | identifierHomoglyph (innerTag : String)
  | compound            (constituents : Array String)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for D1. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

/-- D1 verdict — carries all five sub-detector verdicts so a
    reviewer can drill into any specific family if interested. -/
structure Verdict where
  input              : Array Nat
  classify           : Classification
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
    (c1Tag c2Tag c3Tag c5Tag i1Tag : Option String) : Classification :=
  let fires : Array (String × String) :=
    #[("C1", c1Tag.getD ""), ("C2", c2Tag.getD ""), ("C3", c3Tag.getD ""),
      ("C5", c5Tag.getD ""), ("I1", i1Tag.getD "")]
    |>.filter (fun pair => pair.2 ≠ "")
  match fires.size with
  | 0 => .clear
  | 1 =>
    let pair := fires[0]!
    let sub : SubThreat := match pair.1 with
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
    detectors on the same codepoint stream and aggregates the
    results into a compound verdict.

    Every sub-detector hit fires unconditionally, regardless of
    where in the source the offending codepoint sits.  Earlier
    prereleases tried to filter hits by source-region grammar
    (strings, comments) but that surface has been retracted —
    see module header for the threat-model rationale. -/
def detect (input : Array Nat) : Verdict :=
  let c1 := Unicode.Security.Covert.TagBlockPayload.detect input
  let c2 := Unicode.Security.Covert.VariationSelectorPayload.detect input
  let c3 := Unicode.Security.Covert.ZeroWidthPayload.detect input
  let c5 := Unicode.Security.Covert.BidiControlBalance.detect input
  let i1 := Unicode.Security.Identity.HomoglyphConfusable.detect input
  let c1Tag := c1.classify.tag
  let c2Tag := c2.classify.tag
  let c3Tag := c3.classify.tag
  let c5Tag := c5.classify.tag
  let i1Tag := i1.classify.tag
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

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
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
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def Classification.positions : Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (SubThreat × ByteArray) positions (sub, decoded)

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
-- §6 Region-agnosticism spot checks
--
-- Pinning that D1 fires on hazardous codepoints regardless of
-- where they sit in the source.  Previously some of these
-- inputs cleared under a `Language.rust` / `.python` /
-- `.typescript` filter; the filter has been retracted in
-- v0.12.0 because source-region grammar is not a security
-- boundary (see module header).
-- ═══════════════════════════════════════════════════════════════════════════════

/-- VS payload "inside a string literal" — fires D1 because the
    source bytes are still attacker-visible regardless of what
    a tokenizer says about the region. -/
theorem detect_vs_inside_quote_pair_fires :
    (detect #[0x22, 0x41, 0xFE00, 0x22]).classify.tag
      = some "VariationSelector" := by native_decide

/-- RLO "inside a line comment" — fires D1 for the same
    reason.  Source-display divergence in a comment still
    deceives every consumer that reads bytes (LLM code
    assistants, doc generators, IDE renderers, CI grep
    matchers). -/
theorem detect_rlo_inside_line_comment_marker_fires :
    (detect #[0x2F, 0x2F, 0x202E]).classify.tag
      = some "BidiControl" := by native_decide

/-- RLO "inside a block comment" — fires D1. -/
theorem detect_rlo_inside_block_comment_fires :
    (detect #[0x2F, 0x2A, 0x202E, 0x2A, 0x2F]).classify.tag
      = some "BidiControl" := by native_decide

end Unicode.Security.Display.SourceDisplayDivergence
