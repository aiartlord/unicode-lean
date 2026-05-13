/-
  Unicode.Security.Verdict

  Composite-verdict layer over `Unicode.Security.Calculus`. Provides:

    * `HazardSite` — a single attributable hazard occurrence (family,
      position, attribution map)
    * `CompositeVerdict` — the universal verdict carrier used by
      cross-family composition (e.g. SourceDisplayDivergence layers
      every Covert family + HomoglyphConfusable; the top-level
      `securityVerdict` layers all 6 L-views)
    * Composition operators: `clear`, `singleHazard`, `compose`,
      `concat`
    * `severity` rollup over a composite
    * Severity-lattice operations + propagation laws

  Family modules each define their own `Verdict` structure (under
  the family's namespace) with family-specific payload fields, plus
  a `toComposite : Verdict → CompositeVerdict` adapter.  The
  CompositeVerdict here is the shared carrier that crosses family
  boundaries.

  Modelled on `Unicode.Codec.Strict.StrictParseResult` (parametric
  result-monad with `map` / `bind` / propagation lemmas) and
  `Unicode.Refined` (refinement-typed wrappers).
-/

import Unicode.Security.Calculus

namespace Unicode.Security.Verdict

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 HazardSite — a single attributable hazard
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A single hazard attribution: which family fired, at which positions,
    with what severity and family-specific attribution metadata. -/
structure HazardSite where
  family       : Family
  positions    : Array Nat                    -- 0-indexed codepoint positions
  severity     : Severity
  subThreatTag : String                       -- family-specific sub-threat name
  attribution  : KeyValueAttribution
  deriving Repr, Inhabited

namespace HazardSite

/-- Build a hazard site with default-severity and empty attribution. -/
def mk' (family : Family) (positions : Array Nat) (subThreatTag : String) :
    HazardSite where
  family := family
  positions := positions
  severity := .moderate                       -- default; family verdicts override
  subThreatTag := subThreatTag
  attribution := KeyValueAttribution.empty

/-- The hazard site's start position (lowest position index). Returns 0 if
    positions is empty. -/
def startPos (h : HazardSite) : Nat :=
  h.positions.foldl Nat.min (h.positions.getD 0 0)

/-- The hazard site's end position (highest position index). Returns 0 if
    positions is empty. -/
def endPos (h : HazardSite) : Nat :=
  h.positions.foldl Nat.max 0

end HazardSite

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 CompositeVerdict — the universal verdict carrier
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The cross-family verdict carrier. Each family produces its own rich
    verdict structure (`<F>Verdict`) in its own module and projects it
    onto this shared shape via a `toComposite` adapter. -/
structure CompositeVerdict where
  input    : Array Nat
  kind     : ClassificationKind
  sites    : Array HazardSite                -- empty when kind = .clear
  severity : Severity                         -- rollup over `sites`
  deriving Repr, Inhabited

namespace CompositeVerdict

/-- A clear verdict on `input`. -/
def clear (input : Array Nat) : CompositeVerdict where
  input := input
  kind := .clear
  sites := #[]
  severity := .informational

/-- A single-site hazard verdict on `input`. -/
def singleHazard (input : Array Nat) (site : HazardSite) : CompositeVerdict where
  input := input
  kind := .hazard
  sites := #[site]
  severity := site.severity

/-- A compound (multi-site) verdict on `input`. The composite severity is
    the maximum over constituent site severities. -/
def compoundOf (input : Array Nat) (sites : Array HazardSite) :
    CompositeVerdict :=
  let maxSev := sites.foldl (fun acc s => Severity.max acc s.severity) .informational
  let kind : ClassificationKind :=
    if sites.isEmpty then .clear
    else if sites.size = 1 then .hazard
    else .compound
  { input := input, kind := kind, sites := sites, severity := maxSev }

/-- Concatenate the hazard sites of two composites on the same input.
    Caller is responsible for ensuring `a.input = b.input` (the operator
    is intended for cross-family layering on a shared input). -/
def concat (a b : CompositeVerdict) : CompositeVerdict :=
  compoundOf a.input (a.sites ++ b.sites)

/-- Compose any number of family verdicts on the same input into a single
    CompositeVerdict. -/
def composeMany (input : Array Nat) (vs : List CompositeVerdict) :
    CompositeVerdict :=
  compoundOf input (vs.foldl (fun acc v => acc ++ v.sites) #[])

/-- True iff no hazard was detected. -/
@[inline]
def isClear (v : CompositeVerdict) : Bool := v.kind matches .clear

/-- True iff at least one hazard was detected. -/
@[inline]
def hasHazard (v : CompositeVerdict) : Bool :=
  !v.isClear

end CompositeVerdict

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Compositionality laws
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A clear verdict has no hazard sites. -/
@[simp]
theorem clear_sites_empty (input : Array Nat) :
    (CompositeVerdict.clear input).sites = #[] := rfl

/-- A clear verdict has informational severity. -/
@[simp]
theorem clear_severity (input : Array Nat) :
    (CompositeVerdict.clear input).severity = .informational := rfl

/-- A single-hazard verdict carries the site's severity. -/
@[simp]
theorem singleHazard_severity (input : Array Nat) (s : HazardSite) :
    (CompositeVerdict.singleHazard input s).severity = s.severity := rfl

/-- Concatenating with a clear verdict on the same input preserves the
    other verdict's sites. -/
theorem concat_clear_right (a : CompositeVerdict) :
    let combined := CompositeVerdict.concat a (CompositeVerdict.clear a.input)
    combined.sites = a.sites := by
  simp [CompositeVerdict.concat, CompositeVerdict.compoundOf,
        CompositeVerdict.clear]

/-- Concatenating two clear verdicts yields a clear verdict (modulo
    empty-sites compound classification). -/
theorem concat_clear_clear (input : Array Nat) :
    let lhs := CompositeVerdict.concat (CompositeVerdict.clear input)
                                       (CompositeVerdict.clear input)
    lhs.sites = #[] := by
  simp [CompositeVerdict.concat, CompositeVerdict.compoundOf,
        CompositeVerdict.clear]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Severity-lattice spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The severity lattice's max is monotone: max(a, b) ≥ a. -/
theorem severity_max_left (a b : Severity) :
    a.toNat ≤ (a.max b).toNat := by
  cases a <;> cases b <;> decide

theorem severity_max_right (a b : Severity) :
    b.toNat ≤ (a.max b).toNat := by
  cases a <;> cases b <;> decide

theorem severity_min_left (a b : Severity) :
    (a.min b).toNat ≤ a.toNat := by
  cases a <;> cases b <;> decide

theorem severity_min_right (a b : Severity) :
    (a.min b).toNat ≤ b.toNat := by
  cases a <;> cases b <;> decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Sample composite construction (sanity check)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Build a sample hazard site for the `decide`-based sanity proofs. -/
private def sampleSite : HazardSite :=
  HazardSite.mk' .variationSelectorPayload #[1, 2, 3] "DirectPayload"

private def sampleClear : CompositeVerdict :=
  CompositeVerdict.clear #[0x61, 0x62, 0x63]

private def sampleHazardous : CompositeVerdict :=
  CompositeVerdict.singleHazard #[0x61, 0x62, 0x63] sampleSite

/-- Clear sample is isClear. -/
theorem sample_clear_isClear : sampleClear.isClear = true := rfl

/-- Hazardous sample is not isClear. -/
theorem sample_hazardous_not_clear : sampleHazardous.isClear = false := rfl

/-- Hazardous sample has exactly one site. -/
theorem sample_hazardous_size : sampleHazardous.sites.size = 1 := rfl

end Unicode.Security.Verdict
