{-|
Module      : Unicode.Security.Display.SourceDisplayDivergence
Description : Aggregate "what a reviewer sees differs from what runs" detector.

Haskell port of @Unicode.Security.Display.SourceDisplayDivergence@ from
unicode-lean, transliterated byte-faithfully from the verified Rust reference
implementation (the display-layer aggregator, reason-code letter @D@).

Threat model. A single covert or identity trick may look individually benign,
but any hit means the rendered source diverges from its logical content; two or
more is a strong compound signal. This detector runs the five constituent
detectors on the same codepoint stream and aggregates: zero fire → 'Clear',
exactly one → pass-through that family's tag, two or more → 'Compound'.

What the detector reuses. This is pure aggregation over the port's own
constituent detectors — it introduces no predicate, table, or host library of
its own. It reuses, in this exact canonical order, the five core-family
detectors that already live in 'Unicode.Security.Policy':

  1. 'Unicode.Security.Policy.tagBlockFinding'          → 'TagBlock'
  2. 'Unicode.Security.Policy.variationSelectorFinding' → 'VariationSelector'
  3. 'Unicode.Security.Policy.zeroWidthFinding'         → 'ZeroWidth'
  4. 'Unicode.Security.Policy.bidiFinding'              → 'BidiControl'
  5. 'Unicode.Security.Policy.homoglyphFinding'         → 'IdentifierHomoglyph'

Each constituent's "is clear" accessor is the emptiness of the 'Finding' list it
returns: a non-empty list is a fire (the family's classification is non-clear).

No positions at this layer. By the Lean spec the per-family verdicts carry the
implicated positions; the aggregate verdict carries only the sub-threat tag, so
'Classification' holds no position list.
-}
module Unicode.Security.Display.SourceDisplayDivergence
  ( SubThreat
      ( TagBlock, VariationSelector, ZeroWidth, BidiControl, IdentifierHomoglyph
      , Compound
      )
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , Verdict (Verdict, verdictInput, verdictClassify, verdictFires)
  , detect
  , reasonCode
  ) where

import Unicode.Security.Display.SourceDisplayAggregate
  ( Classification (Clear, Hazard)
  , SubThreat
      ( BidiControl, Compound, IdentifierHomoglyph, TagBlock, VariationSelector
      , ZeroWidth
      )
  , classificationIsClear
  , classificationTag
  , classify
  , firedFrom
  , reasonCode
  , subThreatTag
  )
import qualified Unicode.Security.Policy as Policy

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- | Verdict — the structured output of 'detect' (mirrors the Lean @Verdict@).
data Verdict = Verdict
  { verdictInput    :: ![Int]
    -- ^ The scanned input codepoints.
  , verdictClassify :: !Classification
    -- ^ The aggregate classification verdict.
  , verdictFires    :: ![SubThreat]
    -- ^ The constituent family tags that fired, in canonical order.
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- §2 Aggregation
-- ─────────────────────────────────────────────────────────────────────

-- | The five constituent detectors paired with the tag each contributes, in
-- canonical aggregation order. Each entry runs the port's own core-family
-- detector on the same input; a non-empty 'Finding' list is a fire.
constituents :: [Int] -> [[Policy.Finding]]
constituents input =
  [ Policy.tagBlockFinding input
  , Policy.variationSelectorFinding input
  , Policy.zeroWidthFinding input
  , Policy.bidiFinding input
  , Policy.homoglyphConstituentFinding input
  ]

-- | The constituent tags that fired on this input, in canonical order.
firedFamilies :: [Int] -> [SubThreat]
firedFamilies input = firedFrom (map (not . null) (constituents input))

-- | The SourceDisplayDivergence detection function. Runs the five constituent
-- detectors in canonical order and aggregates by how many fired, mirroring the
-- verified Rust reference exactly; see the module header for the constituent
-- inventory and tag mapping.
detect :: [Int] -> Verdict
detect input =
  Verdict
    { verdictInput    = input
    , verdictClassify = classify fires
    , verdictFires    = fires
    }
  where
    fires = firedFamilies input

