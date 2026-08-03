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

import qualified Unicode.Security.Policy as Policy

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- | Sub-threat tag for the aggregate D1 verdict. The first five constructors
-- are the constituent family tags, in canonical aggregation order; 'Compound'
-- is emitted when two or more constituents fire on one input.
data SubThreat
  = -- | The tag-block-payload family fired (and no other).
    TagBlock
  | -- | The variation-selector-payload family fired (and no other).
    VariationSelector
  | -- | The zero-width-payload family fired (and no other).
    ZeroWidth
  | -- | The bidi-control-balance family fired (and no other).
    BidiControl
  | -- | The homoglyph-confusable family fired (and no other).
    IdentifierHomoglyph
  | -- | Two or more constituent families fired on the same input.
    Compound
  deriving stock (Eq, Show)

-- | Fixture-row tag string for this sub-threat (matches @SubThreat.tag@).
subThreatTag :: SubThreat -> String
subThreatTag TagBlock            = "TagBlock"
subThreatTag VariationSelector   = "VariationSelector"
subThreatTag ZeroWidth           = "ZeroWidth"
subThreatTag BidiControl         = "BidiControl"
subThreatTag IdentifierHomoglyph = "IdentifierHomoglyph"
subThreatTag Compound            = "Compound"

-- | Top-level classification (no constituent fired = 'Clear').
data Classification
  = -- | No constituent detector fired: the source renders as it runs.
    Clear
  | -- | At least one constituent fired; the payload is the aggregate
    -- sub-threat tag. Positions are carried by the per-family verdicts, not
    -- here, mirroring the Lean @Classification@.
    Hazard SubThreat
  deriving stock (Eq, Show)

-- | True iff the classification is 'Clear'.
classificationIsClear :: Classification -> Bool
classificationIsClear Clear        = True
classificationIsClear (Hazard _sub) = False

-- | Human-facing tag for a hazard, or 'Nothing' when clear.
classificationTag :: Classification -> Maybe String
classificationTag Clear         = Nothing
classificationTag (Hazard sub)  = Just (subThreatTag sub)

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
constituents :: [Int] -> [([Policy.Finding], SubThreat)]
constituents input =
  [ (Policy.tagBlockFinding input,          TagBlock)
  , (Policy.variationSelectorFinding input, VariationSelector)
  , (Policy.zeroWidthFinding input,         ZeroWidth)
  , (Policy.bidiFinding input,              BidiControl)
  , (Policy.homoglyphFinding input,         IdentifierHomoglyph)
  ]

-- | The constituent tags that fired on this input, in canonical order.
firedFamilies :: [Int] -> [SubThreat]
firedFamilies input =
  [ tag | (finding, tag) <- constituents input, not (null finding) ]

-- | Aggregate the fired constituents into one classification: none → 'Clear',
-- exactly one → pass-through that family's tag, two or more → 'Compound'.
classify :: [SubThreat] -> Classification
classify []                          = Clear
classify [only]                      = Hazard only
classify (_first : _second : _rest)  = Hazard Compound

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

-- | Fully-qualified reason code for a fired sub-threat, of the shape
-- @unicode.security.D.source-display-divergence.\<subThreatTag\>@.
reasonCode :: SubThreat -> String
reasonCode sub = "unicode.security.D.source-display-divergence." ++ subThreatTag sub
