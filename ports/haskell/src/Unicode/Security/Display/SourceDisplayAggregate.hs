{-# LANGUAGE StrictData #-}

{-|
Module      : Unicode.Security.Display.SourceDisplayAggregate
Description : The source-display-divergence sub-threat, its aggregation rule,
              and the canonical constituent order.

This layer holds everything about source-display-divergence that does not
depend on running the constituent detectors: the sub-threat tags, the rule that
turns a list of fired constituents into one classification, and the order the
constituents are canonically considered in.

It exists so that both callers can share one definition of that rule.
"Unicode.Security.Display.SourceDisplayDivergence" runs the constituents itself
and so depends on "Unicode.Security.Policy", which owns those detectors;
"Unicode.Security.Policy" in turn has to report this family from its own scan,
and importing the detector module back would close a cycle. Splitting the rule
out means the aggregation and the constituent order are written once, and the
two callers differ only in how they discover which constituents fired.
-}
module Unicode.Security.Display.SourceDisplayAggregate
  ( SubThreat
      ( TagBlock, VariationSelector, ZeroWidth, BidiControl, IdentifierHomoglyph
      , Compound
      )
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classify
  , constituentOrder
  , firedFrom
  , reasonCode
  ) where

-- | Which constituent family fired, or that several did.
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

-- | Stable wire tag for a sub-threat.
subThreatTag :: SubThreat -> String
subThreatTag TagBlock            = "TagBlock"
subThreatTag VariationSelector   = "VariationSelector"
subThreatTag ZeroWidth           = "ZeroWidth"
subThreatTag BidiControl         = "BidiControl"
subThreatTag IdentifierHomoglyph = "IdentifierHomoglyph"
subThreatTag Compound            = "Compound"

-- | The aggregate verdict over an input.
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
classificationIsClear (Hazard _)   = False

-- | The sub-threat tag of a hazard, or 'Nothing' when clear.
classificationTag :: Classification -> Maybe String
classificationTag Clear         = Nothing
classificationTag (Hazard sub)   = Just (subThreatTag sub)

-- | Aggregate the fired constituents into one classification: none → 'Clear',
-- exactly one → pass-through that family's tag, two or more → 'Compound'.
classify :: [SubThreat] -> Classification
classify []                          = Clear
classify [only]                      = Hazard only
classify (_first : _second : _rest)  = Hazard Compound

-- | The constituent families, in the order the reference considers them.
constituentOrder :: [SubThreat]
constituentOrder =
  [TagBlock, VariationSelector, ZeroWidth, BidiControl, IdentifierHomoglyph]

-- | The constituents that fired, given one flag per entry of
-- 'constituentOrder' and in that order.
firedFrom :: [Bool] -> [SubThreat]
firedFrom flags = [tag | (True, tag) <- zip flags constituentOrder]

-- | Fully-qualified reason code for a fired sub-threat, of the shape
-- @unicode.security.D.source-display-divergence.\<subThreatTag\>@.
reasonCode :: SubThreat -> String
reasonCode sub = "unicode.security.D.source-display-divergence." ++ subThreatTag sub
