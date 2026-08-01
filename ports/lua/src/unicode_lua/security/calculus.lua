-- Shared verdict vocabulary for the Security Conformance Layer.
--
-- Per-family modules refine this shared vocabulary into family-specific verdict
-- structures.  A `Family` value is its stable slug string (unique per family),
-- so `family_slug` is the identity on these constants.

local M = {}

-- The detector families, in aggregator-walk / priority order.  Each value is
-- the stable reason-code slug.
M.Family = {
  MalformedUtf8 = "malformed-utf8",
  MalformedUtf16 = "malformed-utf16",
  MalformedUtf32 = "malformed-utf32",
  TagBlockPayload = "tag-block-payload",
  VariationSelectorPayload = "variation-selector-payload",
  ZeroWidthPayload = "zero-width-payload",
  SurrogateReassembly = "surrogate-reassembly",
  BidiControlBalance = "bidi-control-balance",
  NoncharacterControl = "noncharacter-control",
  HomoglyphConfusable = "homoglyph-confusable",
  MixedScriptAdmissibility = "mixed-script-admissibility",
  EmojiZwjIntegrity = "emoji-zwj-integrity",
  SkinToneVariationForgery = "skin-tone-variation-forgery",
  SourceDisplayDivergence = "source-display-divergence",
  FilenameDisguise = "filename-disguise",
  RtlInjection = "rtl-injection",
  RendererDivergence = "renderer-divergence",
  NormalizationBomb = "normalization-bomb",
  StreamSafeViolation = "stream-safe-violation",
  LocaleCaseInversion = "locale-case-inversion",
  CaseExpansionMismatch = "case-expansion-mismatch",
  WidthClassConfusion = "width-class-confusion",
  NfcIdempotenceWitness = "nfc-idempotence-witness",
  IdentifierFormDrift = "identifier-form-drift",
  CovertDisplayCompound = "covert-display-compound",
  ConfusableBidiCompound = "confusable-bidi-compound",
  AdmissibilityFormDrift = "admissibility-form-drift",
  Bip39Canonical = "bip39-canonical",
  HashInputStability = "hash-input-stability",
  AiWatermarkDetectability = "ai-watermark-detectability",
}

-- Ordered severity vocabulary: Informational < Low < Moderate < High < Critical.
M.Severity = {
  Informational = 0,
  Low = 1,
  Moderate = 2,
  High = 3,
  Critical = 4,
}

-- Five-tier adversary capability hierarchy (A0 passive .. A4 model-adaptive).
M.AdversaryTier = {
  A0 = 0,
  A1 = 1,
  A2 = 2,
  A3 = 3,
  A4 = 4,
}

-- The verdict kind, independent of any family-specific sub-threat payload.
M.ClassificationKind = {
  Clear = "Clear",
  Hazard = "Hazard",
  Compound = "Compound",
  Informational = "Informational",
}

-- The default severity associated with each classification kind.
function M.default_severity(kind)
  local K = M.ClassificationKind
  local S = M.Severity
  if kind == K.Clear then
    return S.Informational
  elseif kind == K.Hazard then
    return S.Moderate
  elseif kind == K.Compound then
    return S.High
  elseif kind == K.Informational then
    return S.Informational
  else
    error("default_severity: unknown ClassificationKind " .. tostring(kind))
  end
end

return M
