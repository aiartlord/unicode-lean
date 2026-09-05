-- SourceDisplayDivergence — the aggregate "what a reviewer sees differs from
-- what the machine runs" detector (display / D-layer).
--
-- Byte-faithful transcription of the verified Rust reference
-- (`security/display/source_display_divergence.rs`) and of
-- `Unicode/Security/Display/SourceDisplayDivergence.lean`
-- (`detect` + `buildClassification`).
--
-- Threat model. A single covert or identity trick may be individually
-- benign-looking, but any hit means the rendered source diverges from its
-- logical content; two or more is a strong compound signal. This detector runs
-- the five constituent detectors on the same codepoint stream and aggregates:
-- zero fire → clear, exactly one → pass-through that family's tag, two or more →
-- `Compound`. Every constituent fires region-agnostically — payloads inside
-- string literals or comments count.
--
-- It is a pure aggregation over the port's own constituent detectors — the
-- tag-block, variation-selector, and zero-width covert channels, the bidi
-- purpose rule (BidiControlPurpose), and the homoglyph-confusable identity
-- check — reusing their `detect` and classification kind; it introduces no new
-- table, no new predicate, and no host library. A constituent counts as fired
-- iff its classification kind is not Clear.

local calculus = require("unicode_lua.security.calculus")
local tag_block = require("unicode_lua.security.covert.tag_block_payload")
local variation_selector = require("unicode_lua.security.covert.variation_selector_payload")
local zero_width = require("unicode_lua.security.covert.zero_width_payload")
local bidi_purpose = require("unicode_lua.security.display.bidi_control_purpose")
local homoglyph = require("unicode_lua.security.identity.homoglyph_confusable")

local ClassificationKind = calculus.ClassificationKind

local M = {}

-- The constituent family tags, in canonical aggregation order. A single
-- non-clear constituent passes its tag through unchanged.
M.TAG_BLOCK = "TagBlock"
M.VARIATION_SELECTOR = "VariationSelector"
M.ZERO_WIDTH = "ZeroWidth"
M.BIDI_CONTROL = "BidiControl"
M.IDENTIFIER_HOMOGLYPH = "IdentifierHomoglyph"

-- The tag emitted when two or more constituents fire.
M.COMPOUND = "Compound"

-- True iff a constituent classification kind counts as fired — anything other
-- than a clear verdict. Explicit over the closed ClassificationKind enum so an
-- unrecognised kind is a loud error, never a silent miss.
local function fired(kind)
  if kind == ClassificationKind.Clear then
    return false
  elseif kind == ClassificationKind.Hazard then
    return true
  elseif kind == ClassificationKind.Compound then
    return true
  else
    error("source_display_divergence.fired: unknown ClassificationKind " .. tostring(kind))
  end
end

-- Collapse the ordered list of fired tags into the sub-threat: none → clear
-- (nil), one → that tag, two or more → `Compound`.
local function aggregate(fires)
  if #fires == 0 then
    return nil
  elseif #fires == 1 then
    return fires[1]
  else
    return M.COMPOUND
  end
end

-- Aggregate over a homoglyph verdict already in hand. The scan passes the
-- verdict it produced (per identifier token on running text), so the
-- constituent and the family finding are one reading of the same input;
-- mirrors the Lean `detectCore input homoglyphVerdict`. Returns `{ sub }`:
-- `sub` is nil for a clear input, a single constituent hit passes through its
-- family tag, two or more yield `"Compound"`. Positions are empty at this layer
-- by the Lean spec (the per-family verdicts carry them), so this result carries
-- only the sub-threat.
function M.detect_core(input, homoglyph_fired)
  local fires = {}

  if fired(tag_block.detect(input).kind) then
    fires[#fires + 1] = M.TAG_BLOCK
  end
  if fired(variation_selector.detect(input).kind) then
    fires[#fires + 1] = M.VARIATION_SELECTOR
  end
  if fired(zero_width.detect(input).kind) then
    fires[#fires + 1] = M.ZERO_WIDTH
  end
  -- A purposeless control: unbalanced, or a balanced span enclosing nothing
  -- right-to-left in a left-to-right context. A Trojan Source payload balances
  -- its controls -- an unbalanced run breaks the file it is hiding in -- so a
  -- constituent built on the balance verdict is blind to the shape the attack
  -- takes; a balanced embedding around an Arabic string literal manages that
  -- literal and is not a constituent.
  if bidi_purpose.has_purposeless_control(input) then
    fires[#fires + 1] = M.BIDI_CONTROL
  end
  if homoglyph_fired then
    fires[#fires + 1] = M.IDENTIFIER_HOMOGLYPH
  end

  return { sub = aggregate(fires) }
end

-- Aggregate the five constituent detectors into a single D-layer verdict at the
-- default context: the homoglyph constituent is the whole-input homoglyph
-- verdict. Mirrors the Lean detect.
function M.detect(input)
  return M.detect_core(input, fired(homoglyph.detect(input).kind))
end

-- True iff the detection's classification is Clear.
function M.is_clear(detection)
  return detection.sub == nil
end

-- Human-facing tag for a detection's classification, or nil when clear.
function M.classification_tag(detection)
  return detection.sub
end

return M
