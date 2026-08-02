-- RendererDivergence — detection of codepoint/sequence shapes known to render
-- differently across font + terminal + browser stacks (the display-layer
-- detector).
--
-- Byte-faithful transcription of the verified Rust reference
-- `ports/rust/src/security/display/renderer_divergence.rs`, itself a
-- transcription of `Unicode/Security/Display/RendererDivergence.lean`.
--
-- Threat model. An adversary crafts content that renders one way in the
-- auditor's renderer (a benign glyph or an empty span) and a different way in
-- the consumer's renderer (a misleading glyph, a wider glyph, or a different
-- sequence). This is the "fingerprint stability" family — clear inputs render
-- the same across the renderer cohort the Standard documents as stable.
--
-- What the detector draws. A heuristic three-value split, surfaced through the
-- universal clear/hazard carrier: an input is clear when none of the documented
-- variance triggers fire, and otherwise is classified by the first trigger in
-- priority order — combining-mark stack overflow, variation-selector presence,
-- an unregistered ZWJ shape, fullwidth/halfwidth display, or mixed direction.
-- It reuses the port's own tables (the VariationSelectorPayload variation-
-- selector set, the grapheme-segmentation Extend class, the EmojiZwjIntegrity
-- RGI ZWJ registry, and the RtlInjection strong-bidi classes), never a host
-- rendering or shaping library.
--
-- Sub-threats (priority order):
--   1. CombiningStackOverflow    Zalgo-like combining-mark stack >= 4 on a base.
--   2. VariationSelectorVariance any variation selector present.
--   3. UnregisteredZwjVariance   ZWJ-containing input not in the RGI ZWJ set.
--   4. FullwidthVariance         a fullwidth/halfwidth codepoint present.
--   5. MixedDirectionVariance    both strong-LTR and strong-RTL codepoints.
--
-- Codepoint positions are 0-based to mirror the reference.

local variation_selector = require("unicode_lua.security.covert.variation_selector_payload")
local emoji_zwj = require("unicode_lua.security.identity.emoji_zwj_integrity")
local ucd = require("unicode_lua.security.identity.ucd")
local grapheme = require("unicode_lua.segmentation.grapheme")

local unpack = table.unpack or unpack

local M = {}

-- ─────────────────────────────────────────────────────────────────────
-- §1 Constants
-- ─────────────────────────────────────────────────────────────────────

-- The combining-mark stack depth (on a single base) at or beyond which the
-- input is treated as a Zalgo-style rendering-variance hazard.
M.MIN_COMBINING_STACK = 4

-- The ZERO WIDTH JOINER codepoint.
M.ZWJ = 0x200D

-- ─────────────────────────────────────────────────────────────────────
-- §2 Core predicates (reuse the port's own tables)
-- ─────────────────────────────────────────────────────────────────────

-- True iff `cp` is a variation selector (reuses the VariationSelectorPayload
-- predicate over U+FE00..U+FE0F ∪ U+E0100..U+E01EF ∪ U+180B..U+180D).
function M.is_variation_selector(cp)
  return variation_selector.is_variation_selector(cp)
end

-- True iff `cp` is the ZWJ codepoint.
function M.is_zwj(cp)
  return cp == M.ZWJ
end

-- True iff `cp` is in the Halfwidth/Fullwidth Forms block.
function M.is_fullwidth_halfwidth(cp)
  return cp >= 0xFF01 and cp <= 0xFFEF
end

-- True iff `cp` has Grapheme_Cluster_Break = Extend (reuses the grapheme-
-- segmentation GCB table via `lookup_gcb`, exactly as the Rust reference does).
function M.is_grapheme_extend(cp)
  return grapheme.lookup_gcb(cp) == "Extend"
end

-- ─────────────────────────────────────────────────────────────────────
-- §3 Sub-detectors
-- ─────────────────────────────────────────────────────────────────────

local function count_vs(input)
  local count = 0
  for i = 1, #input do
    if M.is_variation_selector(input[i]) then
      count = count + 1
    end
  end
  return count
end

local function count_combining(input)
  local count = 0
  for i = 1, #input do
    if M.is_grapheme_extend(input[i]) then
      count = count + 1
    end
  end
  return count
end

local function count_fullwidth(input)
  local count = 0
  for i = 1, #input do
    if M.is_fullwidth_halfwidth(input[i]) then
      count = count + 1
    end
  end
  return count
end

local function input_has_zwj(input)
  for i = 1, #input do
    if M.is_zwj(input[i]) then
      return true
    end
  end
  return false
end

local function count_strong_ltr(input)
  local count = 0
  for i = 1, #input do
    if ucd.is_strong_ltr(input[i]) then
      count = count + 1
    end
  end
  return count
end

local function count_strong_rtl(input)
  local count = 0
  for i = 1, #input do
    if ucd.is_strong_rtl(input[i]) then
      count = count + 1
    end
  end
  return count
end

-- Position (0-based) and codepoint of the first variation selector, or nil.
local function first_vs_pos(input)
  for i = 1, #input do
    if M.is_variation_selector(input[i]) then
      return i - 1, input[i]
    end
  end
  return nil, nil
end

-- Position (0-based) of the first ZWJ, or nil.
local function first_zwj_pos(input)
  for i = 1, #input do
    if M.is_zwj(input[i]) then
      return i - 1
    end
  end
  return nil
end

-- Position (0-based) and codepoint of the first fullwidth/halfwidth codepoint,
-- or nil.
local function first_fullwidth_pos(input)
  for i = 1, #input do
    if M.is_fullwidth_halfwidth(input[i]) then
      return i - 1, input[i]
    end
  end
  return nil, nil
end

-- The first base position (a non-Extend codepoint) immediately followed by
-- exactly `min_stack` consecutive Extend codepoints. Returns
-- `base_pos (0-based), min_stack` on hit, or nil.
local function first_combining_stack(input, min_stack)
  for i = 1, #input do
    if not M.is_grapheme_extend(input[i]) then
      local following_len = 0
      local all_extend = true
      for j = i + 1, i + min_stack do
        if input[j] == nil then
          break
        end
        following_len = following_len + 1
        if not M.is_grapheme_extend(input[j]) then
          all_extend = false
        end
      end
      if following_len == min_stack and all_extend then
        return i - 1, min_stack
      end
    end
  end
  return nil, nil
end

-- ─────────────────────────────────────────────────────────────────────
-- §4 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- The RendererDivergence detection function. Returns a verdict table mirroring
-- the Rust `Verdict`: `input`, `classify` (`{ kind, sub, positions, decoded }`),
-- `vs_count`, `combining_count`, `fullwidth_count`, `has_zwj`,
-- `strong_ltr_count`, `strong_rtl_count`.
function M.detect(input)
  local vs_count = count_vs(input)
  local combining_count = count_combining(input)
  local fullwidth_count = count_fullwidth(input)
  local has_zwj = input_has_zwj(input)
  local ltr_count = count_strong_ltr(input)
  local rtl_count = count_strong_rtl(input)

  local classify
  -- Priority 1: combining-mark stack overflow (Zalgo).
  local base_pos, stack_len = first_combining_stack(input, M.MIN_COMBINING_STACK)
  if base_pos ~= nil then
    classify = {
      kind = "Hazard",
      sub = { tag = "CombiningStackOverflow", base_pos = base_pos, stack_len = stack_len },
      positions = { base_pos },
      decoded = {},
    }
  else
    -- Priority 2: any variation selector triggers presentation variance.
    local vs_pos, vs_cp = first_vs_pos(input)
    if vs_pos ~= nil then
      classify = {
        kind = "Hazard",
        sub = { tag = "VariationSelectorVariance", first_vs_pos = vs_pos, first_vs_cp = vs_cp },
        positions = { vs_pos },
        decoded = {},
      }
    elseif has_zwj and not emoji_zwj.is_registered_zwj_sequence(input) then
      -- Priority 3: ZWJ-containing input not in the registered RGI set.
      local zwj_pos = first_zwj_pos(input)
      if zwj_pos ~= nil then
        classify = {
          kind = "Hazard",
          sub = { tag = "UnregisteredZwjVariance", first_zwj_pos = zwj_pos },
          positions = { zwj_pos },
          decoded = {},
        }
      else
        classify = { kind = "Clear", sub = nil, positions = {}, decoded = {} }
      end
    else
      -- Priority 4: fullwidth/halfwidth.
      local fw_pos, fw_cp = first_fullwidth_pos(input)
      if fw_pos ~= nil then
        classify = {
          kind = "Hazard",
          sub = { tag = "FullwidthVariance", first_fw_pos = fw_pos, first_fw_cp = fw_cp },
          positions = { fw_pos },
          decoded = {},
        }
      elseif ltr_count > 0 and rtl_count > 0 then
        -- Priority 5: mixed direction.
        classify = {
          kind = "Hazard",
          sub = { tag = "MixedDirectionVariance", ltr_count = ltr_count, rtl_count = rtl_count },
          positions = {},
          decoded = {},
        }
      else
        classify = { kind = "Clear", sub = nil, positions = {}, decoded = {} }
      end
    end
  end

  local input_copy = {}
  if #input > 0 then
    input_copy = { unpack(input) }
  end

  return {
    input = input_copy,
    classify = classify,
    vs_count = vs_count,
    combining_count = combining_count,
    fullwidth_count = fullwidth_count,
    has_zwj = has_zwj,
    strong_ltr_count = ltr_count,
    strong_rtl_count = rtl_count,
  }
end

-- True iff the verdict's classification is Clear.
function M.is_clear(verdict)
  return verdict.classify.kind == "Clear"
end

-- Human-facing tag for a verdict's classification, or nil when clear. Exhaustive
-- over the five sub-threats; an unknown tag is a construction bug and raises.
function M.classification_tag(verdict)
  local sub = verdict.classify.sub
  if sub == nil then
    return nil
  end
  local tag = sub.tag
  if tag == "CombiningStackOverflow" then
    return "CombiningStackOverflow"
  elseif tag == "VariationSelectorVariance" then
    return "VariationSelectorVariance"
  elseif tag == "UnregisteredZwjVariance" then
    return "UnregisteredZwjVariance"
  elseif tag == "FullwidthVariance" then
    return "FullwidthVariance"
  elseif tag == "MixedDirectionVariance" then
    return "MixedDirectionVariance"
  else
    error("classification_tag: unknown RendererDivergence sub-threat " .. tostring(tag))
  end
end

-- Implicated positions (empty when clear).
function M.classification_positions(verdict)
  return verdict.classify.positions
end

return M
