-- IdentifierFormDrift — cross-layer identifier x form drift (boundary-layer
-- detector).
--
-- Byte-faithful transcription of the verified Rust reference implementation,
-- itself a transcription of `Unicode/Security/Boundary/IdentifierFormDrift.lean`.
--
-- Threat model. Tier A2 two-system bypass. An identity validator and a form
-- normalizer disagree about a codepoint: stage A runs the UTS #39
-- `Identifier_Status` check before normalisation and rejects, say, U+1D44E
-- MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and then
-- runs the same check, seeing U+0061 'a' (Allowed) and accepting. The attacker
-- controls which stage processes the input and exploits the disagreement. The
-- same shape covers fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01),
-- and Roman-numeral (U+2163) compatibility forms.
--
-- The detector fires on the form transition itself — it reports every input
-- position whose `Identifier_Status` differs from the `Identifier_Status` of
-- that codepoint's NFKD head. This is orthogonal to the single-form
-- identity-spoofing detectors (which examine the input under one form) and
-- stronger than a form-of-input fold (it asks whether the identifier verdict
-- changes, not whether any output bit changes).
--
-- Note on Hangul: precomposed syllables are Allowed while their NFKD-head jamos
-- are Restricted, so pure Korean text fires; callers intending to accept Korean
-- identifiers should apply NFC before evaluating admissibility.
--
-- It reuses the port's own UTS #39 `Identifier_Status` predicate
-- (`ucd.is_id_allowed`) and NFKD pipeline (`ucd.to_nfkd`), never a host
-- normalization or identifier library.
--
-- Sub-threat (direction-agnostic):
--   IdentifierStatusShift — the first input position whose `Identifier_Status`
--   differs from its NFKD-head's. The verdict carries the total shift count.
--
-- Codepoint positions are 0-based to mirror the reference.

local ucd = require("unicode_lua.security.identity.ucd")

local unpack = table.unpack or unpack

local M = {}

-- ─────────────────────────────────────────────────────────────────────
-- §2 Core predicates (reuse the port's own tables)
-- ─────────────────────────────────────────────────────────────────────

-- `Identifier_Status = Allowed` of the first codepoint of `cp`'s NFKD form, or
-- `cp`'s own status when NFKD is empty (defensive — `to_nfkd` is total and
-- returns at least `[cp]`). Reuses the port's own UTS #39 predicate and NFKD.
function M.nfkd_head_allowed(cp)
  local decomposed = ucd.to_nfkd({ cp })
  local head = decomposed[1]
  if head ~= nil then
    return ucd.is_id_allowed(head)
  end
  return ucd.is_id_allowed(cp)
end

-- ─────────────────────────────────────────────────────────────────────
-- §3 Sub-detectors
-- ─────────────────────────────────────────────────────────────────────

-- Position (0-based) and codepoint of the first input position whose
-- `is_id_allowed` differs from its NFKD-head's, or nil.
local function first_status_shift(input)
  for i = 1, #input do
    local cp = input[i]
    if ucd.is_id_allowed(cp) ~= M.nfkd_head_allowed(cp) then
      return i - 1, cp
    end
  end
  return nil, nil
end

-- Total count of input positions where the per-cp status shifts under NFKD.
local function status_shift_count(input)
  local count = 0
  for i = 1, #input do
    local cp = input[i]
    if ucd.is_id_allowed(cp) ~= M.nfkd_head_allowed(cp) then
      count = count + 1
    end
  end
  return count
end

-- ─────────────────────────────────────────────────────────────────────
-- §4 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- The IdentifierFormDrift detection function. Returns a verdict table mirroring
-- the Rust `Verdict`: `input`, `classify` (`{ kind, sub, positions, decoded }`),
-- `shift_count`.
function M.detect(input)
  local classify
  local pos, cp = first_status_shift(input)
  if pos ~= nil then
    classify = {
      kind = "Hazard",
      sub = { tag = "IdentifierStatusShift", base_pos = pos, cp = cp },
      positions = { pos },
      decoded = {},
    }
  else
    classify = { kind = "Clear", sub = nil, positions = {}, decoded = {} }
  end

  local input_copy = {}
  if #input > 0 then
    input_copy = { unpack(input) }
  end

  return {
    input = input_copy,
    classify = classify,
    shift_count = status_shift_count(input),
  }
end

-- True iff the verdict's classification is Clear.
function M.is_clear(verdict)
  return verdict.classify.kind == "Clear"
end

-- Human-facing tag for a verdict's classification, or nil when clear. Exhaustive
-- over the sole sub-threat; an unknown tag is a construction bug and raises.
function M.classification_tag(verdict)
  local sub = verdict.classify.sub
  if sub == nil then
    return nil
  end
  local tag = sub.tag
  if tag == "IdentifierStatusShift" then
    return "IdentifierStatusShift"
  else
    error("classification_tag: unknown IdentifierFormDrift sub-threat " .. tostring(tag))
  end
end

-- Implicated positions (empty when clear).
function M.classification_positions(verdict)
  return verdict.classify.positions
end

return M
