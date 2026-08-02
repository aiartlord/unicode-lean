-- Stream-Safe-Text-Format-violation detection (F2) — inputs whose consecutive
-- non-starter run exceeds the UAX #15 §13 stream-safe limit of 30. Such an
-- input (the canonical "Zalgo" shape, a single base codepoint followed by a
-- long combining-mark run) forces unbounded combining-mark buffers in
-- receiver-side streaming normalization (to_nfc / to_nfd / to_nfkc / to_nfkd)
-- and is a known DoS vector.
--
-- Direct port of Unicode/Security/Form/StreamSafeViolation.lean, transliterated
-- byte-faithfully from ports/rust/src/security/form/stream_safe_violation.rs.
-- UAX #15 §13 defines Stream-Safe Text Format as the remediation: insert
-- U+034F COMBINING GRAPHEME JOINER (a starter) after every 30 consecutive
-- non-starters, which bounds the normalization buffer. StreamSafeViolation is
-- the security verdict over the same property — distinct from
-- RendererDivergence's combiningStackOverflow (the cosmetic 4-mark threshold),
-- this is the spec-mandated DoS-prevention bound.
--
-- A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
-- (UAX #15 D49). This module reads CCC from the port's own bundled UCD table
-- via ucd.ccc, never a host normalizer.
--
-- Sub-threat: StreamSafeOverrun (base_pos, run_len) — the first non-starter run
-- whose length exceeds the stream-safe limit. base_pos is the index of that
-- run's first non-starter codepoint.
--
-- Positions follow the reference's zero-based codepoint indexing.

local ucd = require("unicode_lua.security.identity.ucd")

local M = {}

-- ─────────────────────────────────────────────────────────────────────
-- §1 Run inventory
-- ─────────────────────────────────────────────────────────────────────

-- UAX #15 §13 Stream-Safe limit: the maximum number of consecutive
-- non-starters permitted before a COMBINING GRAPHEME JOINER must be inserted.
M.STREAM_SAFE_LIMIT = 30

-- True iff `cp` is a non-starter — a codepoint with non-zero
-- Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0.
local function is_non_starter(cp)
  return ucd.ccc(cp) ~= 0
end

-- Inventory of { start = i, len = n } for every maximal non-starter run in
-- `input`. Mirrors collectRunsGo: a run opens on the first non-starter, its
-- start index is fixed to that codepoint's absolute (zero-based) index, and it
-- closes (emitting its (start, length) pair) on the next starter or at end of
-- input.
local function non_starter_runs(input)
  local runs = {}
  local cur_start = nil
  local cur_len = 0
  for i = 1, #input do
    local cp = input[i]
    local idx = i - 1
    if is_non_starter(cp) then
      if cur_start == nil then
        cur_start = idx
      end
      cur_len = cur_len + 1
    else
      if cur_start ~= nil then
        runs[#runs + 1] = { start = cur_start, len = cur_len }
      end
      cur_start = nil
      cur_len = 0
    end
  end
  if cur_start ~= nil then
    runs[#runs + 1] = { start = cur_start, len = cur_len }
  end
  return runs
end

-- First non-starter run whose length exceeds STREAM_SAFE_LIMIT, as
-- { start = i, len = n }, or nil when none.
local function first_overrun(input)
  local runs = non_starter_runs(input)
  for i = 1, #runs do
    if runs[i].len > M.STREAM_SAFE_LIMIT then
      return runs[i]
    end
  end
  return nil
end

-- Longest non-starter run length in `input`.
local function max_run_len(input)
  local runs = non_starter_runs(input)
  local acc = 0
  for i = 1, #runs do
    if runs[i].len > acc then
      acc = runs[i].len
    end
  end
  return acc
end

-- Number of distinct non-starter runs that exceed STREAM_SAFE_LIMIT.
local function overrun_count(input)
  local runs = non_starter_runs(input)
  local acc = 0
  for i = 1, #runs do
    if runs[i].len > M.STREAM_SAFE_LIMIT then
      acc = acc + 1
    end
  end
  return acc
end

-- Total non-starter codepoints in `input` (sum of all run lengths).
local function total_non_starters(input)
  local runs = non_starter_runs(input)
  local acc = 0
  for i = 1, #runs do
    acc = acc + runs[i].len
  end
  return acc
end

-- ─────────────────────────────────────────────────────────────────────
-- §2 Types
-- ─────────────────────────────────────────────────────────────────────
--
-- SubThreat is represented as { kind = "StreamSafeOverrun", base_pos, run_len }.
-- Classification is represented as { kind = "Clear" } or
--   { kind = "Hazard", sub = <SubThreat>, positions = {..}, decoded = {} }.

-- Human-facing classification tag for a sub-threat.
function M.sub_threat_tag(sub)
  if sub.kind == "StreamSafeOverrun" then
    return "StreamSafeOverrun"
  end
  error("stream_safe_violation: unknown sub-threat kind " .. tostring(sub.kind))
end

-- True iff the classification is clear.
function M.classification_is_clear(classify)
  if classify.kind == "Clear" then
    return true
  elseif classify.kind == "Hazard" then
    return false
  end
  error("stream_safe_violation: unknown classification kind " .. tostring(classify.kind))
end

-- Human-facing tag for a hazard, or nil when clear.
function M.classification_tag(classify)
  if classify.kind == "Clear" then
    return nil
  elseif classify.kind == "Hazard" then
    return M.sub_threat_tag(classify.sub)
  end
  error("stream_safe_violation: unknown classification kind " .. tostring(classify.kind))
end

-- Implicated positions (empty when clear).
function M.classification_positions(classify)
  if classify.kind == "Clear" then
    return {}
  elseif classify.kind == "Hazard" then
    return classify.positions
  end
  error("stream_safe_violation: unknown classification kind " .. tostring(classify.kind))
end

-- ─────────────────────────────────────────────────────────────────────
-- §3 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- The F2 detection function. Fires StreamSafeOverrun on the first non-starter
-- run whose length exceeds STREAM_SAFE_LIMIT. Returns a verdict with the
-- scanned input, the classification, and the run-inventory summaries
-- (max_run_len / overrun_count / total_non_starters) so downstream callers can
-- size the buffer pressure a streaming normalizer would see.
function M.detect(input)
  local run = first_overrun(input)
  local classify
  if run ~= nil then
    classify = {
      kind = "Hazard",
      sub = { kind = "StreamSafeOverrun", base_pos = run.start, run_len = run.len },
      positions = { run.start },
      decoded = {},
    }
  else
    classify = { kind = "Clear" }
  end
  local input_copy = {}
  for i = 1, #input do
    input_copy[i] = input[i]
  end
  return {
    input = input_copy,
    classify = classify,
    max_run_len = max_run_len(input),
    overrun_count = overrun_count(input),
    total_non_starters = total_non_starters(input),
  }
end

return M
