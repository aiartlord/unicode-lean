-- hash-input-stability — detection of inputs that are not in canonical
-- hash-input form. Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an input
-- hashed by a signer must be byte-identical to the input hashed by the
-- verifier; if the two ends pick different canonical forms (NFC vs NFD, trim
-- policy, line-ending convention) the resulting hashes diverge silently while
-- both sides believe they signed the same content.
--
-- Direct port of `Unicode/Security/Crypto/HashInputStability.lean` via the
-- verified Rust reference `hash_input_stability.rs`. The canonical
-- (hash-stable) form is `trim_trailing(to_nfc(input))`, where `trim_trailing`
-- strips only ASCII whitespace {U+0020, U+0009, U+000A, U+000D}; Unicode
-- whitespace (U+00A0, U+2000..U+200A, U+3000) is content and is not stripped.
-- NFC is the port's `ucd.to_nfc`, never a host normalizer.
--
-- Six probes run in strict priority order (first hit wins):
--
--   1. encodingMismatch         (context: declared_encoding)
--   2. webhookSignatureDrift    (context: server_bytes)
--   3. auditLogReinterpretation (context: as_written)
--   4. signedMessageRule        (context: rfc_rule)
--   5. trailingWhitespace       (bare input)
--   6. normalizationDrift       (bare input)
--   7. clear
--
-- Context-specific probes fire first because they carry more precise threat
-- information than the generic probes. `detect` is the convenience wrapper
-- `detect_with_context({}, input)` that leaves the four context-bearing probes
-- silent.

local ucd = require("unicode_lua.security.identity.ucd")

local M = {}

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- RFC canonicalisation profiles that the `signedMessageRule` probe checks
-- against. Each value is its own fixture-string tag (interned), so `tag` is
-- the identity and `from_tag` is a validity check.
M.RfcRule = {
  Pgp4880TrailingWhitespace = "pgp4880TrailingWhitespace",
  Pgp9580LineEnding = "pgp9580LineEnding",
  Rfc8785NfcRequirement = "rfc8785NfcRequirement",
  Rfc8259ControlChar = "rfc8259ControlChar",
  Rfc7515JwsBase64Url = "rfc7515JwsBase64Url",
  Rfc6376DkimRelaxed = "rfc6376DkimRelaxed",
  Rfc5751SmimeLineEnding = "rfc5751SmimeLineEnding",
}

local RFC_RULE_TAGS = {
  [M.RfcRule.Pgp4880TrailingWhitespace] = true,
  [M.RfcRule.Pgp9580LineEnding] = true,
  [M.RfcRule.Rfc8785NfcRequirement] = true,
  [M.RfcRule.Rfc8259ControlChar] = true,
  [M.RfcRule.Rfc7515JwsBase64Url] = true,
  [M.RfcRule.Rfc6376DkimRelaxed] = true,
  [M.RfcRule.Rfc5751SmimeLineEnding] = true,
}

-- Fixture-string identifier for an `RfcRule`.
function M.rfc_rule_tag(rule)
  if RFC_RULE_TAGS[rule] then
    return rule
  end
  error("rfc_rule_tag: unknown rule " .. tostring(rule))
end

-- Inverse of `rfc_rule_tag`. Returns nil for unrecognised strings.
function M.rfc_rule_from_tag(tag)
  if RFC_RULE_TAGS[tag] then
    return tag
  end
  return nil
end

-- ─────────────────────────────────────────────────────────────────────
-- §3 Canonicalisation pipeline
-- ─────────────────────────────────────────────────────────────────────

-- True iff `cp` is an ASCII whitespace codepoint that line-oriented hash-input
-- protocols treat as framing rather than content: U+0020 SPACE, U+0009 TAB,
-- U+000A LF, U+000D CR.
local function is_ascii_whitespace(cp)
  return cp == 0x0020 or cp == 0x0009 or cp == 0x000A or cp == 0x000D
end

-- Count of trailing ASCII whitespace codepoints in `input`.
local function count_trailing_whitespace(input)
  local count = 0
  for i = #input, 1, -1 do
    if not is_ascii_whitespace(input[i]) then
      break
    end
    count = count + 1
  end
  return count
end

-- Strip trailing ASCII whitespace.
local function trim_trailing(input)
  local keep = #input - count_trailing_whitespace(input)
  local out = {}
  for i = 1, keep do
    out[i] = input[i]
  end
  return out
end

-- The hash-stable form of an input: NFC then trim, in spec order.
function M.hash_stable(input)
  return trim_trailing(ucd.to_nfc(input))
end

-- ─────────────────────────────────────────────────────────────────────
-- §5 Priority position-finder
-- ─────────────────────────────────────────────────────────────────────

-- First position at which `a` and `b` diverge, or the length of the shared
-- prefix when one strictly extends the other. nil when identical. Positions
-- are 0-based to mirror the reference.
local function first_array_divergence(a, b)
  local common = math.min(#a, #b)
  for i = 1, common do
    if a[i] ~= b[i] then
      return i - 1
    end
  end
  if #a ~= #b then
    return common
  end
  return nil
end

local function arrays_equal(a, b)
  return first_array_divergence(a, b) == nil
end

-- ─────────────────────────────────────────────────────────────────────
-- §6 Context-bearing probes
-- ─────────────────────────────────────────────────────────────────────

-- Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A).
local function ascii_lower_byte(b)
  if b >= 0x41 and b <= 0x5A then
    return b + 0x20
  end
  return b
end

-- True iff `label` (after ASCII case-fold) names UTF-8: accepts "utf-8",
-- "UTF-8", "UTF8", "utf8". Non-ASCII bytes pass through unchanged.
local function is_utf8_label(label)
  local bytes = {}
  for i = 1, #label do
    bytes[i] = string.char(ascii_lower_byte(label:byte(i)))
  end
  local normalised = table.concat(bytes)
  return normalised == "utf-8" or normalised == "utf8"
end

-- True iff `cp` is a valid Unicode scalar value: in [0, 0x10FFFF] and not a
-- surrogate [0xD800, 0xDFFF].
local function is_valid_scalar(cp)
  return cp <= 0x10FFFF and not (cp >= 0xD800 and cp <= 0xDFFF)
end

-- First position in `input` holding a codepoint that is not a valid Unicode
-- scalar, or nil if every codepoint is valid.
local function first_invalid_scalar(input)
  for i = 1, #input do
    if not is_valid_scalar(input[i]) then
      return i - 1
    end
  end
  return nil
end

-- Probe: encodingMismatch. Validity is dispatched first — an invalid scalar
-- fires with detected_enc = "invalid" regardless of the declared label;
-- otherwise a non-UTF-8 label fires with detected_enc = "utf-8" at position 0.
-- Returns { declared, detected, first_pos } when firing, else nil.
local function encoding_mismatch_probe(declared, input)
  local pos = first_invalid_scalar(input)
  if pos ~= nil then
    return { declared = declared, detected = "invalid", first_pos = pos }
  end
  if is_utf8_label(declared) then
    return nil
  end
  return { declared = declared, detected = "utf-8", first_pos = 0 }
end

-- Probe: signedMessageRule for pgp4880TrailingWhitespace. Same condition as
-- trailingWhitespace; returns the first position of the trailing run.
local function pgp4880_violation(input)
  local trailing = count_trailing_whitespace(input)
  if trailing > 0 then
    return #input - trailing
  end
  return nil
end

-- Probe: signedMessageRule for pgp9580LineEnding. First bare LF (U+000A not
-- preceded by CR) or bare CR (U+000D not followed by LF).
local function pgp9580_violation(input)
  for i = 1, #input do
    local cp = input[i]
    if cp == 0x000A then
      local preceded_by_cr = i > 1 and input[i - 1] == 0x000D
      if not preceded_by_cr then
        return i - 1
      end
    elseif cp == 0x000D then
      local followed_by_lf = i < #input and input[i + 1] == 0x000A
      if not followed_by_lf then
        return i - 1
      end
    end
  end
  return nil
end

-- Probe: signedMessageRule for rfc8785NfcRequirement. Same condition as
-- normalizationDrift; returns the first NFC divergence position.
local function rfc8785_violation(input)
  local nfc = ucd.to_nfc(input)
  if arrays_equal(input, nfc) then
    return nil
  end
  return first_array_divergence(input, nfc)
end

-- Probe: signedMessageRule for rfc8259ControlChar. First C0 control
-- (U+0000..U+001F).
local function rfc8259_violation(input)
  for i = 1, #input do
    if input[i] <= 0x1F then
      return i - 1
    end
  end
  return nil
end

-- True iff `cp` is in the JWS Base64URL alphabet [A-Za-z0-9_-].
local function is_base64_url(cp)
  return (cp >= 0x41 and cp <= 0x5A) -- A-Z
    or (cp >= 0x61 and cp <= 0x7A) -- a-z
    or (cp >= 0x30 and cp <= 0x39) -- 0-9
    or cp == 0x2D -- '-'
    or cp == 0x5F -- LOW LINE
end

-- Probe: signedMessageRule for rfc7515JwsBase64Url. First codepoint outside
-- [A-Za-z0-9_-].
local function rfc7515_violation(input)
  for i = 1, #input do
    if not is_base64_url(input[i]) then
      return i - 1
    end
  end
  return nil
end

-- True iff `cp` is DKIM whitespace: U+0020 SPACE or U+0009 HTAB.
local function is_dkim_whitespace(cp)
  return cp == 0x20 or cp == 0x09
end

-- Probe: signedMessageRule for rfc6376DkimRelaxed. Position of the second
-- whitespace codepoint in the first internal whitespace run longer than one.
local function rfc6376_violation(input)
  for i = 1, #input do
    if is_dkim_whitespace(input[i]) and i > 1 and is_dkim_whitespace(input[i - 1]) then
      return i - 1
    end
  end
  return nil
end

-- Probe: signedMessageRule for rfc5751SmimeLineEnding. Reuses the PGP 9580
-- bare-line-ending rule.
local function rfc5751_violation(input)
  return pgp9580_violation(input)
end

-- Dispatch the RFC-rule probe. First violation position, or nil if clean.
local function rfc_rule_violation(rule, input)
  if rule == M.RfcRule.Pgp4880TrailingWhitespace then
    return pgp4880_violation(input)
  elseif rule == M.RfcRule.Pgp9580LineEnding then
    return pgp9580_violation(input)
  elseif rule == M.RfcRule.Rfc8785NfcRequirement then
    return rfc8785_violation(input)
  elseif rule == M.RfcRule.Rfc8259ControlChar then
    return rfc8259_violation(input)
  elseif rule == M.RfcRule.Rfc7515JwsBase64Url then
    return rfc7515_violation(input)
  elseif rule == M.RfcRule.Rfc6376DkimRelaxed then
    return rfc6376_violation(input)
  elseif rule == M.RfcRule.Rfc5751SmimeLineEnding then
    return rfc5751_violation(input)
  end
  error("rfc_rule_violation: unknown rule " .. tostring(rule))
end

-- ─────────────────────────────────────────────────────────────────────
-- §7 Priority resolver
-- ─────────────────────────────────────────────────────────────────────

-- The priority resolver: first hit wins, in the spec's fixed order. Returns a
-- classification { kind, sub, positions } where `sub` is a sub-threat table
-- carrying its `tag`, or the clear verdict when no probe fires.
local function classify(encoding_hit, webhook_hit, audit_hit, rfc_hit, trailing_count, input_len, non_nfc_pos)
  if encoding_hit ~= nil then
    return {
      kind = "hazard",
      sub = {
        tag = "EncodingMismatch",
        declared_enc = encoding_hit.declared,
        detected_enc = encoding_hit.detected,
      },
      positions = { encoding_hit.first_pos },
    }
  end
  if webhook_hit ~= nil then
    return {
      kind = "hazard",
      sub = { tag = "WebhookSignatureDrift", first_pos = webhook_hit },
      positions = { webhook_hit },
    }
  end
  if audit_hit ~= nil then
    return {
      kind = "hazard",
      sub = { tag = "AuditLogReinterpretation", first_divergent_pos = audit_hit },
      positions = { audit_hit },
    }
  end
  if rfc_hit ~= nil then
    return {
      kind = "hazard",
      sub = { tag = "SignedMessageRule", rfc_rule = rfc_hit.rule, first_pos = rfc_hit.pos },
      positions = { rfc_hit.pos },
    }
  end
  if trailing_count > 0 then
    local p = input_len - trailing_count
    return {
      kind = "hazard",
      sub = { tag = "TrailingWhitespace", count = trailing_count },
      positions = { p },
    }
  end
  if non_nfc_pos ~= nil then
    return {
      kind = "hazard",
      sub = { tag = "NormalizationDrift", first_divergent_pos = non_nfc_pos },
      positions = { non_nfc_pos },
    }
  end
  return { kind = "clear", sub = nil, positions = {} }
end

-- ─────────────────────────────────────────────────────────────────────
-- §8 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- The full detection function. Runs all six probes in priority order, with the
-- context-bearing probes ahead of the generic ones. `ctx` carries optional
-- fields: declared_encoding, rfc_rule, as_written, server_bytes.
function M.detect_with_context(ctx, input)
  local stable = M.hash_stable(input)

  -- Probe 1: encodingMismatch.
  local encoding_hit = nil
  if ctx.declared_encoding ~= nil then
    encoding_hit = encoding_mismatch_probe(ctx.declared_encoding, input)
  end

  -- Probe 2: webhookSignatureDrift.
  local webhook_hit = nil
  if ctx.server_bytes ~= nil then
    webhook_hit = first_array_divergence(input, ctx.server_bytes)
  end

  -- Probe 3: auditLogReinterpretation.
  local audit_hit = nil
  if ctx.as_written ~= nil then
    audit_hit = first_array_divergence(ctx.as_written, input)
  end

  -- Probe 4: signedMessageRule.
  local rfc_hit = nil
  if ctx.rfc_rule ~= nil then
    local pos = rfc_rule_violation(ctx.rfc_rule, input)
    if pos ~= nil then
      rfc_hit = { rule = ctx.rfc_rule, pos = pos }
    end
  end

  -- Probe 5: trailingWhitespace.
  local trailing_count = count_trailing_whitespace(input)

  -- Probe 6: normalizationDrift.
  local nfc = ucd.to_nfc(input)
  local non_nfc_pos = nil
  if not arrays_equal(input, nfc) then
    non_nfc_pos = first_array_divergence(input, nfc)
  end

  local classification = classify(encoding_hit, webhook_hit, audit_hit, rfc_hit, trailing_count, #input, non_nfc_pos)

  local input_copy = {}
  for i = 1, #input do
    input_copy[i] = input[i]
  end

  return {
    input = input_copy,
    classify = classification,
    stable_form = stable,
    stable_size = #stable,
  }
end

-- Convenience wrapper over `detect_with_context` with the empty context —
-- equivalent to running only the two bare-input probes (trailingWhitespace,
-- normalizationDrift).
function M.detect(input)
  return M.detect_with_context({}, input)
end

-- Human-facing tag for a verdict's classification, or nil when clear.
function M.classification_tag(verdict)
  if verdict.classify.sub == nil then
    return nil
  end
  return verdict.classify.sub.tag
end

return M
