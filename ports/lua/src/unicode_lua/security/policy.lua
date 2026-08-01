local calculus = require("unicode_lua.security.calculus")
local noncharacters = require("unicode_lua.noncharacters")
local utf8_mod = require("unicode_lua.utf8")
local tag_block = require("unicode_lua.security.covert.tag_block_payload")
local variation_selector = require("unicode_lua.security.covert.variation_selector_payload")
local zero_width = require("unicode_lua.security.covert.zero_width_payload")
local surrogate = require("unicode_lua.security.covert.surrogate_reassembly")
local bidi = require("unicode_lua.security.covert.bidi_control_balance")
local homoglyph = require("unicode_lua.security.identity.homoglyph_confusable")
local rtl = require("unicode_lua.security.display.rtl_injection")
local confusable_bidi = require("unicode_lua.security.boundary.confusable_bidi_compound")
local covert_display = require("unicode_lua.security.boundary.covert_display_compound")

local Family = calculus.Family
local Severity = calculus.Severity
local ClassificationKind = calculus.ClassificationKind
local unpack = table.unpack or unpack

local M = {}

M.Action = {
  Allow = "allow",
  Reject = "reject",
  Quarantine = "quarantine",
  Rewrite = "rewrite",
  Observe = "observe",
}

M.Mode = {
  Observe = "observe",
  Warn = "warn",
  Enforce = "enforce",
  Strict = "strict",
}

M.Profile = {
  GatewayHeader = "gateway-header",
  DomainName = "domain-name",
  DnsLabel = "dns-label",
  Url = "url",
  Username = "username",
  DisplayName = "display-name",
  ChatMessage = "chat-message",
  SourceCode = "source-code",
  OpaqueSecret = "opaque-secret",
  BinaryBlob = "binary-blob",
}

local PolicyLevel = {
  Restrictive = "restrictive",
  Moderate = "moderate",
  Minimal = "minimal",
}

local CryptoContext = {
  NonCrypto = "non-crypto",
  Bip39Mnemonic = "bip39-mnemonic",
  HashInput = "hash-input",
  AiAttribution = "ai-attribution",
}

local restrictive = {
  [Family.MalformedUtf8] = true,
  [Family.MalformedUtf16] = true,
  [Family.MalformedUtf32] = true,
  [Family.TagBlockPayload] = true,
  [Family.VariationSelectorPayload] = true,
  [Family.ZeroWidthPayload] = true,
  [Family.SurrogateReassembly] = true,
  [Family.BidiControlBalance] = true,
  [Family.NoncharacterControl] = true,
  [Family.HomoglyphConfusable] = true,
  [Family.MixedScriptAdmissibility] = true,
  [Family.EmojiZwjIntegrity] = true,
  [Family.SkinToneVariationForgery] = true,
  [Family.SourceDisplayDivergence] = true,
  [Family.FilenameDisguise] = true,
  [Family.RtlInjection] = true,
  [Family.RendererDivergence] = true,
  [Family.NormalizationBomb] = true,
  [Family.StreamSafeViolation] = true,
  [Family.LocaleCaseInversion] = true,
  [Family.CaseExpansionMismatch] = true,
  [Family.WidthClassConfusion] = true,
  [Family.NfcIdempotenceWitness] = true,
  [Family.IdentifierFormDrift] = true,
  [Family.CovertDisplayCompound] = true,
  [Family.ConfusableBidiCompound] = true,
  [Family.AdmissibilityFormDrift] = true,
}

local moderate = {
  [Family.MalformedUtf8] = true,
  [Family.MalformedUtf16] = true,
  [Family.MalformedUtf32] = true,
  [Family.TagBlockPayload] = true,
  [Family.VariationSelectorPayload] = true,
  [Family.ZeroWidthPayload] = true,
  [Family.SurrogateReassembly] = true,
  [Family.BidiControlBalance] = true,
  [Family.NoncharacterControl] = true,
  [Family.HomoglyphConfusable] = true,
  [Family.MixedScriptAdmissibility] = true,
  [Family.SkinToneVariationForgery] = true,
  [Family.SourceDisplayDivergence] = true,
  [Family.FilenameDisguise] = true,
  [Family.StreamSafeViolation] = true,
  [Family.LocaleCaseInversion] = true,
  [Family.CaseExpansionMismatch] = true,
  [Family.WidthClassConfusion] = true,
  [Family.NfcIdempotenceWitness] = true,
  [Family.IdentifierFormDrift] = true,
  [Family.CovertDisplayCompound] = true,
  [Family.ConfusableBidiCompound] = true,
  [Family.AdmissibilityFormDrift] = true,
}

local minimal = {
  [Family.MalformedUtf8] = true,
  [Family.MalformedUtf16] = true,
  [Family.MalformedUtf32] = true,
  [Family.SurrogateReassembly] = true,
  [Family.BidiControlBalance] = true,
  [Family.NoncharacterControl] = true,
  [Family.StreamSafeViolation] = true,
}

local layer = {
  [Family.MalformedUtf8] = "C",
  [Family.MalformedUtf16] = "C",
  [Family.MalformedUtf32] = "C",
  [Family.TagBlockPayload] = "C",
  [Family.VariationSelectorPayload] = "C",
  [Family.ZeroWidthPayload] = "C",
  [Family.SurrogateReassembly] = "C",
  [Family.BidiControlBalance] = "C",
  [Family.NoncharacterControl] = "C",
  [Family.HomoglyphConfusable] = "I",
  [Family.MixedScriptAdmissibility] = "I",
  [Family.EmojiZwjIntegrity] = "I",
  [Family.SkinToneVariationForgery] = "I",
  [Family.SourceDisplayDivergence] = "D",
  [Family.FilenameDisguise] = "D",
  [Family.RtlInjection] = "D",
  [Family.RendererDivergence] = "D",
  [Family.NormalizationBomb] = "F",
  [Family.StreamSafeViolation] = "F",
  [Family.LocaleCaseInversion] = "F",
  [Family.CaseExpansionMismatch] = "F",
  [Family.WidthClassConfusion] = "F",
  [Family.NfcIdempotenceWitness] = "F",
  [Family.IdentifierFormDrift] = "X",
  [Family.CovertDisplayCompound] = "X",
  [Family.ConfusableBidiCompound] = "X",
  [Family.AdmissibilityFormDrift] = "X",
}

local function sub_tag(sub)
  if sub == nil then
    return nil
  end
  if type(sub) == "table" then
    return sub.tag
  end
  return sub
end

function M.family_slug(family)
  return family
end

function M.family_layer_code(family)
  return layer[family] or "K"
end

function M.reason_code(family, sub)
  return "unicode.security." .. M.family_layer_code(family) .. "." .. family .. "." .. (sub or "hazard")
end

local function policy_of_profile(profile)
  if profile == M.Profile.GatewayHeader or profile == M.Profile.DomainName or profile == M.Profile.DnsLabel or profile == M.Profile.SourceCode then
    return { level = PolicyLevel.Restrictive, crypto_context = CryptoContext.NonCrypto, quarantine = false }
  elseif profile == M.Profile.Url then
    return { level = PolicyLevel.Moderate, crypto_context = CryptoContext.NonCrypto, quarantine = false }
  elseif profile == M.Profile.Username then
    return { level = PolicyLevel.Moderate, crypto_context = CryptoContext.NonCrypto, quarantine = true }
  elseif profile == M.Profile.DisplayName or profile == M.Profile.ChatMessage then
    return { level = PolicyLevel.Minimal, crypto_context = CryptoContext.NonCrypto, quarantine = true }
  elseif profile == M.Profile.OpaqueSecret then
    return { level = PolicyLevel.Minimal, crypto_context = CryptoContext.HashInput, quarantine = false }
  end
  return { level = PolicyLevel.Minimal, crypto_context = CryptoContext.NonCrypto, quarantine = false }
end
M.policy_of_profile = policy_of_profile

local function rejection_set(level)
  if level == PolicyLevel.Restrictive then
    return restrictive
  elseif level == PolicyLevel.Moderate then
    return moderate
  end
  return minimal
end

local function family_blocks(profile, family)
  return rejection_set(policy_of_profile(profile).level)[family] == true
end
M.family_blocks = family_blocks

local function select_action(profile, mode, findings)
  local has_findings = #findings > 0
  local has_blocking = false
  for _, finding in ipairs(findings) do
    if family_blocks(profile, finding.family) then
      has_blocking = true
      break
    end
  end
  if mode == M.Mode.Observe or mode == M.Mode.Warn then
    return has_findings and M.Action.Observe or M.Action.Allow
  elseif mode == M.Mode.Enforce then
    if not has_blocking then
      return M.Action.Allow
    end
    return policy_of_profile(profile).quarantine and M.Action.Quarantine or M.Action.Reject
  elseif mode == M.Mode.Strict then
    return has_findings and M.Action.Reject or M.Action.Allow
  end
  error("select_action: unknown mode " .. tostring(mode))
end
M.select_action = select_action

local function push_finding(findings, family, kind, sub, positions)
  if kind == ClassificationKind.Clear then
    return
  end
  local tag = sub_tag(sub)
  findings[#findings + 1] = {
    code = M.reason_code(family, tag),
    family = family,
    severity = kind == ClassificationKind.Compound and Severity.High or (kind == ClassificationKind.Hazard and Severity.Moderate or Severity.Informational),
    positions = positions,
    sub_threat = tag,
    detail = family,
  }
end

local function push_positional_hazard(findings, family, sub, positions)
  if #positions > 0 then
    push_finding(findings, family, ClassificationKind.Hazard, sub, positions)
  end
end

local function positions_where(input, pred)
  local out = {}
  for i = 1, #input do
    if pred(input[i]) then
      out[#out + 1] = i - 1
    end
  end
  return out
end

local function c0_control(cp)
  return (cp >= 0 and cp <= 0x1F and cp ~= 0x09 and cp ~= 0x0A and cp ~= 0x0D) or cp == 0x7F
end

local function c1_control(cp)
  return cp >= 0x80 and cp <= 0x9F
end

function M.scan(profile, mode, input)
  local findings = {}

  local tag = tag_block.detect(input)
  push_finding(findings, Family.TagBlockPayload, tag.kind, tag.sub, tag.tag_positions)

  local vs = variation_selector.detect(input)
  push_finding(findings, Family.VariationSelectorPayload, vs.kind, vs.sub, vs.vs_positions)

  local zw = zero_width.detect(input)
  push_finding(findings, Family.ZeroWidthPayload, zw.kind, zw.sub, zw.zero_width_positions)

  if surrogate.looks_like_byte_stream(input) then
    local sr = surrogate.detect(input)
    if sr.sub ~= nil then
      push_finding(findings, Family.SurrogateReassembly, ClassificationKind.Hazard, sr.sub, sr.positions)
    end
  end

  local b = bidi.detect(input)
  push_finding(findings, Family.BidiControlBalance, b.kind, b.sub, b.bidi_positions)

  push_positional_hazard(findings, Family.NoncharacterControl, "Noncharacter", positions_where(input, noncharacters.is_noncharacter))
  push_positional_hazard(findings, Family.NoncharacterControl, "C0Control", positions_where(input, c0_control))
  push_positional_hazard(findings, Family.NoncharacterControl, "C1Control", positions_where(input, c1_control))

  local h = homoglyph.detect(input)
  local htag = sub_tag(h.sub)
  if htag ~= "CrossScriptMix" then
    local positions = {}
    if h.kind ~= ClassificationKind.Clear then
      for i = 1, #input do
        positions[#positions + 1] = i - 1
      end
    end
    push_finding(findings, Family.HomoglyphConfusable, h.kind, h.sub, positions)
  end
  if homoglyph.has_mixed_script_admissibility(input) then
    local positions = {}
    for i = 1, #input do
      positions[#positions + 1] = i - 1
    end
    push_finding(findings, Family.MixedScriptAdmissibility, ClassificationKind.Hazard, homoglyph.mixed_script_subthreat(input), positions)
  end

  local r = rtl.detect(input)
  if r.sub ~= nil then
    push_finding(findings, Family.RtlInjection, ClassificationKind.Hazard, r.sub, r.positions)
  end

  local cb = confusable_bidi.detect(input)
  if cb.sub ~= nil then
    push_finding(findings, Family.ConfusableBidiCompound, ClassificationKind.Hazard, cb.sub, cb.positions)
  end

  local cd = covert_display.detect(input)
  if cd.sub ~= nil then
    push_finding(findings, Family.CovertDisplayCompound, ClassificationKind.Hazard, cd.sub, cd.positions)
  end

  return { input = { unpack(input) }, profile = profile, mode = mode, action = select_action(profile, mode, findings), findings = findings, normalized = nil }
end

local function malformed_decode_verdict(profile, mode, family, sub, offset)
  local findings = {
    { code = M.reason_code(family, sub), family = family, severity = Severity.Moderate, positions = { offset }, sub_threat = sub, detail = family },
  }
  return { input = {}, profile = profile, mode = mode, action = select_action(profile, mode, findings), findings = findings, normalized = nil }
end

function M.scan_utf8(profile, mode, bytes)
  local offset, kind = utf8_mod.first_invalid_utf8_offset(bytes)
  if offset ~= nil then
    return malformed_decode_verdict(profile, mode, Family.MalformedUtf8, kind, offset)
  end
  return M.scan(profile, mode, utf8_mod.decode_to_codepoints(bytes))
end

local function read_u16(bytes, offset, endian)
  if endian == "big" then
    return bytes[offset + 1] * 0x100 + bytes[offset + 2]
  end
  return bytes[offset + 1] + bytes[offset + 2] * 0x100
end

local function read_u32(bytes, offset, endian)
  if endian == "big" then
    return bytes[offset + 1] * 0x1000000 + bytes[offset + 2] * 0x10000 + bytes[offset + 3] * 0x100 + bytes[offset + 4]
  end
  return bytes[offset + 1] + bytes[offset + 2] * 0x100 + bytes[offset + 3] * 0x10000 + bytes[offset + 4] * 0x1000000
end

local function decode_utf16_stream(bytes, endian)
  local input = {}
  local offset = 0
  while offset < #bytes do
    if offset + 2 > #bytes then
      return nil, "TruncatedCodeUnit", #bytes
    end
    local unit = read_u16(bytes, offset, endian)
    local unit_offset = offset
    offset = offset + 2
    if unit >= 0xD800 and unit <= 0xDBFF then
      if offset + 2 > #bytes then
        return nil, "TruncatedSurrogatePair", #bytes
      end
      local low = read_u16(bytes, offset, endian)
      if low < 0xDC00 or low > 0xDFFF then
        return nil, "InvalidSurrogatePair", offset
      end
      input[#input + 1] = 0x10000 + (unit - 0xD800) * 0x400 + (low - 0xDC00)
      offset = offset + 2
    elseif unit >= 0xDC00 and unit <= 0xDFFF then
      return nil, "LoneSurrogate", unit_offset
    else
      input[#input + 1] = unit
    end
  end
  return input, nil, nil
end

local function decode_utf32_stream(bytes, endian)
  if #bytes % 4 ~= 0 then
    return nil, "TruncatedCodeUnit", #bytes
  end
  local input = {}
  for offset = 0, #bytes - 1, 4 do
    local cp = read_u32(bytes, offset, endian)
    if cp >= 0xD800 and cp <= 0xDFFF then
      return nil, "SurrogateCodepoint", offset
    end
    if cp > 0x10FFFF then
      return nil, "CodepointBeyondMax", offset
    end
    input[#input + 1] = cp
  end
  return input, nil, nil
end

local function scan_utf16(profile, mode, bytes, endian)
  local input, sub, offset = decode_utf16_stream(bytes, endian)
  if input == nil then
    return malformed_decode_verdict(profile, mode, Family.MalformedUtf16, sub, offset)
  end
  return M.scan(profile, mode, input)
end

local function scan_utf32(profile, mode, bytes, endian)
  local input, sub, offset = decode_utf32_stream(bytes, endian)
  if input == nil then
    return malformed_decode_verdict(profile, mode, Family.MalformedUtf32, sub, offset)
  end
  return M.scan(profile, mode, input)
end

function M.scan_utf16be(profile, mode, bytes) return scan_utf16(profile, mode, bytes, "big") end
function M.scan_utf16le(profile, mode, bytes) return scan_utf16(profile, mode, bytes, "little") end
function M.scan_utf32be(profile, mode, bytes) return scan_utf32(profile, mode, bytes, "big") end
function M.scan_utf32le(profile, mode, bytes) return scan_utf32(profile, mode, bytes, "little") end
function M.scan_default(profile, input) return M.scan(profile, M.Mode.Enforce, input) end

function M.finding_to_wire(finding)
  return {
    code = finding.code,
    family = finding.family,
    severity = finding.severity,
    positions = finding.positions,
    sub_threat = finding.sub_threat,
    detail = finding.detail,
  }
end

function M.verdict_to_wire(verdict)
  local findings = {}
  for _, finding in ipairs(verdict.findings) do
    findings[#findings + 1] = M.finding_to_wire(finding)
  end
  return {
    action = verdict.action,
    profile = verdict.profile,
    mode = verdict.mode,
    input = verdict.input,
    findings = findings,
    normalized = verdict.normalized,
  }
end

return M
