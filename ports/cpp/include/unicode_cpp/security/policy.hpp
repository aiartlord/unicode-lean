// Product-facing security policy contract.
//
// Mirrors Unicode.Security.Policy: named profiles, runtime modes,
// stable reason codes, and scan verdicts over decoded codepoints.

#ifndef UNICODE_CPP_SECURITY_POLICY_HPP
#define UNICODE_CPP_SECURITY_POLICY_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "unicode_cpp/noncharacters.hpp"
#include "unicode_cpp/security/boundary/confusable_bidi_compound.hpp"
#include "unicode_cpp/security/boundary/covert_display_compound.hpp"
#include "unicode_cpp/security/calculus.hpp"
#include "unicode_cpp/security/covert/bidi_control_balance.hpp"
#include "unicode_cpp/security/covert/surrogate_reassembly.hpp"
#include "unicode_cpp/security/covert/tag_block_payload.hpp"
#include "unicode_cpp/security/covert/variation_selector_payload.hpp"
#include "unicode_cpp/security/covert/zero_width_payload.hpp"
#include "unicode_cpp/security/display/rtl_injection.hpp"
#include "unicode_cpp/security/identity/homoglyph_confusable.hpp"
#include "unicode_cpp/security/identity/skin_tone_variation_forgery.hpp"
#include "unicode_cpp/security/identity/emoji_zwj_integrity.hpp"
#include "unicode_cpp/security/form/width_class_confusion.hpp"
#include "unicode_cpp/security/form/stream_safe_violation.hpp"
#include "unicode_cpp/security/form/normalization_bomb.hpp"
#include "unicode_cpp/security/form/nfc_idempotence_witness.hpp"
#include "unicode_cpp/security/form/locale_case_inversion.hpp"
#include "unicode_cpp/security/form/case_expansion_mismatch.hpp"
#include "unicode_cpp/security/display/source_display_divergence.hpp"
#include "unicode_cpp/security/display/renderer_divergence.hpp"
#include "unicode_cpp/security/display/filename_disguise.hpp"
#include "unicode_cpp/security/boundary/identifier_form_drift.hpp"
#include "unicode_cpp/security/boundary/admissibility_form_drift.hpp"
#include "unicode_cpp/utf8.hpp"

namespace unicode_cpp::security::policy {

enum class Action : std::uint8_t {
  Allow,
  Reject,
  Quarantine,
  Rewrite,
  Observe,
};

constexpr std::string_view tag(Action action) {
  switch (action) {
  case Action::Allow:
    return "allow";
  case Action::Reject:
    return "reject";
  case Action::Quarantine:
    return "quarantine";
  case Action::Rewrite:
    return "rewrite";
  case Action::Observe:
    return "observe";
  }
  return "observe";
}

enum class Mode : std::uint8_t {
  Observe,
  Warn,
  Enforce,
  Strict,
};

constexpr std::string_view tag(Mode mode) {
  switch (mode) {
  case Mode::Observe:
    return "observe";
  case Mode::Warn:
    return "warn";
  case Mode::Enforce:
    return "enforce";
  case Mode::Strict:
    return "strict";
  }
  return "enforce";
}

enum class Profile : std::uint8_t {
  GatewayHeader,
  DomainName,
  DnsLabel,
  Url,
  Username,
  DisplayName,
  ChatMessage,
  SourceCode,
  OpaqueSecret,
  BinaryBlob,
};

constexpr std::string_view tag(Profile profile) {
  switch (profile) {
  case Profile::GatewayHeader:
    return "gateway-header";
  case Profile::DomainName:
    return "domain-name";
  case Profile::DnsLabel:
    return "dns-label";
  case Profile::Url:
    return "url";
  case Profile::Username:
    return "username";
  case Profile::DisplayName:
    return "display-name";
  case Profile::ChatMessage:
    return "chat-message";
  case Profile::SourceCode:
    return "source-code";
  case Profile::OpaqueSecret:
    return "opaque-secret";
  case Profile::BinaryBlob:
    return "binary-blob";
  }
  return "gateway-header";
}

enum class PolicyLevel : std::uint8_t {
  Restrictive,
  Moderate,
  Minimal,
};

enum class CryptoContext : std::uint8_t {
  NonCrypto,
  Bip39Mnemonic,
  HashInput,
  AiAttribution,
};

struct ProfilePolicy {
  PolicyLevel level;
  CryptoContext crypto_context;
  bool quarantine;
};

struct Finding {
  std::string code;
  Family family;
  Severity severity;
  std::vector<std::size_t> positions;
  std::optional<std::string> sub_threat;
  std::string detail;
};

struct Verdict {
  std::vector<std::uint32_t> input;
  Profile profile;
  Mode mode;
  Action action;
  std::vector<Finding> findings;
  std::optional<std::vector<std::uint32_t>> normalized;
};

inline std::span<const Family> rejection_set(PolicyLevel level) {
  static constexpr std::array<Family, 27> restrictive = {
      Family::MalformedUtf8,
      Family::MalformedUtf16,
      Family::MalformedUtf32,
      Family::TagBlockPayload,
      Family::VariationSelectorPayload,
      Family::ZeroWidthPayload,
      Family::SurrogateReassembly,
      Family::BidiControlBalance,
      Family::NoncharacterControl,
      Family::HomoglyphConfusable,
      Family::MixedScriptAdmissibility,
      Family::EmojiZwjIntegrity,
      Family::SkinToneVariationForgery,
      Family::SourceDisplayDivergence,
      Family::FilenameDisguise,
      Family::RtlInjection,
      Family::RendererDivergence,
      Family::NormalizationBomb,
      Family::StreamSafeViolation,
      Family::LocaleCaseInversion,
      Family::CaseExpansionMismatch,
      Family::WidthClassConfusion,
      Family::NfcIdempotenceWitness,
      Family::IdentifierFormDrift,
      Family::CovertDisplayCompound,
      Family::ConfusableBidiCompound,
      Family::AdmissibilityFormDrift,
  };
  static constexpr std::array<Family, 23> moderate = {
      Family::MalformedUtf8,
      Family::MalformedUtf16,
      Family::MalformedUtf32,
      Family::TagBlockPayload,
      Family::VariationSelectorPayload,
      Family::ZeroWidthPayload,
      Family::SurrogateReassembly,
      Family::BidiControlBalance,
      Family::NoncharacterControl,
      Family::HomoglyphConfusable,
      Family::MixedScriptAdmissibility,
      Family::SkinToneVariationForgery,
      Family::SourceDisplayDivergence,
      Family::FilenameDisguise,
      Family::StreamSafeViolation,
      Family::LocaleCaseInversion,
      Family::CaseExpansionMismatch,
      Family::WidthClassConfusion,
      Family::NfcIdempotenceWitness,
      Family::IdentifierFormDrift,
      Family::CovertDisplayCompound,
      Family::ConfusableBidiCompound,
      Family::AdmissibilityFormDrift,
  };
  static constexpr std::array<Family, 7> minimal = {
      Family::MalformedUtf8,       Family::MalformedUtf16,
      Family::MalformedUtf32,      Family::SurrogateReassembly,
      Family::BidiControlBalance,  Family::NoncharacterControl,
      Family::StreamSafeViolation,
  };

  switch (level) {
  case PolicyLevel::Restrictive:
    return restrictive;
  case PolicyLevel::Moderate:
    return moderate;
  case PolicyLevel::Minimal:
    return minimal;
  }
  return minimal;
}

inline std::span<const Family> crypto_families(CryptoContext context) {
  static constexpr std::array<Family, 0> none = {};
  static constexpr std::array<Family, 1> bip39 = {
      Family::Bip39Canonical,
  };
  static constexpr std::array<Family, 1> hash = {
      Family::HashInputStability,
  };
  static constexpr std::array<Family, 1> ai = {
      Family::AiWatermarkDetectability,
  };

  switch (context) {
  case CryptoContext::NonCrypto:
    return none;
  case CryptoContext::Bip39Mnemonic:
    return bip39;
  case CryptoContext::HashInput:
    return hash;
  case CryptoContext::AiAttribution:
    return ai;
  }
  return none;
}

constexpr ProfilePolicy policy_of_profile(Profile profile) {
  switch (profile) {
  case Profile::GatewayHeader:
  case Profile::DomainName:
  case Profile::DnsLabel:
  case Profile::SourceCode:
    return {
        PolicyLevel::Restrictive,
        CryptoContext::NonCrypto,
        false,
    };
  case Profile::Url:
    return {PolicyLevel::Moderate, CryptoContext::NonCrypto, false};
  case Profile::Username:
    return {PolicyLevel::Moderate, CryptoContext::NonCrypto, true};
  case Profile::DisplayName:
  case Profile::ChatMessage:
    return {PolicyLevel::Minimal, CryptoContext::NonCrypto, true};
  case Profile::OpaqueSecret:
    return {PolicyLevel::Minimal, CryptoContext::HashInput, false};
  case Profile::BinaryBlob:
    return {PolicyLevel::Minimal, CryptoContext::NonCrypto, false};
  }
  return {PolicyLevel::Restrictive, CryptoContext::NonCrypto, false};
}

constexpr std::string_view family_layer_code(Family family) {
  switch (family) {
  case Family::MalformedUtf8:
  case Family::MalformedUtf16:
  case Family::MalformedUtf32:
  case Family::TagBlockPayload:
  case Family::VariationSelectorPayload:
  case Family::ZeroWidthPayload:
  case Family::SurrogateReassembly:
  case Family::BidiControlBalance:
  case Family::NoncharacterControl:
    return "C";
  case Family::HomoglyphConfusable:
  case Family::MixedScriptAdmissibility:
  case Family::EmojiZwjIntegrity:
  case Family::SkinToneVariationForgery:
    return "I";
  case Family::SourceDisplayDivergence:
  case Family::FilenameDisguise:
  case Family::RtlInjection:
  case Family::RendererDivergence:
    return "D";
  case Family::NormalizationBomb:
  case Family::StreamSafeViolation:
  case Family::LocaleCaseInversion:
  case Family::CaseExpansionMismatch:
  case Family::WidthClassConfusion:
  case Family::NfcIdempotenceWitness:
    return "F";
  case Family::IdentifierFormDrift:
  case Family::CovertDisplayCompound:
  case Family::ConfusableBidiCompound:
  case Family::AdmissibilityFormDrift:
    return "X";
  case Family::Bip39Canonical:
  case Family::HashInputStability:
  case Family::AiWatermarkDetectability:
    return "K";
  }
  return "C";
}

constexpr std::string_view family_slug(Family family) {
  switch (family) {
  case Family::MalformedUtf8:
    return "malformed-utf8";
  case Family::MalformedUtf16:
    return "malformed-utf16";
  case Family::MalformedUtf32:
    return "malformed-utf32";
  case Family::TagBlockPayload:
    return "tag-block-payload";
  case Family::VariationSelectorPayload:
    return "variation-selector-payload";
  case Family::ZeroWidthPayload:
    return "zero-width-payload";
  case Family::SurrogateReassembly:
    return "surrogate-reassembly";
  case Family::BidiControlBalance:
    return "bidi-control-balance";
  case Family::NoncharacterControl:
    return "noncharacter-control";
  case Family::HomoglyphConfusable:
    return "homoglyph-confusable";
  case Family::MixedScriptAdmissibility:
    return "mixed-script-admissibility";
  case Family::EmojiZwjIntegrity:
    return "emoji-zwj-integrity";
  case Family::SkinToneVariationForgery:
    return "skin-tone-variation-forgery";
  case Family::SourceDisplayDivergence:
    return "source-display-divergence";
  case Family::FilenameDisguise:
    return "filename-disguise";
  case Family::RtlInjection:
    return "rtl-injection";
  case Family::RendererDivergence:
    return "renderer-divergence";
  case Family::NormalizationBomb:
    return "normalization-bomb";
  case Family::StreamSafeViolation:
    return "stream-safe-violation";
  case Family::LocaleCaseInversion:
    return "locale-case-inversion";
  case Family::CaseExpansionMismatch:
    return "case-expansion-mismatch";
  case Family::WidthClassConfusion:
    return "width-class-confusion";
  case Family::NfcIdempotenceWitness:
    return "nfc-idempotence-witness";
  case Family::IdentifierFormDrift:
    return "identifier-form-drift";
  case Family::CovertDisplayCompound:
    return "covert-display-compound";
  case Family::ConfusableBidiCompound:
    return "confusable-bidi-compound";
  case Family::AdmissibilityFormDrift:
    return "admissibility-form-drift";
  case Family::Bip39Canonical:
    return "bip39-canonical";
  case Family::HashInputStability:
    return "hash-input-stability";
  case Family::AiWatermarkDetectability:
    return "ai-watermark-detectability";
  }
  return "unknown";
}

inline std::string reason_base(Family family) {
  std::string out = "unicode.security.";
  out += family_layer_code(family);
  out += ".";
  out += family_slug(family);
  return out;
}

inline std::string
reason_code(Family family,
            std::optional<std::string_view> sub_threat = std::nullopt) {
  std::string out = reason_base(family);
  out += ".";
  out += sub_threat.value_or("hazard");
  return out;
}

inline void append_json_string(std::string &out, std::string_view value) {
  static constexpr char hex[] = "0123456789abcdef";
  out.push_back('"');
  for (char ch : value) {
    const auto byte = static_cast<unsigned char>(ch);
    switch (ch) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (byte < 0x20u) {
        out += "\\u00";
        out.push_back(hex[(byte >> 4) & 0x0Fu]);
        out.push_back(hex[byte & 0x0Fu]);
      } else {
        out.push_back(ch);
      }
      break;
    }
  }
  out.push_back('"');
}

inline void append_u32_json_array(std::string &out,
                                  std::span<const std::uint32_t> values) {
  out.push_back('[');
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index > 0)
      out.push_back(',');
    out += std::to_string(values[index]);
  }
  out.push_back(']');
}

inline void append_size_json_array(std::string &out,
                                   std::span<const std::size_t> values) {
  out.push_back('[');
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index > 0)
      out.push_back(',');
    out += std::to_string(values[index]);
  }
  out.push_back(']');
}

inline void append_finding_json(std::string &out, const Finding &finding) {
  out.push_back('{');
  out += "\"code\":";
  append_json_string(out, finding.code);
  out += ",\"family\":";
  append_json_string(out, family_slug(finding.family));
  out += ",\"severity\":";
  out += std::to_string(static_cast<int>(finding.severity));
  out += ",\"positions\":";
  append_size_json_array(out, finding.positions);
  out += ",\"sub_threat\":";
  if (finding.sub_threat) {
    append_json_string(out, *finding.sub_threat);
  } else {
    out += "null";
  }
  out += ",\"detail\":";
  append_json_string(out, finding.detail);
  out.push_back('}');
}

inline std::string finding_to_json(const Finding &finding) {
  std::string out;
  append_finding_json(out, finding);
  return out;
}

inline std::string verdict_to_json(const Verdict &verdict) {
  std::string out;
  out.push_back('{');
  out += "\"action\":";
  append_json_string(out, tag(verdict.action));
  out += ",\"profile\":";
  append_json_string(out, tag(verdict.profile));
  out += ",\"mode\":";
  append_json_string(out, tag(verdict.mode));
  out += ",\"input\":";
  append_u32_json_array(out, verdict.input);
  out += ",\"findings\":[";
  for (std::size_t index = 0; index < verdict.findings.size(); ++index) {
    if (index > 0)
      out.push_back(',');
    append_finding_json(out, verdict.findings[index]);
  }
  out += "],\"normalized\":";
  if (verdict.normalized) {
    append_u32_json_array(out, *verdict.normalized);
  } else {
    out += "null";
  }
  out.push_back('}');
  return out;
}

constexpr std::string_view utf8_reject_tag(Utf8RejectKind kind) {
  switch (kind) {
  case Utf8RejectKind::OverlongEncoding:
    return "OverlongEncoding";
  case Utf8RejectKind::SurrogateCodepoint:
    return "SurrogateCodepoint";
  case Utf8RejectKind::CodepointBeyondMax:
    return "CodepointBeyondMax";
  case Utf8RejectKind::TruncatedSequence:
    return "TruncatedSequence";
  case Utf8RejectKind::InvalidStartByte:
    return "InvalidStartByte";
  case Utf8RejectKind::InvalidContinuationByte:
    return "InvalidContinuationByte";
  }
  return "InvalidStartByte";
}

inline bool family_blocks(Profile profile, Family family) {
  const auto policy = policy_of_profile(profile);
  const auto base = rejection_set(policy.level);
  if (std::find(base.begin(), base.end(), family) != base.end()) {
    return true;
  }
  const auto crypto = crypto_families(policy.crypto_context);
  return std::find(crypto.begin(), crypto.end(), family) != crypto.end();
}

inline std::vector<Finding>
blocking_findings(Profile profile, std::span<const Finding> findings) {
  std::vector<Finding> out;
  for (const auto &finding : findings) {
    if (family_blocks(profile, finding.family)) {
      out.push_back(finding);
    }
  }
  return out;
}

inline Action select_action(Profile profile, Mode mode,
                            std::span<const Finding> findings) {
  const bool has_findings = !findings.empty();
  const bool has_blocking = std::any_of(
      findings.begin(), findings.end(),
      [profile](const Finding &f) { return family_blocks(profile, f.family); });

  switch (mode) {
  case Mode::Observe:
  case Mode::Warn:
    return has_findings ? Action::Observe : Action::Allow;
  case Mode::Enforce:
    if (!has_blocking)
      return Action::Allow;
    return policy_of_profile(profile).quarantine ? Action::Quarantine
                                                 : Action::Reject;
  case Mode::Strict:
    return has_findings ? Action::Reject : Action::Allow;
  }
  return Action::Reject;
}

namespace detail {

constexpr Severity default_policy_severity(ClassificationKind kind) {
  switch (kind) {
  case ClassificationKind::Clear:
    return Severity::Informational;
  case ClassificationKind::Hazard:
    return Severity::Moderate;
  case ClassificationKind::Compound:
    return Severity::High;
  case ClassificationKind::Informational:
    return Severity::Informational;
  }
  return Severity::Informational;
}

inline void push_finding(std::vector<Finding> &findings, Family family,
                         ClassificationKind kind,
                         std::optional<std::string> sub_threat,
                         std::vector<std::size_t> positions) {
  if (kind == ClassificationKind::Clear)
    return;
  const auto sub_view = sub_threat
                            ? std::optional<std::string_view>{*sub_threat}
                            : std::optional<std::string_view>{};
  findings.push_back(Finding{
      reason_code(family, sub_view),
      family,
      default_policy_severity(kind),
      std::move(positions),
      std::move(sub_threat),
      std::string(family_slug(family)),
  });
}

// Push the finding for any detector whose verdict carries a classification.
// Every such classification exposes the same three accessors, and tag() yields
// a string_view over storage the classification owns, so it is copied before
// push_finding takes ownership of the finding.
template <typename Classification>
inline void push_classified(std::vector<Finding> &findings, Family family,
                            const Classification &classification) {
  if (classification.is_clear())
    return;
  const auto tag = classification.tag();
  push_finding(findings, family, ClassificationKind::Hazard,
               tag ? std::optional<std::string>{std::string{*tag}}
                   : std::optional<std::string>{},
               classification.positions);
}

inline std::vector<std::size_t> full_span_positions(std::size_t size) {
  std::vector<std::size_t> positions;
  positions.reserve(size);
  for (std::size_t i = 0; i < size; ++i)
    positions.push_back(i);
  return positions;
}

template <typename Predicate>
inline std::vector<std::size_t>
positions_where(std::span<const std::uint32_t> input, Predicate predicate) {
  std::vector<std::size_t> positions;
  for (std::size_t index = 0; index < input.size(); ++index) {
    if (predicate(input[index]))
      positions.push_back(index);
  }
  return positions;
}

inline bool is_c0_control(std::uint32_t cp) {
  return (cp <= 0x1Fu && cp != 0x09u && cp != 0x0Au && cp != 0x0Du) ||
         cp == 0x7Fu;
}

inline bool is_c1_control(std::uint32_t cp) {
  return cp >= 0x80u && cp <= 0x9Fu;
}

inline void push_positional_hazard(std::vector<Finding> &findings,
                                   Family family, std::string sub_threat,
                                   std::vector<std::size_t> positions) {
  if (positions.empty())
    return;
  push_finding(findings, family, ClassificationKind::Hazard,
               std::move(sub_threat), std::move(positions));
}

enum class Endian : std::uint8_t {
  Big,
  Little,
};

struct DecodeFailure {
  std::string_view sub_threat;
  std::size_t offset;
};

inline Verdict malformed_decode_verdict(Profile profile, Mode mode,
                                        Family family,
                                        std::string_view sub_threat,
                                        std::size_t offset) {
  std::string sub{sub_threat};
  std::vector<Finding> findings;
  findings.push_back(Finding{
      reason_code(family, std::optional<std::string_view>{sub_threat}),
      family,
      Severity::Moderate,
      {offset},
      sub,
      std::string(family_slug(family)),
  });
  return Verdict{
      {},
      profile,
      mode,
      select_action(profile, mode, findings),
      std::move(findings),
      std::nullopt,
  };
}

inline std::uint16_t read_u16(std::span<const std::uint8_t> bytes,
                              std::size_t offset, Endian endian) {
  if (endian == Endian::Big) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8) |
        static_cast<std::uint16_t>(bytes[offset + 1]));
  }
  return static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(bytes[offset]) |
      (static_cast<std::uint16_t>(bytes[offset + 1]) << 8));
}

inline std::uint32_t read_u32(std::span<const std::uint8_t> bytes,
                              std::size_t offset, Endian endian) {
  if (endian == Endian::Big) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
  }
  return static_cast<std::uint32_t>(bytes[offset]) |
         (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

inline std::optional<DecodeFailure>
decode_utf16_stream(std::span<const std::uint8_t> bytes, Endian endian,
                    std::vector<std::uint32_t> &out) {
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    if (offset + 2 > bytes.size()) {
      return DecodeFailure{"TruncatedCodeUnit", bytes.size()};
    }

    const std::uint32_t unit = read_u16(bytes, offset, endian);
    const std::size_t unit_offset = offset;
    offset += 2;

    if (unit >= 0xD800u && unit <= 0xDBFFu) {
      if (offset + 2 > bytes.size()) {
        return DecodeFailure{"TruncatedSurrogatePair", bytes.size()};
      }
      const std::uint32_t low = read_u16(bytes, offset, endian);
      if (low < 0xDC00u || low > 0xDFFFu) {
        return DecodeFailure{"InvalidSurrogatePair", offset};
      }
      out.push_back(0x10000u + ((unit - 0xD800u) << 10) + (low - 0xDC00u));
      offset += 2;
    } else if (unit >= 0xDC00u && unit <= 0xDFFFu) {
      return DecodeFailure{"LoneSurrogate", unit_offset};
    } else {
      out.push_back(unit);
    }
  }
  return std::nullopt;
}

inline std::optional<DecodeFailure>
decode_utf32_stream(std::span<const std::uint8_t> bytes, Endian endian,
                    std::vector<std::uint32_t> &out) {
  if (bytes.size() % 4 != 0) {
    return DecodeFailure{"TruncatedCodeUnit", bytes.size()};
  }

  for (std::size_t offset = 0; offset < bytes.size(); offset += 4) {
    const std::uint32_t cp = read_u32(bytes, offset, endian);
    if (cp >= 0xD800u && cp <= 0xDFFFu) {
      return DecodeFailure{"SurrogateCodepoint", offset};
    }
    if (cp > 0x10FFFFu) {
      return DecodeFailure{"CodepointBeyondMax", offset};
    }
    out.push_back(cp);
  }
  return std::nullopt;
}

} // namespace detail

inline Verdict
scan_with_identity_database(Profile profile, Mode mode,
                            std::span<const std::uint32_t> input,
                            const homoglyph_confusable::Database *identity_db) {
  std::vector<Finding> findings;

  const auto tag_result = tag_block_payload::detect(input);
  detail::push_finding(
      findings, Family::TagBlockPayload, tag_result.kind,
      tag_result.sub
          ? std::optional<std::string>{tag_block_payload::sub_threat_tag(
                *tag_result.sub)}
          : std::nullopt,
      tag_result.tag_positions);

  const auto vs_result = variation_selector_payload::detect(input);
  detail::push_finding(
      findings, Family::VariationSelectorPayload, vs_result.kind,
      vs_result.sub
          ? std::optional<
                std::string>{variation_selector_payload::sub_threat_tag(
                *vs_result.sub)}
          : std::nullopt,
      vs_result.vs_positions);

  const auto zw_result = zero_width_payload::detect(input);
  detail::push_finding(
      findings, Family::ZeroWidthPayload, zw_result.kind,
      zw_result.sub
          ? std::optional<std::string>{zero_width_payload::sub_threat_tag(
                *zw_result.sub)}
          : std::nullopt,
      zw_result.zero_width_positions);

  // Mirror `runAll`: SurrogateReassembly only applies to byte-stream input
  // (every codepoint <= 0xFF); on codepoint-array input the family is clear.
  if (surrogate_reassembly::looks_like_byte_stream(input)) {
    const auto surrogate_result = surrogate_reassembly::detect(input);
    if (surrogate_result.sub) {
      detail::push_finding(findings, Family::SurrogateReassembly,
                           ClassificationKind::Hazard, surrogate_result.sub,
                           surrogate_result.positions);
    }
  }

  const auto bidi_result = bidi_control_balance::detect(input);
  detail::push_finding(
      findings, Family::BidiControlBalance, bidi_result.kind,
      bidi_result.sub
          ? std::optional<std::string>{bidi_control_balance::sub_threat_tag(
                *bidi_result.sub)}
          : std::nullopt,
      bidi_result.bidi_positions);

  detail::push_positional_hazard(
      findings, Family::NoncharacterControl, "Noncharacter",
      detail::positions_where(input,
                              unicode_cpp::noncharacters::is_noncharacter));
  detail::push_positional_hazard(
      findings, Family::NoncharacterControl, "C0Control",
      detail::positions_where(input, detail::is_c0_control));
  detail::push_positional_hazard(
      findings, Family::NoncharacterControl, "C1Control",
      detail::positions_where(input, detail::is_c1_control));

  if (identity_db != nullptr) {
    const auto identity_result =
        homoglyph_confusable::detect(input, *identity_db);
    const auto identity_sub =
        identity_result.sub
            ? std::optional<std::string>{homoglyph_confusable::sub_threat_tag(
                  *identity_result.sub)}
            : std::nullopt;
    if (identity_sub != std::optional<std::string>{"CrossScriptMix"}) {
      detail::push_finding(findings, Family::HomoglyphConfusable,
                           identity_result.kind, identity_sub,
                           identity_result.kind == ClassificationKind::Clear
                               ? std::vector<std::size_t>{}
                               : detail::full_span_positions(input.size()));
    }
    if (homoglyph_confusable::has_mixed_script_admissibility(input,
                                                             *identity_db)) {
      detail::push_finding(
          findings, Family::MixedScriptAdmissibility,
          ClassificationKind::Hazard,
          std::optional<std::string>{
              homoglyph_confusable::mixed_script_subthreat(input,
                                                           *identity_db)},
          detail::full_span_positions(input.size()));
    }

    const auto rtl_result =
        display::rtl_injection::detect(identity_db->tables, input);
    if (rtl_result.sub) {
      detail::push_finding(findings, Family::RtlInjection,
                           ClassificationKind::Hazard, rtl_result.sub,
                           rtl_result.positions);
    }

    const auto compound_result =
        boundary::confusable_bidi_compound::detect(input, *identity_db);
    if (compound_result.sub) {
      detail::push_finding(findings, Family::ConfusableBidiCompound,
                           ClassificationKind::Hazard, compound_result.sub,
                           compound_result.positions);
    }

    const auto covert_display_result =
        boundary::covert_display_compound::detect(input);
    if (covert_display_result.sub) {
      detail::push_finding(findings, Family::CovertDisplayCompound,
                           ClassificationKind::Hazard,
                           covert_display_result.sub,
                           covert_display_result.positions);
    }

    namespace ezwj = unicode_cpp::security::identity::emoji_zwj_integrity;
    namespace stvf = unicode_cpp::security::identity::skin_tone_variation_forgery;
    const std::vector<std::uint32_t> input_vec(input.begin(), input.end());

    detail::push_classified(findings, Family::EmojiZwjIntegrity,
                            ezwj::detect(identity_db->rgi, input).classify);
    detail::push_classified(
        findings, Family::SkinToneVariationForgery,
        stvf::detect(identity_db->emoji_properties, input).classify);
    detail::push_classified(findings, Family::FilenameDisguise,
                            display::filename_disguise::detect(input).classify);
    detail::push_classified(
        findings, Family::RendererDivergence,
        display::renderer_divergence::detect(identity_db->rgi,
                                             identity_db->tables, input)
            .classify);
    detail::push_classified(
        findings, Family::StreamSafeViolation,
        form::stream_safe_violation::detect(identity_db->tables, input)
            .classify);
    detail::push_classified(
        findings, Family::CaseExpansionMismatch,
        form::case_expansion_mismatch::detect(identity_db->casing_data,
                                              identity_db->tables, input_vec)
            .classify);
    detail::push_classified(
        findings, Family::IdentifierFormDrift,
        boundary::identifier_form_drift::detect(identity_db->tables, input)
            .classify);
    detail::push_classified(
        findings, Family::AdmissibilityFormDrift,
        boundary::admissibility_form_drift::detect(identity_db->tables, input)
            .classify);

    const auto bomb =
        form::normalization_bomb::detect(identity_db->tables, input_vec);
    if (bomb.sub) {
      detail::push_finding(findings, Family::NormalizationBomb,
                           ClassificationKind::Hazard, bomb.sub,
                           bomb.positions);
    }
    const auto locale_case = form::locale_case_inversion::detect(
        identity_db->casing_data, identity_db->tables, input_vec);
    if (locale_case.sub) {
      detail::push_finding(findings, Family::LocaleCaseInversion,
                           ClassificationKind::Hazard, locale_case.sub,
                           locale_case.positions);
    }
    const auto nfc_witness =
        form::nfc_idempotence_witness::detect(identity_db->tables, input_vec);
    if (nfc_witness.sub) {
      detail::push_finding(findings, Family::NfcIdempotenceWitness,
                           ClassificationKind::Hazard, nfc_witness.sub,
                           nfc_witness.positions);
    }
    const auto width_class =
        form::width_class_confusion::detect(identity_db->tables, input_vec);
    if (width_class.sub) {
      detail::push_finding(findings, Family::WidthClassConfusion,
                           ClassificationKind::Hazard, width_class.sub,
                           width_class.positions);
    }

    // SourceDisplayDivergence judges the input as a unit, so it localises
    // nothing and carries an empty position list.
    const auto source_display =
        display::source_display_divergence::detect(*identity_db, input);
    if (source_display.sub) {
      detail::push_finding(findings, Family::SourceDisplayDivergence,
                           ClassificationKind::Hazard, source_display.sub, {});
    }
  }

  return Verdict{
      std::vector<std::uint32_t>{input.begin(), input.end()},
      profile,
      mode,
      select_action(profile, mode, findings),
      std::move(findings),
      std::nullopt,
  };
}

inline Verdict scan(Profile profile, Mode mode,
                    std::span<const std::uint32_t> input) {
  return scan_with_identity_database(profile, mode, input, nullptr);
}

inline Verdict scan_utf8(Profile profile, Mode mode,
                         std::span<const std::uint8_t> bytes) {
  if (auto invalid = unicode_cpp::first_invalid_utf8_offset(bytes)) {
    return detail::malformed_decode_verdict(
        profile, mode, Family::MalformedUtf8, utf8_reject_tag(invalid->kind),
        invalid->offset);
  }

  const auto input = unicode_cpp::decode_to_codepoints(bytes);
  return scan(profile, mode,
              std::span<const std::uint32_t>{input.data(), input.size()});
}

inline Verdict scan_utf16(Profile profile, Mode mode,
                          std::span<const std::uint8_t> bytes,
                          detail::Endian endian) {
  std::vector<std::uint32_t> input;
  input.reserve(bytes.size() / 2);
  if (auto failure = detail::decode_utf16_stream(bytes, endian, input)) {
    return detail::malformed_decode_verdict(
        profile, mode, Family::MalformedUtf16, failure->sub_threat,
        failure->offset);
  }
  return scan(profile, mode,
              std::span<const std::uint32_t>{input.data(), input.size()});
}

inline Verdict scan_utf16be(Profile profile, Mode mode,
                            std::span<const std::uint8_t> bytes) {
  return scan_utf16(profile, mode, bytes, detail::Endian::Big);
}

inline Verdict scan_utf16le(Profile profile, Mode mode,
                            std::span<const std::uint8_t> bytes) {
  return scan_utf16(profile, mode, bytes, detail::Endian::Little);
}

inline Verdict scan_utf32(Profile profile, Mode mode,
                          std::span<const std::uint8_t> bytes,
                          detail::Endian endian) {
  std::vector<std::uint32_t> input;
  input.reserve(bytes.size() / 4);
  if (auto failure = detail::decode_utf32_stream(bytes, endian, input)) {
    return detail::malformed_decode_verdict(
        profile, mode, Family::MalformedUtf32, failure->sub_threat,
        failure->offset);
  }
  return scan(profile, mode,
              std::span<const std::uint32_t>{input.data(), input.size()});
}

inline Verdict scan_utf32be(Profile profile, Mode mode,
                            std::span<const std::uint8_t> bytes) {
  return scan_utf32(profile, mode, bytes, detail::Endian::Big);
}

inline Verdict scan_utf32le(Profile profile, Mode mode,
                            std::span<const std::uint8_t> bytes) {
  return scan_utf32(profile, mode, bytes, detail::Endian::Little);
}

inline Verdict scan_default(Profile profile,
                            std::span<const std::uint32_t> input) {
  return scan(profile, Mode::Enforce, input);
}

inline bool permits(Profile profile, Mode mode,
                    std::span<const std::uint32_t> input) {
  const auto action = scan(profile, mode, input).action;
  return action == Action::Allow || action == Action::Observe ||
         action == Action::Rewrite;
}

} // namespace unicode_cpp::security::policy

#endif // UNICODE_CPP_SECURITY_POLICY_HPP
