#include <doctest/doctest.h>

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "unicode_cpp/security/boundary/confusable_bidi_compound.hpp"
#include "unicode_cpp/security/calculus.hpp"
#include "unicode_cpp/security/covert/bidi_control_balance.hpp"
#include "unicode_cpp/security/covert/tag_block_payload.hpp"
#include "unicode_cpp/security/covert/variation_selector_payload.hpp"
#include "unicode_cpp/security/covert/zero_width_payload.hpp"
#include "unicode_cpp/security/display/rtl_injection.hpp"
#include "unicode_cpp/security/identity/homoglyph_confusable.hpp"
#include "unicode_cpp/security/policy.hpp"

using namespace unicode_cpp::security;
namespace policy = unicode_cpp::security::policy;

static std::span<const std::uint32_t>
as_span(const std::vector<std::uint32_t> &v) {
  return std::span<const std::uint32_t>(v.data(), v.size());
}

static std::span<const std::uint8_t>
as_byte_span(const std::vector<std::uint8_t> &v) {
  return std::span<const std::uint8_t>(v.data(), v.size());
}

static bool has_code(const policy::Verdict &verdict, std::string_view code) {
  for (const auto &finding : verdict.findings) {
    if (finding.code == code)
      return true;
  }
  return false;
}

static std::optional<std::vector<std::size_t>>
positions_for(const policy::Verdict &verdict, std::string_view code) {
  for (const auto &finding : verdict.findings) {
    if (finding.code == code)
      return finding.positions;
  }
  return std::nullopt;
}

struct TestJson {
  enum class Kind { Object, Array, String, Number, Null };

  Kind kind = Kind::Null;
  std::vector<std::pair<std::string, TestJson>> object;
  std::vector<TestJson> array;
  std::string string;
  int number = 0;

  static TestJson make_object(std::vector<std::pair<std::string, TestJson>> v) {
    TestJson json;
    json.kind = Kind::Object;
    json.object = std::move(v);
    return json;
  }

  static TestJson make_array(std::vector<TestJson> v) {
    TestJson json;
    json.kind = Kind::Array;
    json.array = std::move(v);
    return json;
  }

  static TestJson make_string(std::string v) {
    TestJson json;
    json.kind = Kind::String;
    json.string = std::move(v);
    return json;
  }

  static TestJson make_number(int v) {
    TestJson json;
    json.kind = Kind::Number;
    json.number = v;
    return json;
  }

  const TestJson &field(std::string_view key) const {
    if (kind != Kind::Object)
      throw std::runtime_error("JSON value is not an object");
    for (const auto &[field_key, value] : object) {
      if (field_key == key)
        return value;
    }
    throw std::runtime_error("missing JSON field");
  }

  std::optional<std::string_view>
  optional_string_field(std::string_view key) const {
    if (kind != Kind::Object)
      throw std::runtime_error("JSON value is not an object");
    for (const auto &[field_key, value] : object) {
      if (field_key == key)
        return value.as_string();
    }
    return std::nullopt;
  }

  const std::vector<TestJson> &as_array() const {
    if (kind != Kind::Array)
      throw std::runtime_error("JSON value is not an array");
    return array;
  }

  std::string_view as_string() const {
    if (kind != Kind::String)
      throw std::runtime_error("JSON value is not a string");
    return string;
  }

  int as_number() const {
    if (kind != Kind::Number)
      throw std::runtime_error("JSON value is not a number");
    return number;
  }
};

class TestJsonParser {
public:
  explicit TestJsonParser(std::string_view input) : input_(input) {}

  TestJson parse() {
    skip_ws();
    auto value = parse_value();
    skip_ws();
    if (pos_ != input_.size())
      throw std::runtime_error("trailing JSON input");
    return value;
  }

private:
  std::string_view input_;
  std::size_t pos_ = 0;

  void skip_ws() {
    while (pos_ < input_.size() &&
           std::isspace(static_cast<unsigned char>(input_[pos_]))) {
      ++pos_;
    }
  }

  char peek() const {
    if (pos_ >= input_.size())
      throw std::runtime_error("unexpected end of JSON input");
    return input_[pos_];
  }

  char take() {
    const auto ch = peek();
    ++pos_;
    return ch;
  }

  void expect(char ch) {
    if (take() != ch)
      throw std::runtime_error("unexpected JSON character");
  }

  TestJson parse_value() {
    skip_ws();
    switch (peek()) {
    case '{':
      return parse_object();
    case '[':
      return parse_array();
    case '"':
      return TestJson::make_string(parse_string());
    case 'n':
      return parse_null();
    default:
      return parse_number();
    }
  }

  TestJson parse_object() {
    expect('{');
    skip_ws();
    std::vector<std::pair<std::string, TestJson>> fields;
    if (peek() == '}') {
      take();
      return TestJson::make_object(std::move(fields));
    }
    while (true) {
      skip_ws();
      auto key = parse_string();
      skip_ws();
      expect(':');
      auto value = parse_value();
      fields.emplace_back(std::move(key), std::move(value));
      skip_ws();
      const auto ch = take();
      if (ch == '}')
        break;
      if (ch != ',')
        throw std::runtime_error("expected JSON object comma");
    }
    return TestJson::make_object(std::move(fields));
  }

  TestJson parse_array() {
    expect('[');
    skip_ws();
    std::vector<TestJson> values;
    if (peek() == ']') {
      take();
      return TestJson::make_array(std::move(values));
    }
    while (true) {
      values.push_back(parse_value());
      skip_ws();
      const auto ch = take();
      if (ch == ']')
        break;
      if (ch != ',')
        throw std::runtime_error("expected JSON array comma");
    }
    return TestJson::make_array(std::move(values));
  }

  std::string parse_string() {
    expect('"');
    std::string out;
    while (true) {
      const auto ch = take();
      if (ch == '"')
        break;
      if (ch != '\\') {
        out.push_back(ch);
        continue;
      }
      const auto escaped = take();
      switch (escaped) {
      case '"':
      case '\\':
      case '/':
        out.push_back(escaped);
        break;
      case 'n':
        out.push_back('\n');
        break;
      case 'r':
        out.push_back('\r');
        break;
      case 't':
        out.push_back('\t');
        break;
      default:
        throw std::runtime_error("unsupported JSON string escape");
      }
    }
    return out;
  }

  TestJson parse_null() {
    if (input_.substr(pos_, 4) != "null")
      throw std::runtime_error("expected JSON null");
    pos_ += 4;
    return TestJson{};
  }

  TestJson parse_number() {
    bool negative = false;
    if (peek() == '-') {
      negative = true;
      take();
    }
    int value = 0;
    bool saw_digit = false;
    while (pos_ < input_.size() &&
           std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
      saw_digit = true;
      value = value * 10 + (take() - '0');
    }
    if (!saw_digit)
      throw std::runtime_error("expected JSON number");
    return TestJson::make_number(negative ? -value : value);
  }
};

static std::string read_fixture_file(std::string_view relative) {
  const std::filesystem::path rel{relative};
  const std::filesystem::path candidates[] = {
      rel,
      std::filesystem::path{".."} / rel,
      std::filesystem::path{"../.."} / rel,
  };
  for (const auto &path : candidates) {
    if (!std::filesystem::exists(path))
      continue;
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>{in},
                       std::istreambuf_iterator<char>{});
  }
  throw std::runtime_error("cannot locate JSON fixture");
}

static TestJson parse_fixture_file(std::string_view relative) {
  const auto text = read_fixture_file(relative);
  return TestJsonParser{text}.parse();
}

static std::vector<std::uint32_t> u32_array(const TestJson &json) {
  std::vector<std::uint32_t> out;
  for (const auto &value : json.as_array())
    out.push_back(static_cast<std::uint32_t>(value.as_number()));
  return out;
}

static std::vector<std::uint8_t> byte_array(const TestJson &json) {
  std::vector<std::uint8_t> out;
  for (const auto &value : json.as_array())
    out.push_back(static_cast<std::uint8_t>(value.as_number()));
  return out;
}

static std::vector<std::string> string_array(const TestJson &json) {
  std::vector<std::string> out;
  for (const auto &value : json.as_array())
    out.emplace_back(value.as_string());
  return out;
}

static std::vector<std::size_t> size_array(const TestJson &json) {
  std::vector<std::size_t> out;
  for (const auto &value : json.as_array())
    out.push_back(static_cast<std::size_t>(value.as_number()));
  return out;
}

static policy::Profile parse_profile(std::string_view tag) {
  if (tag == "gateway-header")
    return policy::Profile::GatewayHeader;
  if (tag == "domain-name")
    return policy::Profile::DomainName;
  if (tag == "dns-label")
    return policy::Profile::DnsLabel;
  if (tag == "url")
    return policy::Profile::Url;
  if (tag == "username")
    return policy::Profile::Username;
  if (tag == "display-name")
    return policy::Profile::DisplayName;
  if (tag == "chat-message")
    return policy::Profile::ChatMessage;
  if (tag == "source-code")
    return policy::Profile::SourceCode;
  if (tag == "opaque-secret")
    return policy::Profile::OpaqueSecret;
  if (tag == "binary-blob")
    return policy::Profile::BinaryBlob;
  throw std::runtime_error("unknown profile");
}

static policy::Mode parse_mode(std::string_view tag) {
  if (tag == "observe")
    return policy::Mode::Observe;
  if (tag == "warn")
    return policy::Mode::Warn;
  if (tag == "enforce")
    return policy::Mode::Enforce;
  if (tag == "strict")
    return policy::Mode::Strict;
  throw std::runtime_error("unknown mode");
}

static policy::Action parse_action(std::string_view tag) {
  if (tag == "allow")
    return policy::Action::Allow;
  if (tag == "reject")
    return policy::Action::Reject;
  if (tag == "quarantine")
    return policy::Action::Quarantine;
  if (tag == "rewrite")
    return policy::Action::Rewrite;
  if (tag == "observe")
    return policy::Action::Observe;
  throw std::runtime_error("unknown action");
}

static policy::Verdict
scan_encoded_case(std::string_view encoding, policy::Profile profile,
                  policy::Mode mode, const std::vector<std::uint8_t> &bytes) {
  if (encoding == "utf-8")
    return policy::scan_utf8(profile, mode, as_byte_span(bytes));
  if (encoding == "utf-16be")
    return policy::scan_utf16be(profile, mode, as_byte_span(bytes));
  if (encoding == "utf-16le")
    return policy::scan_utf16le(profile, mode, as_byte_span(bytes));
  if (encoding == "utf-32be")
    return policy::scan_utf32be(profile, mode, as_byte_span(bytes));
  if (encoding == "utf-32le")
    return policy::scan_utf32le(profile, mode, as_byte_span(bytes));
  throw std::runtime_error("unknown encoding");
}

static void check_decode_fixture(std::string_view relative,
                                 std::string_view expected_contract) {
  const auto root = parse_fixture_file(relative);
  REQUIRE(root.field("schema").as_number() == 1);
  REQUIRE(root.field("contract").as_string() == expected_contract);

  for (const auto &test_case : root.field("cases").as_array()) {
    const auto name = std::string(test_case.field("name").as_string());
    INFO(name);
    const auto profile = parse_profile(test_case.field("profile").as_string());
    const auto mode = parse_mode(test_case.field("mode").as_string());
    const auto expected_action =
        parse_action(test_case.field("action").as_string());
    const auto bytes = byte_array(test_case.field("input_bytes"));
    const auto expected_input = u32_array(test_case.field("input"));
    const auto encoding =
        test_case.optional_string_field("encoding").value_or("utf-8");
    const auto verdict = scan_encoded_case(encoding, profile, mode, bytes);

    CHECK(verdict.action == expected_action);
    CHECK(verdict.input == expected_input);

    for (const auto &code : string_array(test_case.field("required_findings")))
      CHECK(has_code(verdict, code));

    for (const auto &required :
         test_case.field("required_positions").as_array()) {
      const auto code = required.field("code").as_string();
      const auto expected_positions = size_array(required.field("positions"));
      const auto actual_positions = positions_for(verdict, code);
      REQUIRE(actual_positions.has_value());
      CHECK(*actual_positions == expected_positions);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────
// Policy contract
// ─────────────────────────────────────────────────────────────────────

TEST_CASE("Policy — reason codes are stable") {
  CHECK(policy::reason_code(Family::TagBlockPayload,
                            std::optional<std::string_view>{"DirectAscii"}) ==
        "unicode.security.C.tag-block-payload.DirectAscii");
  CHECK(policy::reason_code(Family::BidiControlBalance) ==
        "unicode.security.C.bidi-control-balance.hazard");
  CHECK(policy::reason_code(Family::HomoglyphConfusable,
                            std::optional<std::string_view>{"TargetMatch"}) ==
        "unicode.security.I.homoglyph-confusable.TargetMatch");
  CHECK(
      policy::reason_code(Family::MixedScriptAdmissibility,
                          std::optional<std::string_view>{"CrossScriptMix"}) ==
      "unicode.security.I.mixed-script-admissibility.CrossScriptMix");
  CHECK(policy::reason_code(Family::NoncharacterControl,
                            std::optional<std::string_view>{"Noncharacter"}) ==
        "unicode.security.C.noncharacter-control.Noncharacter");
  CHECK(policy::reason_code(
            Family::MalformedUtf8,
            std::optional<std::string_view>{"InvalidStartByte"}) ==
        "unicode.security.C.malformed-utf8.InvalidStartByte");
  CHECK(policy::reason_code(
            Family::MalformedUtf16,
            std::optional<std::string_view>{"TruncatedCodeUnit"}) ==
        "unicode.security.C.malformed-utf16.TruncatedCodeUnit");
  CHECK(policy::reason_code(
            Family::MalformedUtf32,
            std::optional<std::string_view>{"CodepointBeyondMax"}) ==
        "unicode.security.C.malformed-utf32.CodepointBeyondMax");
}

TEST_CASE("Policy — ASCII gateway enforce allows") {
  std::vector<std::uint32_t> input = {'H', 'e', 'l', 'l', 'o'};
  auto verdict = policy::scan(policy::Profile::GatewayHeader,
                              policy::Mode::Enforce, as_span(input));
  CHECK(verdict.action == policy::Action::Allow);
  CHECK(verdict.findings.empty());
  CHECK(policy::verdict_to_json(verdict) ==
        "{\"action\":\"allow\",\"profile\":\"gateway-header\",\"mode\":"
        "\"enforce\",\"input\":[72,101,108,108,111],\"findings\":[],"
        "\"normalized\":null}");
}

TEST_CASE("Policy — tag-block gateway enforce rejects") {
  std::vector<std::uint32_t> input = {0xE0041, 0xE0042};
  auto verdict = policy::scan(policy::Profile::GatewayHeader,
                              policy::Mode::Enforce, as_span(input));
  CHECK(verdict.action == policy::Action::Reject);
  CHECK(has_code(verdict, "unicode.security.C.tag-block-payload.DirectAscii"));
}

TEST_CASE("Policy — noncharacter gateway enforce rejects") {
  std::vector<std::uint32_t> input = {0xFDD0};
  auto verdict = policy::scan(policy::Profile::GatewayHeader,
                              policy::Mode::Enforce, as_span(input));
  CHECK(verdict.action == policy::Action::Reject);
  CHECK(has_code(verdict,
                 "unicode.security.C.noncharacter-control.Noncharacter"));
  CHECK(policy::verdict_to_json(verdict) ==
        "{\"action\":\"reject\",\"profile\":\"gateway-header\",\"mode\":"
        "\"enforce\",\"input\":[64976],\"findings\":[{\"code\":\"unicode."
        "security.C.noncharacter-control.Noncharacter\",\"family\":"
        "\"noncharacter-control\",\"severity\":2,\"positions\":[0],\"sub_"
        "threat\":\"Noncharacter\",\"detail\":\"noncharacter-control\"}],"
        "\"normalized\":null}");
}

TEST_CASE("Policy — structured whitespace is not C0 control") {
  std::vector<std::uint32_t> input = {'a', 0x09, 0x0A, 0x0D, 'b'};
  auto verdict = policy::scan(policy::Profile::GatewayHeader,
                              policy::Mode::Enforce, as_span(input));
  CHECK(verdict.action == policy::Action::Allow);
  CHECK(verdict.findings.empty());
}

TEST_CASE("Policy — tag-block username enforce quarantines") {
  std::vector<std::uint32_t> input = {0xE0041, 0xE0042};
  auto verdict = policy::scan(policy::Profile::Username, policy::Mode::Enforce,
                              as_span(input));
  CHECK(verdict.action == policy::Action::Quarantine);
  CHECK(has_code(verdict, "unicode.security.C.tag-block-payload.DirectAscii"));
}

TEST_CASE("Policy — zero-width display-name enforce reports and allows") {
  std::vector<std::uint32_t> input = {'a', 0x200B, 'b'};
  auto verdict = policy::scan(policy::Profile::DisplayName,
                              policy::Mode::Enforce, as_span(input));
  CHECK(verdict.action == policy::Action::Allow);
  CHECK(
      has_code(verdict, "unicode.security.C.zero-width-payload.BareZeroWidth"));
}

TEST_CASE("Policy — zero-width source strict rejects") {
  std::vector<std::uint32_t> input = {'a', 0x200B, 'b'};
  auto verdict = policy::scan(policy::Profile::SourceCode, policy::Mode::Strict,
                              as_span(input));
  CHECK(verdict.action == policy::Action::Reject);
  CHECK(
      has_code(verdict, "unicode.security.C.zero-width-payload.BareZeroWidth"));
}

TEST_CASE("Policy — bidi source enforce rejects") {
  std::vector<std::uint32_t> input = {'i', 'f', ' ', 0x202E, ')', '{'};
  auto verdict = policy::scan(policy::Profile::SourceCode,
                              policy::Mode::Enforce, as_span(input));
  CHECK(verdict.action == policy::Action::Reject);
  CHECK(has_code(
      verdict, "unicode.security.C.bidi-control-balance.UnbalancedEmbedding"));
}

TEST_CASE("Policy — shared UTF-8 decode contract fixture") {
  check_decode_fixture("testdata/fixtures/security/decode_contract.json",
                       "unicode-security-decode-v0");
}

TEST_CASE("Policy — shared UTF-16/UTF-32 decode contract fixture") {
  check_decode_fixture("testdata/fixtures/security/decode_multiencoding_contract.json",
                       "unicode-security-multiencoding-decode-v0");
}

TEST_CASE("Policy — UTF-8 decode contract") {
  struct Case {
    std::vector<std::uint8_t> bytes;
    policy::Profile profile;
    policy::Mode mode;
    policy::Action action;
    std::vector<std::uint32_t> input;
    std::string_view code;
    std::vector<std::size_t> positions;
  };

  const Case cases[] = {
      {{'H', 'e', 'l', 'l', 'o'},
       policy::Profile::GatewayHeader,
       policy::Mode::Enforce,
       policy::Action::Allow,
       {'H', 'e', 'l', 'l', 'o'},
       "",
       {}},
      {{0x80},
       policy::Profile::GatewayHeader,
       policy::Mode::Enforce,
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf8.InvalidStartByte",
       {0}},
      {{0xC2, 0x00},
       policy::Profile::GatewayHeader,
       policy::Mode::Enforce,
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf8.InvalidContinuationByte",
       {1}},
      {{0xE0, 0x80, 0xAF},
       policy::Profile::GatewayHeader,
       policy::Mode::Enforce,
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf8.OverlongEncoding",
       {0}},
      {{0xED, 0xA0, 0x80},
       policy::Profile::GatewayHeader,
       policy::Mode::Enforce,
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf8.SurrogateCodepoint",
       {2}},
      {{0xF4, 0x90, 0x80, 0x80},
       policy::Profile::GatewayHeader,
       policy::Mode::Enforce,
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf8.CodepointBeyondMax",
       {3}},
      {{0xC2},
       policy::Profile::GatewayHeader,
       policy::Mode::Enforce,
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf8.TruncatedSequence",
       {1}},
      {{0x80},
       policy::Profile::GatewayHeader,
       policy::Mode::Observe,
       policy::Action::Observe,
       {},
       "unicode.security.C.malformed-utf8.InvalidStartByte",
       {0}},
      {{'a', 0xE2, 0x80, 0x8B, 'b'},
       policy::Profile::SourceCode,
       policy::Mode::Strict,
       policy::Action::Reject,
       {'a', 0x200B, 'b'},
       "unicode.security.C.zero-width-payload.BareZeroWidth",
       {1}},
  };

  for (const auto &tc : cases) {
    auto verdict =
        policy::scan_utf8(tc.profile, tc.mode, as_byte_span(tc.bytes));
    CHECK(verdict.action == tc.action);
    CHECK(verdict.input == tc.input);
    if (!tc.code.empty()) {
      REQUIRE(!verdict.findings.empty());
      CHECK(has_code(verdict, tc.code));
      for (const auto &finding : verdict.findings) {
        if (finding.code == tc.code) {
          CHECK(finding.positions == tc.positions);
        }
      }
    }
  }
}

TEST_CASE("Policy — UTF-16 and UTF-32 decode contract") {
  struct Case {
    std::vector<std::uint8_t> bytes;
    std::string_view encoding;
    policy::Action action;
    std::vector<std::uint32_t> input;
    std::string_view code;
    std::vector<std::size_t> positions;
    policy::Profile profile = policy::Profile::GatewayHeader;
    policy::Mode mode = policy::Mode::Enforce;
  };

  const Case cases[] = {
      {{'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0},
       "utf-16le",
       policy::Action::Allow,
       {'H', 'e', 'l', 'l', 'o'},
       "",
       {}},
      {{0x61},
       "utf-16le",
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf16.TruncatedCodeUnit",
       {1}},
      {{0xDC, 0x00},
       "utf-16be",
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf16.LoneSurrogate",
       {0}},
      {{0x00, 0xD8, 0x41, 0x00},
       "utf-16le",
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf16.InvalidSurrogatePair",
       {2}},
      {{0x00, 0xD8},
       "utf-16le",
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf16.TruncatedSurrogatePair",
       {2}},
      {{'H', 0, 0, 0, 'e', 0, 0, 0, 'l', 0, 0, 0, 'l', 0, 0, 0, 'o', 0, 0, 0},
       "utf-32le",
       policy::Action::Allow,
       {'H', 'e', 'l', 'l', 'o'},
       "",
       {}},
      {{0x00, 0x00, 0x00},
       "utf-32be",
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf32.TruncatedCodeUnit",
       {3}},
      {{0x00, 0xD8, 0x00, 0x00},
       "utf-32le",
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf32.SurrogateCodepoint",
       {0}},
      {{0x00, 0x11, 0x00, 0x00},
       "utf-32be",
       policy::Action::Reject,
       {},
       "unicode.security.C.malformed-utf32.CodepointBeyondMax",
       {0}},
      {{'a', 0x00, 0x0B, 0x20, 'b', 0x00},
       "utf-16le",
       policy::Action::Reject,
       {'a', 0x200B, 'b'},
       "unicode.security.C.zero-width-payload.BareZeroWidth",
       {1},
       policy::Profile::SourceCode,
       policy::Mode::Strict},
  };

  for (const auto &tc : cases) {
    policy::Verdict verdict;
    if (tc.encoding == "utf-16be") {
      verdict =
          policy::scan_utf16be(tc.profile, tc.mode, as_byte_span(tc.bytes));
    } else if (tc.encoding == "utf-16le") {
      verdict =
          policy::scan_utf16le(tc.profile, tc.mode, as_byte_span(tc.bytes));
    } else if (tc.encoding == "utf-32be") {
      verdict =
          policy::scan_utf32be(tc.profile, tc.mode, as_byte_span(tc.bytes));
    } else {
      verdict =
          policy::scan_utf32le(tc.profile, tc.mode, as_byte_span(tc.bytes));
    }

    CHECK(verdict.action == tc.action);
    CHECK(verdict.input == tc.input);
    if (!tc.code.empty()) {
      REQUIRE(has_code(verdict, tc.code));
      for (const auto &finding : verdict.findings) {
        if (finding.code == tc.code) {
          CHECK(finding.positions == tc.positions);
        }
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────
// TagBlockPayload
// ─────────────────────────────────────────────────────────────────────

TEST_CASE("TagBlockPayload — empty input is clear") {
  std::vector<std::uint32_t> empty;
  auto v = tag_block_payload::detect(as_span(empty));
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("TagBlockPayload — pure ASCII is clear") {
  std::vector<std::uint32_t> bytes = {'H', 'e', 'l', 'l', 'o'};
  auto v = tag_block_payload::detect(as_span(bytes));
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("TagBlockPayload — direct ASCII tag payload \"AB\"") {
  std::vector<std::uint32_t> in = {0xE0041, 0xE0042};
  auto v = tag_block_payload::detect(as_span(in));
  REQUIRE(v.kind == ClassificationKind::Hazard);
  REQUIRE(v.sub.has_value());
  CHECK(tag_block_payload::sub_threat_tag(*v.sub) == "DirectAscii");
  CHECK(v.recovered_ascii == "AB");
}

TEST_CASE("TagBlockPayload — Goodside \"Print 'pwned'\" payload decodes") {
  std::vector<std::uint32_t> in = {
      0xE0050, 0xE0072, 0xE0069, 0xE006E, 0xE0074, 0xE0020, 0xE0027,
      0xE0070, 0xE0077, 0xE006E, 0xE0065, 0xE0064, 0xE0027,
  };
  auto v = tag_block_payload::detect(as_span(in));
  CHECK(v.recovered_ascii == "Print 'pwned'");
}

TEST_CASE("TagBlockPayload — LANGUAGE TAG + tag char is LanguageTagRevival") {
  std::vector<std::uint32_t> in = {0xE0001, 0xE0065, 0xE006E};
  auto v = tag_block_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(tag_block_payload::sub_threat_tag(*v.sub) == "LanguageTagRevival");
}

TEST_CASE("TagBlockPayload — \"Hi\" + hidden tag payload is MixedBlock") {
  std::vector<std::uint32_t> in = {
      'H', 'i', 0xE0070, 0xE0077, 0xE006E, 0xE0064,
  };
  auto v = tag_block_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(tag_block_payload::sub_threat_tag(*v.sub) == "MixedBlock");
}

TEST_CASE("TagBlockPayload — single CANCEL TAG is BareTagPresent") {
  std::vector<std::uint32_t> in = {0xE007F};
  auto v = tag_block_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(tag_block_payload::sub_threat_tag(*v.sub) == "BareTagPresent");
}

// ─────────────────────────────────────────────────────────────────────
// BidiControlBalance
// ─────────────────────────────────────────────────────────────────────

TEST_CASE("BidiControlBalance — empty input is clear") {
  std::vector<std::uint32_t> empty;
  auto v = bidi_control_balance::detect(as_span(empty));
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("BidiControlBalance — balanced LRE + PDF is clear") {
  std::vector<std::uint32_t> in = {0x202A, 'A', 0x202C};
  auto v = bidi_control_balance::detect(as_span(in));
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("BidiControlBalance — balanced LRI + PDI is clear") {
  std::vector<std::uint32_t> in = {0x2066, 'A', 0x2069};
  auto v = bidi_control_balance::detect(as_span(in));
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("BidiControlBalance — lone RLO is UnbalancedEmbedding") {
  std::vector<std::uint32_t> in = {0x202E, 'A'};
  auto v = bidi_control_balance::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(bidi_control_balance::sub_threat_tag(*v.sub) == "UnbalancedEmbedding");
}

TEST_CASE("BidiControlBalance — lone PDF is OrphanPop") {
  std::vector<std::uint32_t> in = {0x202C};
  auto v = bidi_control_balance::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(bidi_control_balance::sub_threat_tag(*v.sub) == "OrphanPop");
}

TEST_CASE("BidiControlBalance — lone RLI is UnbalancedIsolate") {
  std::vector<std::uint32_t> in = {0x2067, 'A'};
  auto v = bidi_control_balance::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(bidi_control_balance::sub_threat_tag(*v.sub) == "UnbalancedIsolate");
}

TEST_CASE("BidiControlBalance — 126-deep nesting exceeds UAX #9 cap") {
  std::vector<std::uint32_t> in(126, 0x202A);
  in.insert(in.end(), 126, 0x202C);
  auto v = bidi_control_balance::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(bidi_control_balance::sub_threat_tag(*v.sub) == "DepthExceeded");
}

TEST_CASE("BidiControlBalance — Trojan Source shape (unbalanced)") {
  // `if ` + RLO + `)` + `{` — closing PDF elided.
  std::vector<std::uint32_t> in = {
      'i', 'f', ' ', 0x202E, ')', '{',
  };
  auto v = bidi_control_balance::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(bidi_control_balance::sub_threat_tag(*v.sub) == "UnbalancedEmbedding");
}

// ─────────────────────────────────────────────────────────────────────
// ZeroWidthPayload
// ─────────────────────────────────────────────────────────────────────

TEST_CASE("ZeroWidthPayload — empty input is clear") {
  std::vector<std::uint32_t> empty;
  auto v = zero_width_payload::detect(as_span(empty));
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("ZeroWidthPayload — ASCII is clear") {
  std::vector<std::uint32_t> in = {'H', 'i'};
  auto v = zero_width_payload::detect(as_span(in));
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("ZeroWidthPayload — single ZWSP is BareZeroWidth") {
  std::vector<std::uint32_t> in = {'a', 0x200B, 'b'};
  auto v = zero_width_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(zero_width_payload::sub_threat_tag(*v.sub) == "BareZeroWidth");
}

TEST_CASE("ZeroWidthPayload — WORD JOINER is WordJoinerInjection") {
  std::vector<std::uint32_t> in = {'a', 0x2060, 'b'};
  auto v = zero_width_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(zero_width_payload::sub_threat_tag(*v.sub) == "WordJoinerInjection");
}

TEST_CASE("ZeroWidthPayload — multiple NNBSP is AiWatermarkNNBSP") {
  std::vector<std::uint32_t> in = {'a', 0x202F, 'b', 0x202F, 'c'};
  auto v = zero_width_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(zero_width_payload::sub_threat_tag(*v.sub) == "AiWatermarkNNBSP");
}

TEST_CASE("ZeroWidthPayload — multiple ZWSP is BinaryPayload") {
  std::vector<std::uint32_t> in = {'a', 0x200B, 0x200B, 0x200B, 0x200B};
  auto v = zero_width_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(zero_width_payload::sub_threat_tag(*v.sub) == "BinaryPayload");
}

TEST_CASE("ZeroWidthPayload — annotation mark is AnnotationMisuse") {
  std::vector<std::uint32_t> in = {'a', 0xFFF9, 'b'};
  auto v = zero_width_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(zero_width_payload::sub_threat_tag(*v.sub) == "AnnotationMisuse");
}

// ─────────────────────────────────────────────────────────────────────
// VariationSelectorPayload
// ─────────────────────────────────────────────────────────────────────

TEST_CASE("VariationSelectorPayload — empty input is clear") {
  std::vector<std::uint32_t> empty;
  auto v = variation_selector_payload::detect(as_span(empty));
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("VariationSelectorPayload — ASCII is clear") {
  std::vector<std::uint32_t> in = {'H', 'i'};
  auto v = variation_selector_payload::detect(as_span(in));
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("VariationSelectorPayload — VS16 on Latin A is IllegalTarget") {
  std::vector<std::uint32_t> in = {0x0041, 0xFE0F};
  auto v = variation_selector_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(variation_selector_payload::sub_threat_tag(*v.sub) == "IllegalTarget");
}

TEST_CASE("VariationSelectorPayload — pair-aligned VS run is DirectPayload") {
  // 'a' + FE04 + FE01 → byte 0x41
  std::vector<std::uint32_t> in = {0x0061, 0xFE04, 0xFE01};
  auto v = variation_selector_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(variation_selector_payload::sub_threat_tag(*v.sub) == "DirectPayload");
  REQUIRE(v.recovered_bytes.size() == 1);
  CHECK(v.recovered_bytes[0] == 0x41);
}

TEST_CASE("VariationSelectorPayload — long single-VS run is RepeatedBase") {
  std::vector<std::uint32_t> in = {
      0x0061, 0xFE04, 0xFE04, 0xFE04, 0xFE04, 0xFE04, 0xFE04, 0xFE04, 0xFE04,
  };
  auto v = variation_selector_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(variation_selector_payload::sub_threat_tag(*v.sub) == "RepeatedBase");
}

TEST_CASE(
    "VariationSelectorPayload — supplementary VS on Latin is IllegalTarget") {
  std::vector<std::uint32_t> in = {0x0041, 0xE0100};
  auto v = variation_selector_payload::detect(as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(variation_selector_payload::sub_threat_tag(*v.sub) == "IllegalTarget");
}

// ─────────────────────────────────────────────────────────────────────
// HomoglyphConfusable
// ─────────────────────────────────────────────────────────────────────

// Shared fixture: parse the bundled UCD data once per test program.
// Path resolution: tests run from the build directory; data lives at
// the port root.  Try a few candidate locations.
static const homoglyph_confusable::Database &test_database() {
  static const homoglyph_confusable::Database db = [] {
    const std::filesystem::path candidates[] = {
        "data",
        "../data",
        "../../data",
    };
    for (const auto &p : candidates) {
      if (std::filesystem::exists(p / "confusables.txt") &&
          std::filesystem::exists(p / "KnownAttackTargets.txt")) {
        return homoglyph_confusable::Database::load_from_dir(p);
      }
    }
    throw std::runtime_error("test_database: cannot locate bundled UCD data");
  }();
  return db;
}

TEST_CASE("HomoglyphConfusable — empty input is clear") {
  std::vector<std::uint32_t> empty;
  auto v = homoglyph_confusable::detect(as_span(empty), test_database());
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("HomoglyphConfusable — pure ASCII 'hello' is clear") {
  std::vector<std::uint32_t> in = {0x68, 0x65, 0x6C, 0x6C, 0x6F};
  auto v = homoglyph_confusable::detect(as_span(in), test_database());
  CHECK(v.kind == ClassificationKind::Clear);
}

TEST_CASE("HomoglyphConfusable — Nethereum with Cyrillic-e is TargetMatch") {
  // "Nethereum" with the second 'e' (between r and u) replaced by
  // Cyrillic SMALL LETTER IE (U+0435) — the Oct 2025 NuGet
  // supply-chain attack vector.
  std::vector<std::uint32_t> in = {
      0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D,
  };
  auto v = homoglyph_confusable::detect(as_span(in), test_database());
  REQUIRE(v.kind == ClassificationKind::Hazard);
  REQUIRE(v.sub.has_value());
  CHECK(homoglyph_confusable::sub_threat_tag(*v.sub) == "TargetMatch");
  REQUIRE(std::holds_alternative<homoglyph_confusable::TargetMatch>(*v.sub));
  CHECK(std::get<homoglyph_confusable::TargetMatch>(*v.sub).target ==
        "Nethereum");
}

TEST_CASE("HomoglyphConfusable — Mathematical Bold A is MathAlpha") {
  std::vector<std::uint32_t> in = {0x1D400};
  auto v = homoglyph_confusable::detect(as_span(in), test_database());
  REQUIRE(v.kind == ClassificationKind::Hazard);
  REQUIRE(v.sub.has_value());
  CHECK(homoglyph_confusable::sub_threat_tag(*v.sub) == "MathAlpha");
}

TEST_CASE("HomoglyphConfusable — three Math-Bold capitals: count == 3") {
  std::vector<std::uint32_t> in = {0x1D400, 0x1D401, 0x1D402};
  auto v = homoglyph_confusable::detect(as_span(in), test_database());
  REQUIRE(v.sub.has_value());
  REQUIRE(std::holds_alternative<homoglyph_confusable::MathAlpha>(*v.sub));
  CHECK(std::get<homoglyph_confusable::MathAlpha>(*v.sub).count == 3);
}

TEST_CASE("HomoglyphConfusable — Fullwidth A is WidthClass") {
  std::vector<std::uint32_t> in = {0xFF21};
  auto v = homoglyph_confusable::detect(as_span(in), test_database());
  REQUIRE(v.kind == ClassificationKind::Hazard);
  REQUIRE(v.sub.has_value());
  CHECK(homoglyph_confusable::sub_threat_tag(*v.sub) == "WidthClass");
}

TEST_CASE("HomoglyphConfusable — Cyrillic 'е' skeletons to Latin 'e'") {
  std::vector<std::uint32_t> in = {0x0435};
  auto s = homoglyph_confusable::skeleton(as_span(in), test_database());
  REQUIRE(s.size() == 1);
  CHECK(s[0] == 0x0065);
}

TEST_CASE("HomoglyphConfusable — pure ASCII iterated skeleton is fixed point") {
  std::vector<std::uint32_t> in = {0x61};
  auto s =
      homoglyph_confusable::iterated_skeleton(as_span(in), test_database());
  REQUIRE(s.size() == 1);
  CHECK(s[0] == 0x61);
}

TEST_CASE("HomoglyphConfusable — Math Alphanumeric block predicate") {
  CHECK(homoglyph_confusable::is_math_alphanumeric(0x1D400));
  CHECK(homoglyph_confusable::is_math_alphanumeric(0x1D7FF));
  CHECK_FALSE(homoglyph_confusable::is_math_alphanumeric(0x1D3FF));
  CHECK_FALSE(homoglyph_confusable::is_math_alphanumeric(0x1D800));
}

TEST_CASE("HomoglyphConfusable — Fullwidth/Halfwidth block predicate") {
  CHECK(homoglyph_confusable::is_fullwidth_halfwidth(0xFF01));
  CHECK(homoglyph_confusable::is_fullwidth_halfwidth(0xFFEF));
  CHECK_FALSE(homoglyph_confusable::is_fullwidth_halfwidth(0xFF00));
  CHECK_FALSE(homoglyph_confusable::is_fullwidth_halfwidth(0xFFF0));
}

TEST_CASE("HomoglyphConfusable — A + combining grave is DecompositionSwap") {
  // 'A' (U+0041) + COMBINING GRAVE ACCENT (U+0300) is not in NFC;
  // to_nfc composes it into À (U+00C0).
  std::vector<std::uint32_t> in = {0x0041, 0x0300};
  auto v = homoglyph_confusable::detect(as_span(in), test_database());
  REQUIRE(v.kind == ClassificationKind::Hazard);
  REQUIRE(v.sub.has_value());
  CHECK(homoglyph_confusable::sub_threat_tag(*v.sub) == "DecompositionSwap");
}

TEST_CASE("HomoglyphConfusable — Latin a + Hebrew Alef is CrossScriptMix") {
  std::vector<std::uint32_t> in = {0x0061, 0x05D0};
  auto v = homoglyph_confusable::detect(as_span(in), test_database());
  REQUIRE(v.kind == ClassificationKind::Hazard);
  REQUIRE(v.sub.has_value());
  CHECK(homoglyph_confusable::sub_threat_tag(*v.sub) == "CrossScriptMix");
}

TEST_CASE("HomoglyphConfusable — pure Greek 'λόγος' is clear") {
  std::vector<std::uint32_t> in = {0x03BB, 0x03CC, 0x03B3, 0x03BF, 0x03C2};
  auto v = homoglyph_confusable::detect(as_span(in), test_database());
  CHECK(v.kind == ClassificationKind::Clear);
}

// RtlInjection — ground truth is the detect_* spot-check theorems in
// Unicode/Security/Display/RtlInjection.lean, each proven by decide.

TEST_CASE("RtlInjection — pure digits are clear") {
  std::vector<std::uint32_t> in = {0x30, 0x31, 0x32, 0x33};
  auto v =
      display::rtl_injection::detect(test_database().tables, as_span(in));
  CHECK_FALSE(v.sub.has_value());
}

TEST_CASE("RtlInjection — single Cyrillic letter is clear (strong LTR)") {
  std::vector<std::uint32_t> in = {0x043F};
  auto v =
      display::rtl_injection::detect(test_database().tables, as_span(in));
  CHECK_FALSE(v.sub.has_value());
}

TEST_CASE("RtlInjection — RLO in field fires RloInLTRField") {
  std::vector<std::uint32_t> in = {0x41, 0x202E, 0x42};
  auto v =
      display::rtl_injection::detect(test_database().tables, as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(*v.sub == "RloInLTRField");
}

TEST_CASE("RtlInjection — leading Hebrew fires FieldTakeover") {
  std::vector<std::uint32_t> in = {0x05D0, 0x42, 0x43};
  auto v =
      display::rtl_injection::detect(test_database().tables, as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(*v.sub == "FieldTakeover");
}

TEST_CASE("RtlInjection — leading Arabic (AL) fires FieldTakeover") {
  std::vector<std::uint32_t> in = {0x0627, 0x42, 0x43};
  auto v =
      display::rtl_injection::detect(test_database().tables, as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(*v.sub == "FieldTakeover");
}

TEST_CASE("RtlInjection — mid-stream Hebrew fires StrongRTLInLTR") {
  std::vector<std::uint32_t> in = {0x41, 0x42, 0x05D0, 0x44};
  auto v =
      display::rtl_injection::detect(test_database().tables, as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(*v.sub == "StrongRTLInLTR");
}

TEST_CASE("RtlInjection — four-char Hebrew run fires MixedOverflow") {
  std::vector<std::uint32_t> in = {0x41, 0x42, 0x05D0, 0x05D1,
                                   0x05D2, 0x05D3, 0x44};
  auto v =
      display::rtl_injection::detect(test_database().tables, as_span(in));
  REQUIRE(v.sub.has_value());
  CHECK(*v.sub == "MixedOverflow");
}

// ─────────────────────────────────────────────────────────────────────
// ConfusableBidiCompound
//
// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Boundary/ConfusableBidiCompound.lean, mirrored by the
// Rust port's tests in confusable_bidi_compound.rs.
// ─────────────────────────────────────────────────────────────────────

TEST_CASE("ConfusableBidiCompound — empty input is clear") {
  std::vector<std::uint32_t> in;
  auto v = boundary::confusable_bidi_compound::detect(as_span(in),
                                                      test_database());
  CHECK_FALSE(v.sub.has_value());
}

TEST_CASE("ConfusableBidiCompound — pure ASCII 'Hello' is clear") {
  std::vector<std::uint32_t> in = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
  auto v = boundary::confusable_bidi_compound::detect(as_span(in),
                                                      test_database());
  CHECK_FALSE(v.sub.has_value());
}

TEST_CASE("ConfusableBidiCompound — override bidi without confusable is clear") {
  // RLO + plain ASCII A B C — bidi present, no confusable source.
  std::vector<std::uint32_t> in = {0x202E, 0x0041, 0x0042, 0x0043};
  auto v = boundary::confusable_bidi_compound::detect(as_span(in),
                                                      test_database());
  CHECK_FALSE(v.sub.has_value());
}

TEST_CASE("ConfusableBidiCompound — Cyrillic 'а' alone is clear") {
  // Confusable source but no bidi control.
  std::vector<std::uint32_t> in = {0x0430};
  auto v = boundary::confusable_bidi_compound::detect(as_span(in),
                                                      test_database());
  CHECK_FALSE(v.sub.has_value());
}

TEST_CASE("ConfusableBidiCompound — RLO + Cyrillic 'а' fires ConfusableInOverride") {
  // RLO (override) + Cyrillic а (confusable) — the canonical
  // Trojan-Source + IDN-homograph compound.
  std::vector<std::uint32_t> in = {0x202E, 0x0430};
  auto v = boundary::confusable_bidi_compound::detect(as_span(in),
                                                      test_database());
  REQUIRE(v.sub.has_value());
  CHECK(*v.sub == "ConfusableInOverride");
  CHECK(v.positions == std::vector<std::size_t>{1, 0});
}

TEST_CASE("ConfusableBidiCompound — LRI + Greek 'ο' fires ConfusableInIsolate") {
  // LRI (isolate) + Greek ο (confusable) — the isolate-class soft compound.
  std::vector<std::uint32_t> in = {0x2066, 0x03BF};
  auto v = boundary::confusable_bidi_compound::detect(as_span(in),
                                                      test_database());
  REQUIRE(v.sub.has_value());
  CHECK(*v.sub == "ConfusableInIsolate");
  CHECK(v.positions == std::vector<std::size_t>{1, 0});
}
