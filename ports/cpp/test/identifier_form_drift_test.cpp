#include <doctest/doctest.h>

#include <cctype>
#include <cstddef>
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

#include "unicode_cpp/security/boundary/identifier_form_drift.hpp"
#include "unicode_cpp/security/calculus.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"
#include "unicode_cpp/security/policy.hpp"

namespace {

namespace ifd = unicode_cpp::security::boundary::identifier_form_drift;
namespace ucd = unicode_cpp::security::ucd;
namespace policy = unicode_cpp::security::policy;
using unicode_cpp::security::Family;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data", "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "UnicodeData.txt")) {
            return p;
        }
    }
    throw std::runtime_error(
        "identifier-form-drift test: cannot locate bundled UCD data");
}

const ucd::Tables& tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}

std::span<const std::uint32_t> as_span(const std::vector<std::uint32_t>& v) {
    return std::span<const std::uint32_t>(v.data(), v.size());
}

ifd::Verdict det(const std::vector<std::uint32_t>& in) {
    return ifd::detect(tables(), as_span(in));
}

std::optional<std::string_view> tag(const std::vector<std::uint32_t>& in) {
    return det(in).classify.tag();
}

// ── Minimal JSON reader for the shared detector fixture ─────────────────
struct Json {
    enum class Kind { Object, Array, String, Number };
    Kind kind = Kind::Number;
    std::vector<std::pair<std::string, Json>> object;
    std::vector<Json> array;
    std::string string;
    long number = 0;

    const Json& field(std::string_view key) const {
        for (const auto& [k, v] : object) {
            if (k == key) {
                return v;
            }
        }
        throw std::runtime_error("missing JSON field");
    }
};

class JsonParser {
public:
    explicit JsonParser(std::string_view input) : input_(input) {}

    Json parse() {
        skip_ws();
        Json value = parse_value();
        skip_ws();
        if (pos_ != input_.size()) {
            throw std::runtime_error("trailing JSON input");
        }
        return value;
    }

private:
    std::string_view input_;
    std::size_t pos_ = 0;

    void skip_ws() {
        while (pos_ < input_.size()
               && std::isspace(static_cast<unsigned char>(input_[pos_]))) {
            ++pos_;
        }
    }

    char peek() const {
        if (pos_ >= input_.size()) {
            throw std::runtime_error("unexpected end of JSON input");
        }
        return input_[pos_];
    }

    char take() {
        const char ch = peek();
        ++pos_;
        return ch;
    }

    void expect(char ch) {
        if (take() != ch) {
            throw std::runtime_error("unexpected JSON character");
        }
    }

    Json parse_value() {
        skip_ws();
        switch (peek()) {
        case '{':
            return parse_object();
        case '[':
            return parse_array();
        case '"':
            return parse_string_value();
        default:
            return parse_number();
        }
    }

    Json parse_object() {
        expect('{');
        skip_ws();
        Json out;
        out.kind = Json::Kind::Object;
        if (peek() == '}') {
            take();
            return out;
        }
        while (true) {
            skip_ws();
            std::string key = parse_string();
            skip_ws();
            expect(':');
            out.object.emplace_back(std::move(key), parse_value());
            skip_ws();
            const char ch = take();
            if (ch == '}') {
                break;
            }
            if (ch != ',') {
                throw std::runtime_error("expected object comma");
            }
        }
        return out;
    }

    Json parse_array() {
        expect('[');
        skip_ws();
        Json out;
        out.kind = Json::Kind::Array;
        if (peek() == ']') {
            take();
            return out;
        }
        while (true) {
            out.array.push_back(parse_value());
            skip_ws();
            const char ch = take();
            if (ch == ']') {
                break;
            }
            if (ch != ',') {
                throw std::runtime_error("expected array comma");
            }
        }
        return out;
    }

    Json parse_string_value() {
        Json out;
        out.kind = Json::Kind::String;
        out.string = parse_string();
        return out;
    }

    std::string parse_string() {
        expect('"');
        std::string out;
        while (true) {
            const char ch = take();
            if (ch == '"') {
                break;
            }
            if (ch != '\\') {
                out.push_back(ch);
                continue;
            }
            const char escaped = take();
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
                throw std::runtime_error("unsupported string escape");
            }
        }
        return out;
    }

    Json parse_number() {
        bool negative = false;
        if (peek() == '-') {
            negative = true;
            take();
        }
        long value = 0;
        bool saw_digit = false;
        while (pos_ < input_.size()
               && std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
            saw_digit = true;
            value = value * 10 + (take() - '0');
        }
        if (!saw_digit) {
            throw std::runtime_error("expected JSON number");
        }
        Json out;
        out.kind = Json::Kind::Number;
        out.number = negative ? -value : value;
        return out;
    }
};

std::string read_fixture(std::string_view relative) {
    const std::filesystem::path rel{relative};
    const std::filesystem::path candidates[] = {
        rel, std::filesystem::path{".."} / rel,
        std::filesystem::path{"../.."} / rel};
    for (const auto& path : candidates) {
        if (!std::filesystem::exists(path)) {
            continue;
        }
        std::ifstream in(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>{in},
                           std::istreambuf_iterator<char>{});
    }
    throw std::runtime_error("cannot locate identifier-form-drift fixture");
}

}  // namespace

// Ground truth: every detect_* theorem in the verified Rust reference
// implementation. The shared context-free fixture carries the eight
// context-free vectors.

// ── §5 detect spot checks (one per Rust reference theorem) ───────────────

TEST_CASE("IdentifierFormDrift — detect_empty_clear") {
    CHECK(det({}).classify.is_clear());
}

TEST_CASE("IdentifierFormDrift — detect_ascii_clear") {
    // "Hello"; every ASCII letter is Allowed with identity NFKD.
    const auto v = det({0x48, 0x65, 0x6C, 0x6C, 0x6F});
    CHECK(v.classify.is_clear());
    CHECK(v.shift_count == 0);
}

TEST_CASE("IdentifierFormDrift — detect_greek_alpha_clear") {
    // α is Allowed with identity NFKD.
    CHECK(det({0x03B1}).classify.is_clear());
}

TEST_CASE("IdentifierFormDrift — detect_math_italic_a_shift") {
    // U+1D44E Restricted, NFKD head U+0061 Allowed.
    using SV = std::optional<std::string_view>;
    const auto v = det({0x1D44E});
    CHECK(v.classify.tag() == SV{"IdentifierStatusShift"});
    CHECK(v.classify.positions == std::vector<std::size_t>{0});
    CHECK(v.shift_count == 1);
}

TEST_CASE("IdentifierFormDrift — detect_fullwidth_A_shift") {
    // U+FF21 Restricted, NFKD head U+0041 Allowed.
    using SV = std::optional<std::string_view>;
    CHECK(tag({0xFF21}) == SV{"IdentifierStatusShift"});
}

TEST_CASE("IdentifierFormDrift — detect_circled_A_shift") {
    // U+24B6 CIRCLED LATIN CAPITAL LETTER A → Restricted → Allowed (A).
    using SV = std::optional<std::string_view>;
    CHECK(tag({0x24B6}) == SV{"IdentifierStatusShift"});
}

TEST_CASE("IdentifierFormDrift — detect_fi_ligature_shift") {
    // U+FB01 'ﬁ' ligature → Restricted → Allowed (f).
    using SV = std::optional<std::string_view>;
    CHECK(tag({0xFB01}) == SV{"IdentifierStatusShift"});
}

TEST_CASE("IdentifierFormDrift — detect_roman_iv_shift") {
    // U+2163 ROMAN NUMERAL FOUR → Restricted → Allowed (I).
    using SV = std::optional<std::string_view>;
    CHECK(tag({0x2163}) == SV{"IdentifierStatusShift"});
}

TEST_CASE("IdentifierFormDrift — detect_reports_first_shift_position") {
    // "ab" + U+1D44E: positions 0,1 are Allowed/identity, position 2 shifts.
    const auto v = det({0x61, 0x62, 0x1D44E});
    CHECK(v.classify.positions == std::vector<std::size_t>{2});
    CHECK(v.shift_count == 1);
}

TEST_CASE("IdentifierFormDrift — reason_code_is_stable") {
    CHECK(policy::reason_code(Family::IdentifierFormDrift,
                              std::optional<std::string_view>{
                                  "IdentifierStatusShift"})
          == "unicode.security.X.identifier-form-drift.IdentifierStatusShift");
}

// ── Shared context-free fixture through detect + reason-code wiring ──────

TEST_CASE("IdentifierFormDrift — shared detector fixture") {
    const auto text = read_fixture(
        "testdata/fixtures/security/detectors/identifier_form_drift.json");
    const Json root = JsonParser{text}.parse();
    REQUIRE(root.field("schema").number == 1);
    CHECK(root.field("family").string == "identifier-form-drift");

    for (const auto& test_case : root.field("cases").array) {
        const std::string name = test_case.field("name").string;
        INFO(name);

        std::vector<std::uint32_t> input;
        for (const auto& value : test_case.field("input").array) {
            input.push_back(static_cast<std::uint32_t>(value.number));
        }

        const auto verdict = det(input);

        // Reason code the policy layer would emit for this verdict, wired
        // exactly as the sibling detectors do (Family::IdentifierFormDrift,
        // X layer).
        std::optional<std::string> emitted;
        if (auto verdict_tag = verdict.classify.tag()) {
            emitted = policy::reason_code(
                Family::IdentifierFormDrift,
                std::optional<std::string_view>{*verdict_tag});
        }

        const auto& required = test_case.field("required_findings").array;
        if (required.empty()) {
            CHECK(verdict.classify.is_clear());
        } else {
            REQUIRE(emitted.has_value());
            for (const auto& finding : required) {
                CHECK(*emitted == finding.string);
            }
        }
    }
}
