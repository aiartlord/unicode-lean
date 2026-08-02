#include <doctest/doctest.h>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "unicode_cpp/security/calculus.hpp"
#include "unicode_cpp/security/form/case_expansion_mismatch.hpp"
#include "unicode_cpp/security/identity/casing.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"
#include "unicode_cpp/security/policy.hpp"

namespace {

namespace ucd = unicode_cpp::security::ucd;
namespace casing = unicode_cpp::security::casing;
namespace cem = unicode_cpp::security::form::case_expansion_mismatch;
namespace policy = unicode_cpp::security::policy;
using unicode_cpp::security::Family;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data", "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "SpecialCasing.txt")) {
            return p;
        }
    }
    throw std::runtime_error(
        "case-expansion-mismatch test: cannot locate bundled UCD data");
}

const ucd::Tables& tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}

const casing::CasingData& casing_data() {
    static const casing::CasingData c = casing::CasingData::load_from_dir(data_dir());
    return c;
}

cem::Verdict det(const std::vector<std::uint32_t>& in) {
    return cem::detect(casing_data(), tables(), in);
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
        const char ch = peek();
        if (ch == '{') return parse_object();
        if (ch == '[') return parse_array();
        if (ch == '"') return parse_string_value();
        return parse_number();
    }

    Json parse_object() {
        Json out;
        out.kind = Json::Kind::Object;
        expect('{');
        skip_ws();
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
            if (ch == ',') continue;
            if (ch == '}') break;
            throw std::runtime_error("unexpected JSON object separator");
        }
        return out;
    }

    Json parse_array() {
        Json out;
        out.kind = Json::Kind::Array;
        expect('[');
        skip_ws();
        if (peek() == ']') {
            take();
            return out;
        }
        while (true) {
            out.array.push_back(parse_value());
            skip_ws();
            const char ch = take();
            if (ch == ',') continue;
            if (ch == ']') break;
            throw std::runtime_error("unexpected JSON array separator");
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
        std::string out;
        expect('"');
        while (true) {
            const char ch = take();
            if (ch == '"') break;
            if (ch == '\\') {
                out.push_back(take());
            } else {
                out.push_back(ch);
            }
        }
        return out;
    }

    Json parse_number() {
        Json out;
        out.kind = Json::Kind::Number;
        bool negative = false;
        if (peek() == '-') {
            negative = true;
            take();
        }
        long value = 0;
        while (pos_ < input_.size()
               && std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
            value = value * 10 + (take() - '0');
        }
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
    throw std::runtime_error("cannot locate case-expansion-mismatch fixture");
}

}  // namespace

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/CaseExpansionMismatch.lean.

TEST_CASE("CaseExpansionMismatch — detect_empty_clear") {
    CHECK(det({}).classify.is_clear());
    CHECK(det({}).max_expansion_len == 0);
}

TEST_CASE("CaseExpansionMismatch — detect_ascii_clear") {
    const auto v = det({0x48, 0x65, 0x6C, 0x6C, 0x6F});
    CHECK(v.classify.is_clear());
    CHECK(v.max_expansion_len == 1);
}

TEST_CASE("CaseExpansionMismatch — detect_sharp_s_upper") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x00DF});
    CHECK(v.classify.tag() == SV{"UpperExpansion"});
    CHECK(v.classify.positions == std::vector<std::size_t>{0});
    CHECK(v.upper_expansion_count == 1);
    CHECK(v.max_expansion_len == 2);
}

TEST_CASE("CaseExpansionMismatch — detect_fi_ligature_upper") {
    using SV = std::optional<std::string_view>;
    CHECK(tag({0xFB01}) == SV{"UpperExpansion"});
}

TEST_CASE("CaseExpansionMismatch — detect_dotted_I_lower") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x0130});
    CHECK(v.classify.tag() == SV{"LowerExpansion"});
    CHECK(v.lower_expansion_count == 1);
}

TEST_CASE("CaseExpansionMismatch — detect_ffi_ligature_len3") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0xFB03});
    CHECK(v.classify.tag() == SV{"UpperExpansion"});
    CHECK(v.max_expansion_len == 3);
}

TEST_CASE("CaseExpansionMismatch — detect_reports_first_expansion_position") {
    const auto v = det({0x61, 0x00DF});
    CHECK(v.classify.positions == std::vector<std::size_t>{1});
}

TEST_CASE("CaseExpansionMismatch — reason_code_is_stable") {
    CHECK(policy::reason_code(Family::CaseExpansionMismatch,
                              std::optional<std::string_view>{"UpperExpansion"})
          == "unicode.security.F.case-expansion-mismatch.UpperExpansion");
    CHECK(policy::reason_code(Family::CaseExpansionMismatch,
                              std::optional<std::string_view>{"LowerExpansion"})
          == "unicode.security.F.case-expansion-mismatch.LowerExpansion");
}

// ── Shared context-free fixture through detect + reason-code wiring ──────

TEST_CASE("CaseExpansionMismatch — shared detector fixture") {
    const auto text = read_fixture(
        "testdata/fixtures/security/detectors/case_expansion_mismatch.json");
    const Json root = JsonParser{text}.parse();
    REQUIRE(root.field("schema").number == 1);
    CHECK(root.field("family").string == "case-expansion-mismatch");

    for (const auto& test_case : root.field("cases").array) {
        const std::string name = test_case.field("name").string;
        INFO(name);

        std::vector<std::uint32_t> input;
        for (const auto& value : test_case.field("input").array) {
            input.push_back(static_cast<std::uint32_t>(value.number));
        }

        const auto verdict = det(input);

        // Reason code the policy layer would emit for this verdict, wired
        // exactly as the sibling form detectors do (Family::CaseExpansionMismatch,
        // F layer).
        std::optional<std::string> emitted;
        if (auto verdict_tag = verdict.classify.tag()) {
            emitted = policy::reason_code(
                Family::CaseExpansionMismatch,
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
