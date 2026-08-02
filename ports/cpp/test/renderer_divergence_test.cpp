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
#include <variant>
#include <vector>

#include "unicode_cpp/security/calculus.hpp"
#include "unicode_cpp/security/display/renderer_divergence.hpp"
#include "unicode_cpp/security/identity/emoji_zwj_integrity.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"
#include "unicode_cpp/security/policy.hpp"

namespace {

namespace rd = unicode_cpp::security::display::renderer_divergence;
namespace ezwj = unicode_cpp::security::identity::emoji_zwj_integrity;
namespace ucd = unicode_cpp::security::ucd;
namespace policy = unicode_cpp::security::policy;
using unicode_cpp::security::Family;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data", "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "emoji-zwj-sequences.txt")) {
            return p;
        }
    }
    throw std::runtime_error(
        "renderer-divergence test: cannot locate bundled data");
}

const ezwj::RgiTable& rgi() {
    static const ezwj::RgiTable t = ezwj::RgiTable::load_from_dir(data_dir());
    return t;
}

const ucd::Tables& ucd_tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}

std::span<const std::uint32_t> as_span(const std::vector<std::uint32_t>& v) {
    return std::span<const std::uint32_t>(v.data(), v.size());
}

rd::Verdict det(const std::vector<std::uint32_t>& in) {
    return rd::detect(rgi(), ucd_tables(), as_span(in));
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
    throw std::runtime_error("cannot locate renderer-divergence fixture");
}

}  // namespace

// ── §5 detect spot checks (one per Rust reference theorem) ───────────────

TEST_CASE("RendererDivergence — detect_empty_clear") {
    CHECK(det({}).classify.is_clear());
}

TEST_CASE("RendererDivergence — detect_ascii_clear") {
    CHECK(det({0x48, 0x65, 0x6C, 0x6C, 0x6F}).classify.is_clear());
}

TEST_CASE("RendererDivergence — detect_han_clear") {
    CHECK(det({0x4E2D, 0x6587}).classify.is_clear());
}

TEST_CASE("RendererDivergence — detect_vs_variance") {
    using SV = std::optional<std::string_view>;
    CHECK(tag({0x1F600, 0xFE0F}) == SV{"VariationSelectorVariance"});
}

TEST_CASE("RendererDivergence — detect_rgi_family_clear") {
    const auto v =
        det({0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466});
    CHECK(v.classify.is_clear());
    CHECK(v.has_zwj);
}

TEST_CASE("RendererDivergence — detect_unregistered_zwj_variance") {
    using SV = std::optional<std::string_view>;
    CHECK(tag({0x1F468, 0x200D, 0x1F469}) == SV{"UnregisteredZwjVariance"});
}

TEST_CASE("RendererDivergence — detect_zalgo_variance") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x0061, 0x0301, 0x0302, 0x0303, 0x0304});
    CHECK(v.classify.tag() == SV{"CombiningStackOverflow"});
    CHECK(v.classify.positions == std::vector<std::size_t>{0});
    CHECK(v.combining_count == 4);
}

TEST_CASE("RendererDivergence — detect_fullwidth_variance") {
    using SV = std::optional<std::string_view>;
    CHECK(tag({0xFF21}) == SV{"FullwidthVariance"});
}

TEST_CASE("RendererDivergence — detect_mixed_direction") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x41, 0x42, 0x05D0, 0x05D1});
    CHECK(v.classify.tag() == SV{"MixedDirectionVariance"});
    CHECK(v.strong_ltr_count > 0);
    CHECK(v.strong_rtl_count > 0);
}

// ── priority-ladder structural checks ────────────────────────────────

TEST_CASE("RendererDivergence — combining_stack_beats_vs") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F});
    CHECK(v.classify.tag() == SV{"CombiningStackOverflow"});
}

TEST_CASE("RendererDivergence — three_marks_below_threshold") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x0061, 0x0301, 0x0302, 0x0303});
    CHECK(v.classify.tag() != SV{"CombiningStackOverflow"});
}

// ── Shared context-free fixture through detect + reason-code wiring ──────

TEST_CASE("RendererDivergence — shared detector fixture") {
    const auto text = read_fixture(
        "testdata/fixtures/security/detectors/renderer_divergence.json");
    const Json root = JsonParser{text}.parse();
    REQUIRE(root.field("schema").number == 1);
    CHECK(root.field("family").string == "renderer-divergence");

    for (const auto& test_case : root.field("cases").array) {
        const std::string name = test_case.field("name").string;
        INFO(name);

        std::vector<std::uint32_t> input;
        for (const auto& value : test_case.field("input").array) {
            input.push_back(static_cast<std::uint32_t>(value.number));
        }

        const auto verdict = det(input);

        // Reason code the policy layer would emit for this verdict, wired
        // exactly as the sibling display detectors do
        // (Family::RendererDivergence, D layer).
        std::optional<std::string> emitted;
        if (auto verdict_tag = verdict.classify.tag()) {
            emitted = policy::reason_code(
                Family::RendererDivergence,
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
