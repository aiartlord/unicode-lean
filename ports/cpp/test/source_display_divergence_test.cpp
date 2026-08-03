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

#include "unicode_cpp/security/calculus.hpp"
#include "unicode_cpp/security/display/source_display_divergence.hpp"
#include "unicode_cpp/security/identity/homoglyph_confusable.hpp"
#include "unicode_cpp/security/policy.hpp"

namespace {

namespace sdd = unicode_cpp::security::display::source_display_divergence;
namespace homoglyph = unicode_cpp::security::homoglyph_confusable;
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
        "source-display-divergence test: cannot locate bundled UCD data");
}

// The homoglyph constituent reads a caller-owned identity database; build it
// once from the bundled data and reuse it across every detect call.
const homoglyph::Database& database() {
    static const homoglyph::Database db =
        homoglyph::Database::load_from_dir(data_dir());
    return db;
}

std::span<const std::uint32_t> as_span(const std::vector<std::uint32_t>& v) {
    return std::span<const std::uint32_t>(v.data(), v.size());
}

sdd::Detection det(const std::vector<std::uint32_t>& in) {
    return sdd::detect(database(), as_span(in));
}

// The aggregate sub-threat tag as an owning optional, mirroring the Rust
// reference's `sub(input)`. Owning (not a view) so it never dangles past the
// scanned Detection.
std::optional<std::string> sub(const std::vector<std::uint32_t>& in) {
    return det(in).sub;
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
    throw std::runtime_error("cannot locate source-display-divergence fixture");
}

}  // namespace

// ── §5 detect spot checks (one per Rust reference theorem) ───────────────

TEST_CASE("SourceDisplayDivergence — clear cases") {
    CHECK(det({}).is_clear());
    // "Hello world"
    CHECK(det({0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64})
              .is_clear());
    // "let x = 1;"
    CHECK(det({0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B})
              .is_clear());
}

TEST_CASE("SourceDisplayDivergence — single fire passthrough") {
    using SS = std::optional<std::string>;
    // tag-encoded "AB"
    CHECK(sub({0xE0041, 0xE0042}) == SS{"TagBlock"});
    // A + VS16
    CHECK(sub({0x0041, 0xFE0F}) == SS{"VariationSelector"});
    // H + ZWSP + i
    CHECK(sub({0x0048, 0x200B, 0x69}) == SS{"ZeroWidth"});
    // RLO + A
    CHECK(sub({0x202E, 0x41}) == SS{"BidiControl"});
    // "Neth<Cyrillic е>um"
    CHECK(sub({0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D})
          == SS{"IdentifierHomoglyph"});
}

TEST_CASE("SourceDisplayDivergence — two or more is compound") {
    using SS = std::optional<std::string>;
    // A + VS16 + ZWSP
    CHECK(sub({0x0041, 0xFE0F, 0x200B}) == SS{"Compound"});
    // tag "AB" + ZWSP
    CHECK(sub({0xE0041, 0xE0042, 0x200B}) == SS{"Compound"});
}

// ── Shared context-free fixture through detect + reason-code wiring ──────

TEST_CASE("SourceDisplayDivergence — shared detector fixture") {
    const auto text = read_fixture(
        "testdata/fixtures/security/detectors/source_display_divergence.json");
    const Json root = JsonParser{text}.parse();
    REQUIRE(root.field("schema").number == 1);
    CHECK(root.field("family").string == "source-display-divergence");

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
        // (Family::SourceDisplayDivergence, D layer).
        std::optional<std::string> emitted;
        if (auto verdict_tag = verdict.tag()) {
            emitted = policy::reason_code(
                Family::SourceDisplayDivergence,
                std::optional<std::string_view>{*verdict_tag});
        }

        const auto& required = test_case.field("required_findings").array;
        if (required.empty()) {
            CHECK(verdict.is_clear());
        } else {
            REQUIRE(emitted.has_value());
            for (const auto& finding : required) {
                CHECK(*emitted == finding.string);
            }
        }
    }
}
