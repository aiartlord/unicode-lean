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
#include "unicode_cpp/security/display/filename_disguise.hpp"
#include "unicode_cpp/security/policy.hpp"

namespace {

namespace fd = unicode_cpp::security::display::filename_disguise;
namespace policy = unicode_cpp::security::policy;
using unicode_cpp::security::Family;

std::span<const std::uint32_t> as_span(const std::vector<std::uint32_t>& v) {
    return std::span<const std::uint32_t>(v.data(), v.size());
}

fd::Verdict det(const std::vector<std::uint32_t>& in) {
    return fd::detect(as_span(in));
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
    throw std::runtime_error("cannot locate filename-disguise fixture");
}

}  // namespace

// ── §5 detect spot checks (one per Rust reference theorem) ───────────────

TEST_CASE("FilenameDisguise — detect_empty_clear") {
    CHECK(det({}).classify.is_clear());
}

TEST_CASE("FilenameDisguise — detect_plain_txt_clear") {
    const auto v = det({0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E,
                        0x74, 0x78, 0x74});
    CHECK(v.classify.is_clear());
    CHECK(v.last_dot_pos == std::optional<std::size_t>{8});
}

TEST_CASE("FilenameDisguise — detect_no_extension_clear") {
    const auto v = det({0x66, 0x6F, 0x6F});
    CHECK(v.classify.is_clear());
    CHECK(v.last_dot_pos == std::optional<std::size_t>{});
}

TEST_CASE("FilenameDisguise — detect_tar_gz_clear") {
    CHECK(det({0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61,
               0x72, 0x2E, 0x67, 0x7A})
              .classify.is_clear());
}

TEST_CASE("FilenameDisguise — detect_hebrew_clear") {
    CHECK(det({0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74})
              .classify.is_clear());
}

TEST_CASE("FilenameDisguise — detect_rlo_flip") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E,
                        0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65});
    CHECK(v.classify.tag() == SV{"RloFlip"});
    CHECK(v.classify.positions == std::vector<std::size_t>{8});
}

TEST_CASE("FilenameDisguise — detect_isolate_flip") {
    using SV = std::optional<std::string_view>;
    CHECK(tag({0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78,
               0x65, 0x2069})
          == SV{"RloFlip"});
}

TEST_CASE("FilenameDisguise — detect_fullwidth_exe") {
    using SV = std::optional<std::string_view>;
    CHECK(tag({0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25})
          == SV{"WidthClassExt"});
}

TEST_CASE("FilenameDisguise — detect_combining_in_ext") {
    using SV = std::optional<std::string_view>;
    CHECK(tag({0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65})
          == SV{"CombiningInExt"});
}

TEST_CASE("FilenameDisguise — detect_triple_extension") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72,
                        0x2E, 0x67, 0x7A, 0x2E, 0x73, 0x69, 0x67});
    CHECK(v.classify.tag() == SV{"MultipleExtensions"});
}

// ── priority-ladder structural check ────────────────────────────────────

TEST_CASE("FilenameDisguise — bidi_beats_fullwidth") {
    using SV = std::optional<std::string_view>;
    CHECK(tag({0x202E, 0x66, 0x2E, 0xFF25}) == SV{"RloFlip"});
}

// ── Shared context-free fixture through detect + reason-code wiring ──────

TEST_CASE("FilenameDisguise — shared detector fixture") {
    const auto text = read_fixture(
        "testdata/fixtures/security/detectors/filename_disguise.json");
    const Json root = JsonParser{text}.parse();
    REQUIRE(root.field("schema").number == 1);
    CHECK(root.field("family").string == "filename-disguise");

    for (const auto& test_case : root.field("cases").array) {
        const std::string name = test_case.field("name").string;
        INFO(name);

        std::vector<std::uint32_t> input;
        for (const auto& value : test_case.field("input").array) {
            input.push_back(static_cast<std::uint32_t>(value.number));
        }

        const auto verdict = det(input);

        // Reason code the policy layer would emit for this verdict, wired
        // exactly as the sibling display detectors do (Family::FilenameDisguise,
        // D layer).
        std::optional<std::string> emitted;
        if (auto verdict_tag = verdict.classify.tag()) {
            emitted = policy::reason_code(
                Family::FilenameDisguise,
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
