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
#include "unicode_cpp/security/identity/skin_tone_variation_forgery.hpp"
#include "unicode_cpp/security/policy.hpp"

namespace {

namespace stvf =
    unicode_cpp::security::identity::skin_tone_variation_forgery;
namespace policy = unicode_cpp::security::policy;
using unicode_cpp::security::Family;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data",
                                                "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "emoji-data.txt")) {
            return p;
        }
    }
    throw std::runtime_error(
        "skin-tone-variation-forgery test: cannot locate bundled data");
}

const stvf::EmojiPropertyTable& props() {
    static const stvf::EmojiPropertyTable t =
        stvf::EmojiPropertyTable::load_from_dir(data_dir());
    return t;
}

std::span<const std::uint32_t> as_span(const std::vector<std::uint32_t>& v) {
    return std::span<const std::uint32_t>(v.data(), v.size());
}

stvf::Verdict det(const std::vector<std::uint32_t>& in) {
    return stvf::detect(props(), as_span(in));
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
    throw std::runtime_error(
        "cannot locate skin-tone-variation-forgery fixture");
}

}  // namespace

// ── §2/§3 data-layer sanity ─────────────────────────────────────────────

TEST_CASE("SkinToneVariationForgery — is_skin_tone reuses port modifier range") {
    CHECK(stvf::is_skin_tone(0x1F3FB));
    CHECK(stvf::is_skin_tone(0x1F3FF));
    CHECK(!stvf::is_skin_tone(0x1F3FA));
    CHECK(!stvf::is_skin_tone(0x1F600));
}

TEST_CASE("SkinToneVariationForgery — Emoji_Modifier_Base table") {
    // U+1F44B WAVING HAND lies in the 1F446..1F450 modifier-base range.
    CHECK(props().is_skin_tone_base(0x1F44B));
    // U+1F600 GRINNING FACE is emoji-presentation but not a modifier base.
    CHECK(!props().is_skin_tone_base(0x1F600));
    // ASCII 'A' is not a modifier base.
    CHECK(!props().is_skin_tone_base(0x0041));
}

TEST_CASE("SkinToneVariationForgery — Emoji_Presentation table") {
    CHECK(props().is_emoji_presentation(0x1F600));
    CHECK(!props().is_emoji_presentation(0x0041));
}

TEST_CASE("SkinToneVariationForgery — variation-selector predicates") {
    CHECK(stvf::is_vs15(0xFE0E));
    CHECK(!stvf::is_vs15(0xFE0F));
    CHECK(stvf::is_vs16(0xFE0F));
    CHECK(!stvf::is_vs16(0xFE0E));
}

// ── §5 detect spot checks (one per Rust reference theorem) ───────────────

TEST_CASE("SkinToneVariationForgery — detect_empty_clear") {
    const auto v = det({});
    CHECK(v.classify.is_clear());
    CHECK(v.classify.tag() == std::nullopt);
    CHECK(v.skin_tone_count == 0);
    CHECK(v.variation_selector15_count == 0);
    CHECK(v.variation_selector16_count == 0);
}

TEST_CASE("SkinToneVariationForgery — detect_ascii_clear") {
    CHECK(det({0x48, 0x65}).classify.is_clear());
}

TEST_CASE("SkinToneVariationForgery — detect_plain_emoji_clear") {
    CHECK(det({0x1F600}).classify.is_clear());
}

TEST_CASE("SkinToneVariationForgery — detect_wave_skin_tone_clear") {
    const auto v = det({0x1F44B, 0x1F3FB});
    CHECK(v.classify.is_clear());
    CHECK(v.skin_tone_count == 1);
}

TEST_CASE("SkinToneVariationForgery — detect_stacked_skin_tones") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x1F44B, 0x1F3FB, 0x1F3FC});
    CHECK(v.classify.tag() == SV{"StackedSkinTones"});
    CHECK(v.classify.positions == std::vector<std::size_t>{1, 2});
    REQUIRE(v.classify.sub.has_value());
    const auto* stacked =
        std::get_if<stvf::StackedSkinTones>(&*v.classify.sub);
    REQUIRE(stacked != nullptr);
    CHECK(stacked->base_pos == 0);
    CHECK(stacked->modifiers ==
          std::vector<std::uint32_t>{0x1F3FB, 0x1F3FC});
}

TEST_CASE("SkinToneVariationForgery — detect_invalid_target_ascii") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x0041, 0x1F3FB});
    CHECK(v.classify.tag() == SV{"InvalidSkinToneTarget"});
    CHECK(v.classify.positions == std::vector<std::size_t>{1});
    REQUIRE(v.classify.sub.has_value());
    const auto* invalid =
        std::get_if<stvf::InvalidSkinToneTarget>(&*v.classify.sub);
    REQUIRE(invalid != nullptr);
    CHECK(invalid->base_pos == 0);
    CHECK(invalid->base_cp == 0x0041);
    CHECK(invalid->modifier_cp == 0x1F3FB);
}

TEST_CASE("SkinToneVariationForgery — detect_invalid_target_smiley") {
    using SV = std::optional<std::string_view>;
    CHECK(tag({0x1F600, 0x1F3FB}) == SV{"InvalidSkinToneTarget"});
}

TEST_CASE("SkinToneVariationForgery — detect_forced_text_style") {
    using SV = std::optional<std::string_view>;
    const auto v = det({0x1F600, 0xFE0E});
    CHECK(v.classify.tag() == SV{"ForcedTextStyle"});
    CHECK(v.classify.positions == std::vector<std::size_t>{1});
    CHECK(v.variation_selector15_count == 1);
    REQUIRE(v.classify.sub.has_value());
    const auto* forced = std::get_if<stvf::ForcedTextStyle>(&*v.classify.sub);
    REQUIRE(forced != nullptr);
    CHECK(forced->base_pos == 0);
    CHECK(forced->base_cp == 0x1F600);
}

// ── priority ladder ──────────────────────────────────────────────────────

TEST_CASE("SkinToneVariationForgery — stacked beats invalid-target") {
    using SV = std::optional<std::string_view>;
    // grinning face (non-modifier-base) followed by two skin tones: both the
    // stacked and the invalid-target conditions hold; stacked wins.
    CHECK(tag({0x1F600, 0x1F3FB, 0x1F3FC}) == SV{"StackedSkinTones"});
}

// ── reason-code wiring ───────────────────────────────────────────────────

TEST_CASE("SkinToneVariationForgery — reason_code_is_stable") {
    CHECK(policy::reason_code(
              Family::SkinToneVariationForgery,
              std::optional<std::string_view>{"StackedSkinTones"}) ==
          "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones");
    CHECK(policy::reason_code(
              Family::SkinToneVariationForgery,
              std::optional<std::string_view>{"ForcedTextStyle"}) ==
          "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle");
}

// ── Shared context-free fixture through detect + reason-code wiring ──────

TEST_CASE("SkinToneVariationForgery — shared detector fixture") {
    const auto text = read_fixture(
        "testdata/fixtures/security/detectors/"
        "skin_tone_variation_forgery.json");
    const Json root = JsonParser{text}.parse();
    REQUIRE(root.field("schema").number == 1);
    CHECK(root.field("family").string == "skin-tone-variation-forgery");

    for (const auto& test_case : root.field("cases").array) {
        const std::string name = test_case.field("name").string;
        INFO(name);

        std::vector<std::uint32_t> input;
        for (const auto& value : test_case.field("input").array) {
            input.push_back(static_cast<std::uint32_t>(value.number));
        }

        const auto verdict = det(input);

        // Reason code the policy layer would emit for this verdict, wired
        // exactly as the sibling identity detectors do
        // (Family::SkinToneVariationForgery, I layer).
        std::optional<std::string> emitted;
        if (auto verdict_tag = verdict.classify.tag()) {
            emitted = policy::reason_code(
                Family::SkinToneVariationForgery,
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
