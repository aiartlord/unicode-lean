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
#include "unicode_cpp/security/crypto/ai_watermark_detectability.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"
#include "unicode_cpp/security/policy.hpp"

namespace {

namespace ucd = unicode_cpp::security::ucd;
namespace awd = unicode_cpp::security::crypto::ai_watermark_detectability;
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
        "ai-watermark-detectability test: cannot locate bundled data");
}

const ucd::Tables& tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}

const awd::EmojiTable& emoji() {
    static const awd::EmojiTable e = awd::EmojiTable::load_from_dir(data_dir());
    return e;
}

std::span<const std::uint32_t> as_span(const std::vector<std::uint32_t>& v) {
    return std::span<const std::uint32_t>(v.data(), v.size());
}

awd::Verdict det(const std::vector<std::uint32_t>& in) {
    return awd::detect(tables(), emoji(), as_span(in));
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
        "cannot locate ai-watermark-detectability fixture");
}

}  // namespace

// ── §4 probe spot checks ────────────────────────────────────────────────

TEST_CASE("AiWatermarkDetectability — codepoint probe spot checks") {
    CHECK(awd::detail::is_nnbsp(0x202F));
    CHECK(!awd::detail::is_nnbsp(0x20));
    CHECK(!awd::detail::is_nnbsp(0x3000));

    CHECK(awd::detail::is_zwj(0x200D));
    CHECK(!awd::detail::is_zwj(0x200B));
    CHECK(!awd::detail::is_zwj(0x200C));

    CHECK(awd::detail::is_variation_selector(0xFE00));
    CHECK(awd::detail::is_variation_selector(0xFE0F));
    CHECK(awd::detail::is_variation_selector(0xE0100));
    CHECK(!awd::detail::is_variation_selector(0x61));
    CHECK(!awd::detail::is_variation_selector(0x200D));

    CHECK(ucd::is_default_ignorable(tables(), 0x200B));
    CHECK(ucd::is_default_ignorable(tables(), 0x200D));
    CHECK(ucd::is_default_ignorable(tables(), 0x00AD));
    CHECK(!ucd::is_default_ignorable(tables(), 0x202F));
    CHECK(!ucd::is_default_ignorable(tables(), 0x61));
}

TEST_CASE("AiWatermarkDetectability — emoji + adjacency probes") {
    CHECK(emoji().is_emoji(0x1F600));
    CHECK(!emoji().is_emoji(0x200D));
    CHECK(!emoji().is_emoji(0x61));

    const std::vector<std::uint32_t> plain = {0x61, 0xFE0F, 0x62};
    CHECK(!awd::detail::is_adjacent_to_emoji(emoji(), as_span(plain), 1));

    const std::vector<std::uint32_t> after = {0x1F600, 0xFE0F};
    CHECK(awd::detail::is_adjacent_to_emoji(emoji(), as_span(after), 1));

    const std::vector<std::uint32_t> before = {0xFE0F, 0x1F600};
    CHECK(awd::detail::is_adjacent_to_emoji(emoji(), as_span(before), 0));
}

// ── §6 detect spot checks ───────────────────────────────────────────────

TEST_CASE("AiWatermarkDetectability — clear inputs") {
    CHECK(det({}).classify.is_clear());
    CHECK(det({0x61, 0x62, 0x63}).classify.is_clear());
    CHECK(det({0x4E2D, 0x6587}).classify.is_clear());
}

TEST_CASE("AiWatermarkDetectability — single-marker probes") {
    using SV = std::optional<std::string_view>;

    auto nnbsp = det({0x61, 0x202F, 0x62});
    CHECK(nnbsp.classify.tag() == SV{"NnbspBoundary"});
    CHECK(nnbsp.classify.positions == std::vector<std::size_t>{1});
    CHECK(nnbsp.marker_count == 1);

    auto vs = det({0x61, 0xFE0F, 0x62});
    CHECK(vs.classify.tag() == SV{"VariationSelectorCarrier"});
    CHECK(vs.marker_count == 1);

    CHECK(det({0x1F600, 0xFE0F}).classify.is_clear());

    auto zwj = det({0x61, 0x200D, 0x62});
    CHECK(zwj.classify.tag() == SV{"ZwjNonEmoji"});
    CHECK(zwj.marker_count == 1);

    CHECK(det({0x1F469, 0x200D, 0x1F52C}).classify.is_clear());

    auto soft = det({0x61, 0x00AD, 0x62});
    CHECK(soft.classify.tag() == SV{"DefaultIgnorableCarrier"});
    CHECK(soft.marker_count == 1);

    auto zwsp = det({0x61, 0x200B, 0x62});
    CHECK(zwsp.classify.tag() == SV{"DefaultIgnorableCarrier"});
    CHECK(zwsp.marker_count == 1);

    auto multi = det({0x61, 0x202F, 0x62, 0x202F, 0x63});
    CHECK(multi.classify.tag() == SV{"NnbspBoundary"});
    CHECK(multi.marker_count == 2);
    CHECK(multi.classify.positions == std::vector<std::size_t>{1, 3});
}

// ── §7 refinement-probe spot checks ─────────────────────────────────────

TEST_CASE("AiWatermarkDetectability — refinement probes") {
    using SV = std::optional<std::string_view>;

    auto adversarial = det({0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64});
    CHECK(adversarial.classify.tag() == SV{"Adversarial"});
    CHECK(adversarial.marker_count == 3);

    CHECK(tag({0x61, 0x202F, 0x62, 0x202F, 0x63}) == SV{"NnbspBoundary"});

    auto gpt5 = det({0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64});
    CHECK(gpt5.classify.tag() == SV{"Gpt5ZwspModulo"});
    CHECK(gpt5.marker_count == 3);

    CHECK(tag({0x61, 0x200B, 0x62, 0x200B, 0x63})
          == SV{"DefaultIgnorableCarrier"});

    auto smart = det({0x201C, 0x61, 0x62, 0x63, 0x201D});
    CHECK(smart.classify.tag() == SV{"SmartQuoteAlternation"});
    CHECK(smart.marker_count == 2);

    CHECK(det({0x201C, 0x61, 0x22, 0x201D}).classify.is_clear());

    auto em = det({0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014,
                   0x20, 0x65, 0x66});
    CHECK(em.classify.tag() == SV{"EmDashPattern"});
    CHECK(em.marker_count == 2);

    CHECK(det({0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66})
              .classify.is_clear());

    auto delve = det({0x64, 0x65, 0x6C, 0x76, 0x65});
    CHECK(delve.classify.tag() == SV{"StatisticalTokenChoice"});
    CHECK(delve.marker_count == 1);

    auto moreover = det({0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65,
                         0x72, 0x2C, 0x20});
    CHECK(moreover.classify.tag() == SV{"StatisticalTokenChoice"});
    CHECK(moreover.classify.positions == std::vector<std::size_t>{2});
}

TEST_CASE("AiWatermarkDetectability — unknown multi-category + priority") {
    using SV = std::optional<std::string_view>;

    auto nnbsp_di = det({0x61, 0x202F, 0x00AD, 0x62});
    CHECK(nnbsp_di.classify.tag() == SV{"Unknown"});
    CHECK(nnbsp_di.marker_count == 2);

    auto vs_zwj = det({0x61, 0xFE0F, 0x200D, 0x62});
    CHECK(vs_zwj.classify.tag() == SV{"Unknown"});
    CHECK(vs_zwj.marker_count == 2);

    auto nnbsp_zwj = det({0x61, 0x202F, 0x200D, 0x62});
    CHECK(nnbsp_zwj.classify.tag() == SV{"Unknown"});
    CHECK(nnbsp_zwj.marker_count == 2);

    CHECK(tag({0x61, 0x202F, 0x62}) == SV{"NnbspBoundary"});

    CHECK(tag({0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64})
          == SV{"Adversarial"});
    CHECK(tag({0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64})
          == SV{"Gpt5ZwspModulo"});
}

// ── §8 tolerance-parameterised probes ───────────────────────────────────

TEST_CASE("AiWatermarkDetectability — Context tolerance vectors") {
    using SV = std::optional<std::string_view>;
    // ZWSPs at 1, 3, 6 (gaps 2, 3). Bare detect (tolerance 0) does not fire
    // gpt5ZwspModulo; falls through to defaultIgnorableCarrier.
    const std::vector<std::uint32_t> jittered = {0x61, 0x200B, 0x62, 0x200B,
                                                 0x63, 0x64,   0x200B, 0x65};
    CHECK(tag(jittered) == SV{"DefaultIgnorableCarrier"});

    awd::Context ctx;
    ctx.zwsp_modulo_tolerance = 1;
    auto tolerant = awd::detect_with_context(tables(), emoji(), ctx,
                                             as_span(jittered));
    CHECK(tolerant.classify.tag() == SV{"Gpt5ZwspModulo"});

    // Default context matches bare detect.
    const std::vector<std::uint32_t> nnbsp = {0x61, 0x202F, 0x62};
    auto d = awd::detect(tables(), emoji(), as_span(nnbsp));
    auto c = awd::detect_with_context(tables(), emoji(), awd::Context{},
                                      as_span(nnbsp));
    CHECK(c.classify.tag() == d.classify.tag());
}

// ── §7 cue-class coverage ───────────────────────────────────────────────

TEST_CASE("AiWatermarkDetectability — cue-class coverage") {
    const awd::CueClass classes[] = {
        awd::CueClass::GreenListBias,
        awd::CueClass::PseudorandomSeq,
        awd::CueClass::SemanticDrift,
    };
    const awd::SubThreat sub_threats[] = {
        awd::SubThreat{awd::NnbspBoundary{0}},
        awd::SubThreat{awd::VariationSelectorCarrier{0}},
        awd::SubThreat{awd::ZwjNonEmoji{0}},
        awd::SubThreat{awd::DefaultIgnorableCarrier{0}},
        awd::SubThreat{awd::Gpt5ZwspModulo{0}},
        awd::SubThreat{awd::EmDashPattern{0}},
        awd::SubThreat{awd::SmartQuoteAlternation{0}},
        awd::SubThreat{awd::StatisticalTokenChoice{0}},
        awd::SubThreat{awd::Adversarial{std::string(), 0}},
    };
    for (awd::CueClass cls : classes) {
        bool probed = false;
        for (const auto& st : sub_threats) {
            if (awd::sub_threat_cue_class(st)
                == std::optional<awd::CueClass>{cls}) {
                probed = true;
                break;
            }
        }
        CHECK(probed);
    }

    CHECK(awd::sub_threat_cue_class(awd::SubThreat{awd::Unknown{0}})
          == std::optional<awd::CueClass>{});
}

// ── Shared context-free fixture through detect + reason-code wiring ──────

TEST_CASE("AiWatermarkDetectability — shared detector fixture") {
    const auto text = read_fixture(
        "testdata/fixtures/security/detectors/ai_watermark_detectability.json");
    const Json root = JsonParser{text}.parse();
    REQUIRE(root.field("schema").number == 1);
    CHECK(root.field("family").string == "ai-watermark-detectability");

    for (const auto& test_case : root.field("cases").array) {
        const std::string name = test_case.field("name").string;
        INFO(name);

        std::vector<std::uint32_t> input;
        for (const auto& value : test_case.field("input").array) {
            input.push_back(static_cast<std::uint32_t>(value.number));
        }

        const auto verdict = det(input);

        // Reason code the policy layer would emit for this verdict, wired
        // exactly as hash-input-stability is (Family::AiWatermarkDetectability,
        // K layer).
        std::optional<std::string> emitted;
        if (auto verdict_tag = verdict.classify.tag()) {
            emitted = policy::reason_code(
                Family::AiWatermarkDetectability,
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
