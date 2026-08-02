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
#include "unicode_cpp/security/crypto/hash_input_stability.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"
#include "unicode_cpp/security/policy.hpp"

namespace {

namespace ucd = unicode_cpp::security::ucd;
namespace his = unicode_cpp::security::crypto::hash_input_stability;
namespace policy = unicode_cpp::security::policy;
using unicode_cpp::security::Family;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data", "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "UnicodeData.txt")) {
            return p;
        }
    }
    throw std::runtime_error("hash-input-stability test: cannot locate bundled data");
}

const ucd::Tables& tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}

std::span<const std::uint32_t> as_span(const std::vector<std::uint32_t>& v) {
    return std::span<const std::uint32_t>(v.data(), v.size());
}

his::Verdict det(const std::vector<std::uint32_t>& in) {
    return his::detect(tables(), as_span(in));
}

std::optional<std::string_view> tag(const std::vector<std::uint32_t>& in) {
    return det(in).classify.tag();
}

std::optional<std::string_view> ctx_tag(const his::Context& ctx,
                                        const std::vector<std::uint32_t>& in) {
    return his::detect_with_context(tables(), ctx, as_span(in)).classify.tag();
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
    throw std::runtime_error("cannot locate hash-input-stability fixture");
}

}  // namespace

// ── §4 hash_stable spot checks ──────────────────────────────────────────

TEST_CASE("HashInputStability — hash_stable canonical form") {
    using V = std::vector<std::uint32_t>;
    CHECK(his::hash_stable(tables(), as_span(V{})) == V{});
    CHECK(his::hash_stable(tables(), as_span(V{0x61, 0x62, 0x63})) == V{0x61, 0x62, 0x63});
    // Idempotence: hash_stable(hash_stable(x)) == hash_stable(x).
    auto once = his::hash_stable(tables(), as_span(V{0x61, 0x62, 0x63}));
    CHECK(his::hash_stable(tables(), as_span(once)) == once);
    CHECK(his::hash_stable(tables(), as_span(V{0x61, 0x20})) == V{0x61});
    CHECK(his::hash_stable(tables(), as_span(V{0x61, 0x09})) == V{0x61});
    CHECK(his::hash_stable(tables(), as_span(V{0x61, 0x0A})) == V{0x61});
    CHECK(his::hash_stable(tables(), as_span(V{0x61, 0x0D, 0x0A})) == V{0x61});
    CHECK(his::hash_stable(tables(), as_span(V{0x61, 0x20, 0x62})) == V{0x61, 0x20, 0x62});
    CHECK(his::hash_stable(tables(), as_span(V{0x0065, 0x0301})) == V{0x00E9});
    // Unicode NBSP is content, not framing — preserved.
    CHECK(his::hash_stable(tables(), as_span(V{0x61, 0x00A0})) == V{0x61, 0x00A0});
}

// ── §8 detect spot checks ────────────────────────────────────────────────

TEST_CASE("HashInputStability — detect bare-input probes") {
    CHECK(det({}).classify.is_clear());
    CHECK(det({0x61, 0x62, 0x63}).classify.is_clear());

    auto space = det({0x61, 0x20});
    CHECK(space.classify.tag() == std::optional<std::string_view>{"TrailingWhitespace"});
    CHECK(space.stable_size == 1);
    CHECK(space.classify.positions == std::vector<std::size_t>{1});

    auto crlf = det({0x61, 0x0D, 0x0A});
    CHECK(crlf.classify.tag() == std::optional<std::string_view>{"TrailingWhitespace"});
    CHECK(crlf.stable_size == 1);

    auto drift = det({0x0065, 0x0301});
    CHECK(drift.classify.tag() == std::optional<std::string_view>{"NormalizationDrift"});
    CHECK(drift.classify.positions == std::vector<std::size_t>{0});

    CHECK(det({0x00E9}).classify.is_clear());

    // Decomposed "é " — TrailingWhitespace wins over NormalizationDrift.
    CHECK(tag({0x0065, 0x0301, 0x20})
          == std::optional<std::string_view>{"TrailingWhitespace"});

    CHECK(det({0x61, 0x20, 0x62}).classify.is_clear());
}

// ── §9 context-bearing probe vectors (transcribed from the Rust comment
//    block; the shared detector-fixture schema cannot express a Context) ───

TEST_CASE("HashInputStability — default context matches detect") {
    auto d = det({0x61, 0x62, 0x63});
    auto c = his::detect_with_context(tables(), his::Context{},
                                      as_span(std::vector<std::uint32_t>{0x61, 0x62, 0x63}));
    CHECK(c.classify.tag() == d.classify.tag());
    CHECK(c.stable_size == d.stable_size);
}

TEST_CASE("HashInputStability — encodingMismatch probe") {
    using SV = std::optional<std::string_view>;
    {
        his::Context ctx;
        ctx.declared_encoding = "utf-16";
        auto v = his::detect_with_context(
            tables(), ctx, as_span(std::vector<std::uint32_t>{0x61, 0x62, 0x63}));
        CHECK(v.classify.tag() == SV{"EncodingMismatch"});
        CHECK(v.classify.positions == std::vector<std::size_t>{0});
    }
    {
        his::Context ctx;
        ctx.declared_encoding = "utf-8";
        auto v = his::detect_with_context(
            tables(), ctx, as_span(std::vector<std::uint32_t>{0x61, 0xD800, 0x62}));
        CHECK(v.classify.tag() == SV{"EncodingMismatch"});
        CHECK(v.classify.positions == std::vector<std::size_t>{1});
    }
    {
        his::Context ctx;
        ctx.declared_encoding = "utf-8";
        auto v = his::detect_with_context(
            tables(), ctx, as_span(std::vector<std::uint32_t>{0x61, 0x110000, 0x62}));
        CHECK(v.classify.tag() == SV{"EncodingMismatch"});
        CHECK(v.classify.positions == std::vector<std::size_t>{1});
    }
    for (const char* label : {"UTF-8", "utf-8", "UTF8", "utf8"}) {
        his::Context ctx;
        ctx.declared_encoding = std::string(label);
        CHECK(ctx_tag(ctx, {0x61, 0x62, 0x63}) == std::optional<std::string_view>{});
    }
}

TEST_CASE("HashInputStability — signedMessageRule probes") {
    using SV = std::optional<std::string_view>;
    auto rule_ctx = [](his::RfcRule r) {
        his::Context ctx;
        ctx.rfc_rule = r;
        return ctx;
    };

    {
        auto v = his::detect_with_context(
            tables(), rule_ctx(his::RfcRule::Pgp4880TrailingWhitespace),
            as_span(std::vector<std::uint32_t>{0x61, 0x20}));
        CHECK(v.classify.tag() == SV{"SignedMessageRule"});
        CHECK(v.classify.positions == std::vector<std::size_t>{1});
    }
    {
        auto v = his::detect_with_context(
            tables(), rule_ctx(his::RfcRule::Pgp9580LineEnding),
            as_span(std::vector<std::uint32_t>{0x61, 0x0A, 0x62}));
        CHECK(v.classify.tag() == SV{"SignedMessageRule"});
        CHECK(v.classify.positions == std::vector<std::size_t>{1});
    }
    // "abc" CRLF "def" — clean under the CRLF rule.
    CHECK(ctx_tag(rule_ctx(his::RfcRule::Pgp9580LineEnding),
                  {0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66})
          == std::optional<std::string_view>{});
    {
        auto v = his::detect_with_context(
            tables(), rule_ctx(his::RfcRule::Rfc8785NfcRequirement),
            as_span(std::vector<std::uint32_t>{0x0065, 0x0301}));
        CHECK(v.classify.tag() == SV{"SignedMessageRule"});
        CHECK(v.classify.positions == std::vector<std::size_t>{0});
    }
    {
        auto v = his::detect_with_context(
            tables(), rule_ctx(his::RfcRule::Rfc8259ControlChar),
            as_span(std::vector<std::uint32_t>{0x61, 0x01, 0x62}));
        CHECK(v.classify.tag() == SV{"SignedMessageRule"});
        CHECK(v.classify.positions == std::vector<std::size_t>{1});
    }
    {
        // '+' (0x2B) is standard Base64 but not Base64URL.
        auto v = his::detect_with_context(
            tables(), rule_ctx(his::RfcRule::Rfc7515JwsBase64Url),
            as_span(std::vector<std::uint32_t>{0x41, 0x2B, 0x42}));
        CHECK(v.classify.tag() == SV{"SignedMessageRule"});
        CHECK(v.classify.positions == std::vector<std::size_t>{1});
    }
    // "Aa0-_zZ9" — clean under the Base64URL rule.
    CHECK(ctx_tag(rule_ctx(his::RfcRule::Rfc7515JwsBase64Url),
                  {0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39})
          == std::optional<std::string_view>{});
    {
        // "a" + SP + SP + "b".
        auto v = his::detect_with_context(
            tables(), rule_ctx(his::RfcRule::Rfc6376DkimRelaxed),
            as_span(std::vector<std::uint32_t>{0x61, 0x20, 0x20, 0x62}));
        CHECK(v.classify.tag() == SV{"SignedMessageRule"});
        CHECK(v.classify.positions == std::vector<std::size_t>{2});
    }
    // "a" + SP + "b" — single space is clean.
    CHECK(ctx_tag(rule_ctx(his::RfcRule::Rfc6376DkimRelaxed), {0x61, 0x20, 0x62})
          == std::optional<std::string_view>{});
    {
        auto v = his::detect_with_context(
            tables(), rule_ctx(his::RfcRule::Rfc5751SmimeLineEnding),
            as_span(std::vector<std::uint32_t>{0x61, 0x0A, 0x62}));
        CHECK(v.classify.tag() == SV{"SignedMessageRule"});
        CHECK(v.classify.positions == std::vector<std::size_t>{1});
    }
}

TEST_CASE("HashInputStability — audit + webhook probes") {
    using SV = std::optional<std::string_view>;
    {
        his::Context ctx;
        ctx.as_written = std::vector<std::uint32_t>{0x61, 0x62, 0x63};
        auto v = his::detect_with_context(
            tables(), ctx, as_span(std::vector<std::uint32_t>{0x61, 0x62, 0x64}));
        CHECK(v.classify.tag() == SV{"AuditLogReinterpretation"});
        CHECK(v.classify.positions == std::vector<std::size_t>{2});
    }
    {
        his::Context ctx;
        ctx.as_written = std::vector<std::uint32_t>{0x61, 0x62, 0x63};
        CHECK(ctx_tag(ctx, {0x61, 0x62, 0x63}) == std::optional<std::string_view>{});
    }
    {
        his::Context ctx;
        ctx.server_bytes = std::vector<std::uint32_t>{0x61, 0x62, 0x64};
        auto v = his::detect_with_context(
            tables(), ctx, as_span(std::vector<std::uint32_t>{0x61, 0x62, 0x63}));
        CHECK(v.classify.tag() == SV{"WebhookSignatureDrift"});
        CHECK(v.classify.positions == std::vector<std::size_t>{2});
    }
    {
        his::Context ctx;
        ctx.server_bytes = std::vector<std::uint32_t>{0x61, 0x62, 0x63};
        CHECK(ctx_tag(ctx, {0x61, 0x62, 0x63}) == std::optional<std::string_view>{});
    }
}

TEST_CASE("HashInputStability — priority ordering across probes") {
    using SV = std::optional<std::string_view>;
    {
        // Bare LF (pgp9580) + decomposed é (rfc8785) labeled utf-16 —
        // EncodingMismatch wins over the RFC rule.
        his::Context ctx;
        ctx.declared_encoding = "utf-16";
        ctx.rfc_rule = his::RfcRule::Pgp9580LineEnding;
        CHECK(ctx_tag(ctx, {0x0065, 0x0301, 0x0A}) == SV{"EncodingMismatch"});
    }
    {
        // WebhookSignatureDrift wins over AuditLogReinterpretation.
        his::Context ctx;
        ctx.server_bytes = std::vector<std::uint32_t>{0x61, 0x62, 0x65};
        ctx.as_written = std::vector<std::uint32_t>{0x61, 0x62, 0x66};
        CHECK(ctx_tag(ctx, {0x61, 0x62, 0x63}) == SV{"WebhookSignatureDrift"});
    }
    {
        // SignedMessageRule wins over the generic trailingWhitespace probe.
        his::Context ctx;
        ctx.rfc_rule = his::RfcRule::Pgp4880TrailingWhitespace;
        CHECK(ctx_tag(ctx, {0x61, 0x20}) == SV{"SignedMessageRule"});
    }
}

// ── RfcRule fixture-tag round-trip ───────────────────────────────────────

TEST_CASE("HashInputStability — RfcRule tag round-trip") {
    const his::RfcRule rules[] = {
        his::RfcRule::Pgp4880TrailingWhitespace,
        his::RfcRule::Pgp9580LineEnding,
        his::RfcRule::Rfc8785NfcRequirement,
        his::RfcRule::Rfc8259ControlChar,
        his::RfcRule::Rfc7515JwsBase64Url,
        his::RfcRule::Rfc6376DkimRelaxed,
        his::RfcRule::Rfc5751SmimeLineEnding,
    };
    for (his::RfcRule rule : rules) {
        auto round = his::from_tag(his::tag(rule));
        REQUIRE(round.has_value());
        CHECK(*round == rule);
    }
    CHECK(his::from_tag("nope") == std::optional<his::RfcRule>{});
}

// ── Shared context-free fixture through detect + reason-code wiring ──────

TEST_CASE("HashInputStability — shared detector fixture") {
    const auto text =
        read_fixture("testdata/fixtures/security/detectors/hash_input_stability.json");
    const Json root = JsonParser{text}.parse();
    REQUIRE(root.field("schema").number == 1);
    CHECK(root.field("family").string == "hash-input-stability");

    for (const auto& test_case : root.field("cases").array) {
        const std::string name = test_case.field("name").string;
        INFO(name);

        std::vector<std::uint32_t> input;
        for (const auto& value : test_case.field("input").array) {
            input.push_back(static_cast<std::uint32_t>(value.number));
        }

        const auto verdict = det(input);

        // Reason code the policy layer would emit for this verdict, wired
        // exactly as bip39-canonical is (Family::HashInputStability, K layer).
        std::optional<std::string> emitted;
        if (auto verdict_tag = verdict.classify.tag()) {
            emitted = policy::reason_code(Family::HashInputStability,
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
