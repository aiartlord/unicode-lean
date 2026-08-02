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
#include "unicode_cpp/security/form/stream_safe_violation.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"
#include "unicode_cpp/security/policy.hpp"

namespace {

namespace ucd = unicode_cpp::security::ucd;
namespace ssv = unicode_cpp::security::form::stream_safe_violation;
namespace policy = unicode_cpp::security::policy;
using unicode_cpp::security::Family;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data", "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "UnicodeData.txt")) {
            return p;
        }
    }
    throw std::runtime_error("stream-safe-violation test: cannot locate bundled UCD data");
}

const ucd::Tables& tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}

std::span<const std::uint32_t> as_span(const std::vector<std::uint32_t>& v) {
    return std::span<const std::uint32_t>(v.data(), v.size());
}

ssv::Verdict det(const std::vector<std::uint32_t>& in) {
    return ssv::detect(tables(), as_span(in));
}

// U+0301 COMBINING ACUTE ACCENT has CCC = 230 (a non-starter); the ASCII
// letters in these vectors have CCC = 0 (starters).
constexpr std::uint32_t ACUTE = 0x0301;

// Build "a" followed by n combining acute accents.
std::vector<std::uint32_t> a_plus_marks(std::size_t n) {
    std::vector<std::uint32_t> v{0x61};
    v.insert(v.end(), n, ACUTE);
    return v;
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
    throw std::runtime_error("cannot locate stream-safe-violation fixture");
}

}  // namespace

// Ground truth: the detect_* theorems in
// Unicode/Security/Form/StreamSafeViolation.lean, transcribed from the verified
// Rust reference's #[test] block.
TEST_CASE("StreamSafeViolation — detect spot-checks") {
    using SV = std::optional<std::string_view>;

    // detect_empty_clear: empty input is clear.
    {
        auto v = det({});
        CHECK(v.classify.is_clear());
        CHECK(v.classify.tag() == SV{});
        CHECK(v.max_run_len == 0);
        CHECK(v.overrun_count == 0);
        CHECK(v.total_non_starters == 0);
    }

    // detect_ascii_clear: the pure-ASCII "Hello" input is clear.
    {
        auto v = det({0x48, 0x65, 0x6C, 0x6C, 0x6F});
        CHECK(v.classify.is_clear());
        CHECK(v.max_run_len == 0);
        CHECK(v.total_non_starters == 0);
    }

    // detect_one_combine_clear: a starter plus a single combining mark
    // ("a" + U+0301) is clear.
    {
        auto v = det({0x61, ACUTE});
        CHECK(v.classify.is_clear());
        CHECK(v.max_run_len == 1);
        CHECK(v.overrun_count == 0);
        CHECK(v.total_non_starters == 1);
    }

    // detect_thirty_marks_clear: exactly 30 combining marks after a starter is
    // the boundary case — stays clear under strict >.
    {
        auto v = det(a_plus_marks(30));
        CHECK(v.classify.is_clear());
        CHECK(v.classify.tag() == SV{});
        CHECK(v.max_run_len == 30);
        CHECK(v.overrun_count == 0);
        CHECK(v.total_non_starters == 30);
    }

    // detect_thirtyone_marks_hazard: 31 combining marks after a starter fires
    // StreamSafeOverrun with firstOverrun = some (1, 31) and positions [1].
    {
        auto v = det(a_plus_marks(31));
        CHECK(!v.classify.is_clear());
        CHECK(v.classify.tag() == SV{"StreamSafeOverrun"});
        CHECK(v.classify.positions == std::vector<std::size_t>{1});
        REQUIRE(v.classify.sub.has_value());
        const auto& overrun =
            std::get<ssv::StreamSafeOverrun>(*v.classify.sub);
        CHECK(overrun.base_pos == 1);
        CHECK(overrun.run_len == 31);
        CHECK(v.classify.decoded.empty());
        CHECK(v.max_run_len == 31);
        CHECK(v.overrun_count == 1);
        CHECK(v.total_non_starters == 31);
    }

    // A non-starter run that opens at index 0 (no leading starter) records its
    // start as 0. Firing at the 31st mark of a bare 31-mark run.
    {
        std::vector<std::uint32_t> input(31, ACUTE);
        auto v = det(input);
        CHECK(v.classify.tag() == SV{"StreamSafeOverrun"});
        CHECK(v.classify.positions == std::vector<std::size_t>{0});
        CHECK(v.max_run_len == 31);
        CHECK(v.total_non_starters == 31);
    }

    // Two separate runs, each under the limit, stay clear but are both counted
    // in the totals. "a" + 30 marks + "b" + 30 marks.
    {
        auto input = a_plus_marks(30);
        input.push_back(0x62);
        input.insert(input.end(), 30, ACUTE);
        auto v = det(input);
        CHECK(v.classify.is_clear());
        CHECK(v.max_run_len == 30);
        CHECK(v.overrun_count == 0);
        CHECK(v.total_non_starters == 60);
    }

    // The first overrun wins: a short run before a long run does not shadow it,
    // and the reported base_pos is the long run's start. "a" + 5 marks + "b" +
    // 31 marks — the run starting at index 7 fires.
    {
        auto input = a_plus_marks(5);
        input.push_back(0x62);
        input.insert(input.end(), 31, ACUTE);
        auto v = det(input);
        CHECK(v.classify.tag() == SV{"StreamSafeOverrun"});
        CHECK(v.classify.positions == std::vector<std::size_t>{7});
        CHECK(v.max_run_len == 31);
        CHECK(v.overrun_count == 1);
        CHECK(v.total_non_starters == 36);
    }
}

// ── Shared context-free fixture through detect + reason-code wiring ──────
TEST_CASE("StreamSafeViolation — shared detector fixture") {
    const auto text =
        read_fixture("testdata/fixtures/security/detectors/stream_safe_violation.json");
    const Json root = JsonParser{text}.parse();
    REQUIRE(root.field("schema").number == 1);
    CHECK(root.field("family").string == "stream-safe-violation");

    for (const auto& test_case : root.field("cases").array) {
        const std::string name = test_case.field("name").string;
        INFO(name);

        std::vector<std::uint32_t> input;
        for (const auto& value : test_case.field("input").array) {
            input.push_back(static_cast<std::uint32_t>(value.number));
        }

        const auto verdict = det(input);

        // Reason code the policy layer would emit for this verdict, wired
        // exactly as the sibling form detectors are (Family::StreamSafeViolation,
        // F layer) → unicode.security.F.stream-safe-violation.<SubThreat>.
        std::optional<std::string> emitted;
        if (auto verdict_tag = verdict.classify.tag()) {
            emitted = policy::reason_code(Family::StreamSafeViolation,
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
