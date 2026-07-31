// NFKD / NFKC compatibility-normalization tests for the C++ port.
//
// Mirrors the Rust port's `nfkc_nfkd_tests` in
// ports/rust/src/security/identity/ucd.rs, which in turn mirror the Lean
// specs Unicode.Normalization.NFKD / NFKC.  All data comes from the
// vendored UCD 17.0.0 tables under the port's data/ directory — no
// stdlib/ICU normalization is used.

#include <doctest/doctest.h>

#include <cstdint>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace {

using unicode_cpp::security::ucd::Tables;
using unicode_cpp::security::ucd::to_nfkc;
using unicode_cpp::security::ucd::to_nfkd;

// Shared fixture: parse the bundled UCD data once per test program.
// Tests run from the build directory; data lives at the port root, so
// probe a few candidate locations exactly as the homoglyph tests do.
const Tables& test_tables() {
    static const Tables t = [] {
        const std::filesystem::path candidates[] = {
            "data",
            "../data",
            "../../data",
        };
        for (const auto& p : candidates) {
            if (std::filesystem::exists(p / "UnicodeData.txt")) {
                return Tables::load_from_dir(p);
            }
        }
        throw std::runtime_error(
            "nfkc_nfkd test_tables: cannot locate bundled UCD data");
    }();
    return t;
}

std::span<const std::uint32_t> as_span(const std::vector<std::uint32_t>& v) {
    return std::span<const std::uint32_t>(v.data(), v.size());
}

}  // namespace

TEST_CASE("NFKC — known compatibility vectors") {
    const Tables& t = test_tables();
    // LATIN SMALL LIGATURE FI (U+FB01) → "fi".
    CHECK(to_nfkc(t, as_span({0xFB01}))
          == std::vector<std::uint32_t>{0x66, 0x69});
    // CIRCLED DIGIT ONE (U+2460) → "1".
    CHECK(to_nfkc(t, as_span({0x2460}))
          == std::vector<std::uint32_t>{0x31});
    // FULLWIDTH LATIN CAPITAL LETTER A (U+FF21) → "A".
    CHECK(to_nfkc(t, as_span({0xFF21}))
          == std::vector<std::uint32_t>{0x41});
}

TEST_CASE("NFKC — canonical forms are preserved") {
    const Tables& t = test_tables();
    // Precomposed é (U+00E9) stays é under NFKC.
    CHECK(to_nfkc(t, as_span({0x00E9}))
          == std::vector<std::uint32_t>{0x00E9});
    // Decomposed e + combining acute recomposes to é under NFKC.
    CHECK(to_nfkc(t, as_span({0x0065, 0x0301}))
          == std::vector<std::uint32_t>{0x00E9});
    // Hangul jamo L+V+T → precomposed syllable 한 (U+D55C).
    CHECK(to_nfkc(t, as_span({0x1112, 0x1161, 0x11AB}))
          == std::vector<std::uint32_t>{0xD55C});
}

TEST_CASE("NFKD — known compatibility vectors") {
    const Tables& t = test_tables();
    // FULLWIDTH LATIN CAPITAL LETTER A (U+FF21) → "A".
    CHECK(to_nfkd(t, as_span({0xFF21}))
          == std::vector<std::uint32_t>{0x41});
    // Precomposed é (U+00E9) → e + combining acute under NFKD.
    CHECK(to_nfkd(t, as_span({0x00E9}))
          == std::vector<std::uint32_t>{0x0065, 0x0301});
}
