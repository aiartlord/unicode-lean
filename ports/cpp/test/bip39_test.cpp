#include <doctest/doctest.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "unicode_cpp/security/crypto/bip39_canonical.hpp"
#include "unicode_cpp/security/identity/casing.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace {

namespace ucd = unicode_cpp::security::ucd;
namespace casing = unicode_cpp::security::casing;
namespace bip39 = unicode_cpp::security::bip39;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data", "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "bip39" / "english.txt")) {
            return p;
        }
    }
    throw std::runtime_error("bip39 test: cannot locate bundled data");
}

const ucd::Tables& tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}
const casing::CasingData& cdata() {
    static const casing::CasingData c = casing::CasingData::load_from_dir(data_dir());
    return c;
}
const bip39::Bip39Data& bdata() {
    static const bip39::Bip39Data b = bip39::Bip39Data::load_from_dir(data_dir());
    return b;
}

bip39::Detection det(const std::vector<std::uint32_t>& in) {
    return bip39::detect(tables(), cdata(), bdata(),
                         std::span<const std::uint32_t>(in));
}
std::optional<std::string> sub(const std::vector<std::uint32_t>& in) {
    return det(in).sub;
}

const std::vector<std::uint32_t> kAbandon = {0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E};
const std::vector<std::uint32_t> kAbout = {0x61, 0x62, 0x6F, 0x75, 0x74};

std::vector<std::uint32_t> concat(std::vector<std::uint32_t> a,
                                  const std::vector<std::uint32_t>& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

}  // namespace

// Ground truth: the detect spot-check theorems in Bip39CanonicalVectorsDetect.
TEST_CASE("Bip39 — detect hazard tags") {
    using S = std::optional<std::string>;
    CHECK(sub(concat(kAbandon, {0x20})) == S{"TrailingWhitespace"});
    CHECK(sub({0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E}) == S{"MixedCase"});
    CHECK(sub(concat(concat(kAbandon, {0x20, 0x20}), kAbout)) == S{"WhitespaceAnomaly"});
    CHECK(sub(concat({0x20}, kAbandon)) == S{"WhitespaceAnomaly"});
    CHECK(sub({0xFB00}) == S{"NonNFKD"});
    CHECK(sub({0x61, 0x00A0, 0x62}) == S{"NonNFKD"});
    CHECK(sub({0x71, 0x7A, 0x71, 0x7A}) == S{"WordlistMismatch"});
}

TEST_CASE("Bip39 — positions and clear cases") {
    CHECK(det(concat(kAbandon, {0x20})).positions == std::vector<std::size_t>{7});
    CHECK(det({0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E}).positions
          == std::vector<std::size_t>{0});

    auto empty = det({});
    CHECK(!empty.sub.has_value());
    CHECK(empty.language == std::optional<std::string>{"english"});

    std::vector<std::uint32_t> mnemonic;
    for (int i = 0; i < 11; ++i) {
        mnemonic.insert(mnemonic.end(), kAbandon.begin(), kAbandon.end());
        mnemonic.push_back(0x20);
    }
    mnemonic.insert(mnemonic.end(), kAbout.begin(), kAbout.end());
    auto verdict = det(mnemonic);
    CHECK(!verdict.sub.has_value());
    CHECK(verdict.language == std::optional<std::string>{"english"});
    CHECK(verdict.word_count == 12);
}
