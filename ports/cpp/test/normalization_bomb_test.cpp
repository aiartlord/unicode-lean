#include <doctest/doctest.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "unicode_cpp/security/form/normalization_bomb.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace {

namespace ucd = unicode_cpp::security::ucd;
namespace nb = unicode_cpp::security::form::normalization_bomb;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data", "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "UnicodeData.txt")) {
            return p;
        }
    }
    throw std::runtime_error("normalization-bomb test: cannot locate bundled UCD data");
}

const ucd::Tables& tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}

std::optional<std::string> sub(std::vector<std::uint32_t> in) {
    return nb::detect(tables(), in).sub;
}

}  // namespace

// Ground truth: the detect_* theorems in
// Unicode/Security/Form/NormalizationBomb.lean, plus the two ratio-branch
// shapes the module docstring guarantees (FDFB -> NFKD 8x ratio; a Greek
// extended form -> NFD 4x ratio).
TEST_CASE("NormalizationBomb — detect spot-checks") {
    using Opt = std::optional<std::string>;
    CHECK(sub({}) == std::nullopt);
    CHECK(sub({0x48, 0x65, 0x6C, 0x6C, 0x6F}) == std::nullopt);
    CHECK(sub({0xD55C}) == std::nullopt);  // NFD ratio exactly 300, not > 300
    CHECK(sub({0x2460}) == std::nullopt);  // circled one, NFKD 1x
    CHECK(sub({0xFDFA}) == Opt("SingleCpBlowup"));
    CHECK(nb::detect(tables(), {0xFDFA}).positions == std::vector<std::size_t>{0});
    CHECK(sub({0xFDFB}) == Opt("NfkdHighExpansion"));
    CHECK(sub({0x1F82}) == Opt("NfdHighExpansion"));
}
