#include <doctest/doctest.h>

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <vector>

#include "unicode_cpp/security/identity/casing.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace {

namespace ucd = unicode_cpp::security::ucd;
namespace casing = unicode_cpp::security::casing;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data", "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "SpecialCasing.txt")) {
            return p;
        }
    }
    throw std::runtime_error("casing test: cannot locate bundled UCD data");
}

const ucd::Tables& tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}

const casing::CasingData& casing_data() {
    static const casing::CasingData c = casing::CasingData::load_from_dir(data_dir());
    return c;
}

std::vector<std::uint32_t> lower(casing::Locale loc, std::vector<std::uint32_t> in) {
    return casing::to_lower(casing_data(), tables(), loc, in);
}

}  // namespace

// Ground truth: the toLower spot-check theorems in Unicode.Casing.
TEST_CASE("Casing — toLower spot-checks") {
    using L = casing::Locale;
    CHECK(lower(L::Default, {0x48, 0x65, 0x6C, 0x6C, 0x6F})
          == std::vector<std::uint32_t>{0x68, 0x65, 0x6C, 0x6C, 0x6F});
    CHECK(lower(L::Default, {0x0049}) == std::vector<std::uint32_t>{0x0069});
    CHECK(lower(L::Turkish, {0x0049}) == std::vector<std::uint32_t>{0x0131});
    CHECK(lower(L::Azeri, {0x0049}) == std::vector<std::uint32_t>{0x0131});
    CHECK(lower(L::Turkish, {0x0130}) == std::vector<std::uint32_t>{0x0069});
    CHECK(lower(L::Default, {0x0130})
          == std::vector<std::uint32_t>{0x0069, 0x0307});
}
