#include <doctest/doctest.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "unicode_cpp/security/form/locale_case_inversion.hpp"
#include "unicode_cpp/security/identity/casing.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace {

namespace ucd = unicode_cpp::security::ucd;
namespace casing = unicode_cpp::security::casing;
namespace lci = unicode_cpp::security::form::locale_case_inversion;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data", "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "SpecialCasing.txt")) {
            return p;
        }
    }
    throw std::runtime_error("locale-case-inversion test: cannot locate bundled UCD data");
}

const ucd::Tables& tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}

const casing::CasingData& casing_data() {
    static const casing::CasingData c = casing::CasingData::load_from_dir(data_dir());
    return c;
}

std::optional<std::string> sub(std::vector<std::uint32_t> in) {
    return lci::detect(casing_data(), tables(), in).sub;
}

}  // namespace

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/LocaleCaseInversion.lean.
TEST_CASE("LocaleCaseInversion — detect spot-checks") {
    using Opt = std::optional<std::string>;
    CHECK(sub({}) == std::nullopt);
    CHECK(sub({0x48, 0x65, 0x6C, 0x6C, 0x6F}) == std::nullopt);
    CHECK(sub({0x0049}) == Opt("TurkishCaseDivergence"));
    CHECK(lci::detect(casing_data(), tables(), {0x0049}).positions
          == std::vector<std::size_t>{0});
    CHECK(sub({0x0130}) == Opt("TurkishCaseDivergence"));
    CHECK(sub({0x0049, 0x0300}) == Opt("TurkishCaseDivergence"));
    CHECK(sub({0x004A, 0x0300}) == Opt("LithuanianCaseDivergence"));
}
