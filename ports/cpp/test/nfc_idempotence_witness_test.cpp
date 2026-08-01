#include <doctest/doctest.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "unicode_cpp/security/form/nfc_idempotence_witness.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace {

namespace ucd = unicode_cpp::security::ucd;
namespace niw = unicode_cpp::security::form::nfc_idempotence_witness;

std::filesystem::path data_dir() {
    const std::filesystem::path candidates[] = {"data", "../data", "../../data"};
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p / "UnicodeData.txt")) {
            return p;
        }
    }
    throw std::runtime_error("nfc-idempotence-witness test: cannot locate bundled UCD data");
}

const ucd::Tables& tables() {
    static const ucd::Tables t = ucd::Tables::load_from_dir(data_dir());
    return t;
}

std::optional<std::string> sub(std::vector<std::uint32_t> in) {
    return niw::detect(tables(), in).sub;
}

}  // namespace

// Ground truth: the detect_* theorems in
// Unicode/Security/Form/NfcIdempotenceWitness.lean.
TEST_CASE("NfcIdempotenceWitness — detect spot-checks") {
    using Opt = std::optional<std::string>;
    CHECK(sub({}) == std::nullopt);
    CHECK(sub({0x48, 0x65, 0x6C, 0x6C, 0x6F}) == std::nullopt);
    CHECK(sub({0x00E9}) == std::nullopt);  // precomposed e-acute, already NFC/NFKC
    CHECK(sub({0x0065, 0x0301}) == Opt("NonNfcForm"));
    CHECK(niw::detect(tables(), {0x0065, 0x0301}).positions == std::vector<std::size_t>{0});
    CHECK(sub({0xFB01}) == Opt("NonNfkcCompatForm"));  // fi ligature
}
