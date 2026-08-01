// NFC-idempotence-witness detection (F6) — inputs that are not already in NFC
// (or, failing that, not in NFKC), the silent normalization-drift class where a
// signer and verifier pick different canonical forms and their hashes diverge.
// Direct port of Unicode/Security/Form/NfcIdempotenceWitness.lean.
//
// Compares input element-wise against to_nfc(input) and to_nfkc(input),
// reporting the first divergent position: a mismatch against NFC is
// NonNfcForm; a sequence already in NFC but not NFKC is NonNfkcCompatForm.
#ifndef UNICODE_CPP_SECURITY_FORM_NFC_IDEMPOTENCE_WITNESS_HPP
#define UNICODE_CPP_SECURITY_FORM_NFC_IDEMPOTENCE_WITNESS_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::form::nfc_idempotence_witness {

namespace ucd = unicode_cpp::security::ucd;

// One NFC-idempotence-witness scan result. `sub` is empty for a clear input
// (already in NFC and NFKC), else the divergence tag with its first position.
struct Detection {
    std::optional<std::string> sub;
    std::vector<std::size_t> positions;
};

namespace detail {

// First index at which two sequences diverge (in element, or one ends);
// std::nullopt when identical.
inline std::optional<std::size_t> first_divergence(
    const std::vector<std::uint32_t>& a, const std::vector<std::uint32_t>& b) {
    const std::size_t common = a.size() < b.size() ? a.size() : b.size();
    for (std::size_t i = 0; i < common; ++i) {
        if (a[i] != b[i]) {
            return i;
        }
    }
    if (a.size() != b.size()) {
        return common;
    }
    return std::nullopt;
}

}  // namespace detail

// Detect an input that is not in canonical (NFC), or not in compatibility
// (NFKC), form. NFC divergence takes priority over NFKC.
inline Detection detect(const ucd::Tables& t,
                        const std::vector<std::uint32_t>& input) {
    std::vector<std::uint32_t> nfc = ucd::to_nfc(t, input);
    if (auto pos = detail::first_divergence(input, nfc)) {
        return Detection{std::string("NonNfcForm"), {*pos}};
    }
    std::vector<std::uint32_t> nfkc = ucd::to_nfkc(t, input);
    if (auto pos = detail::first_divergence(input, nfkc)) {
        return Detection{std::string("NonNfkcCompatForm"), {*pos}};
    }
    return Detection{std::nullopt, {}};
}

}  // namespace unicode_cpp::security::form::nfc_idempotence_witness

#endif  // UNICODE_CPP_SECURITY_FORM_NFC_IDEMPOTENCE_WITNESS_HPP
