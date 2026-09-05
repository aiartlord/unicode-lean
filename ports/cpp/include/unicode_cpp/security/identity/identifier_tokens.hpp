// Identifier-shaped tokens of a running-text field.
//
// Direct port of Unicode/Security/Identity/IdentifierTokens.lean. A source
// line, a chat message or a display name is not one identifier, but the
// identifier-shaped words inside it are the surface a homoglyph attack targets
// (scоpe with a Cyrillic о in `let scоpe = 1;`). A token is a maximal run of
// XID_Continue codepoints; everything else (space, punctuation, operators,
// format controls) separates tokens. Each token carries its start position so a
// finding made on the token can be reported in input coordinates.
//
// XID_Continue reads the bundled DerivedCoreProperties.txt through
// ucd::is_xid_continue, so tokenisation takes an explicit ucd::Tables.

#ifndef UNICODE_CPP_SECURITY_IDENTITY_IDENTIFIER_TOKENS_HPP
#define UNICODE_CPP_SECURITY_IDENTITY_IDENTIFIER_TOKENS_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::identity::identifier_tokens {

// One identifier-shaped run: its start position in the input and its
// codepoints.
struct Token {
  std::size_t start;
  std::vector<std::uint32_t> cps;
};

// The maximal XID_Continue runs of the input, in input order.
inline std::vector<Token> tokens(const ucd::Tables &t,
                                 std::span<const std::uint32_t> input) {
  std::vector<Token> out;
  bool open = false;
  Token current{0, {}};
  for (std::size_t idx = 0; idx < input.size(); ++idx) {
    const std::uint32_t cp = input[idx];
    if (ucd::is_xid_continue(t, cp)) {
      if (!open) {
        open = true;
        current = Token{idx, {}};
      }
      current.cps.push_back(cp);
    } else if (open) {
      out.push_back(std::move(current));
      open = false;
      current = Token{0, {}};
    }
  }
  if (open) {
    out.push_back(std::move(current));
  }
  return out;
}

// Move token-local positions back into input coordinates.
inline std::vector<std::size_t>
shift_positions(std::size_t start, std::span<const std::size_t> positions) {
  std::vector<std::size_t> out;
  out.reserve(positions.size());
  for (std::size_t pos : positions) {
    out.push_back(pos + start);
  }
  return out;
}

} // namespace unicode_cpp::security::identity::identifier_tokens

#endif // UNICODE_CPP_SECURITY_IDENTITY_IDENTIFIER_TOKENS_HPP
