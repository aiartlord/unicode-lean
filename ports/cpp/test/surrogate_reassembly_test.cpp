#include <doctest/doctest.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "unicode_cpp/security/covert/surrogate_reassembly.hpp"

namespace sr = unicode_cpp::security::surrogate_reassembly;

// Ground truth: the `detect_*` spot-check theorems in
// `Unicode/Security/Covert/SurrogateReassembly.lean`, each proven by
// `decide`, and mirrored by the verified Rust port's test vectors.

static std::optional<std::string> sub(const std::vector<std::uint32_t> &input) {
  return sr::detect(std::span<const std::uint32_t>{input.data(), input.size()})
      .sub;
}

TEST_CASE("SurrogateReassembly — well-formed byte streams are clear") {
  CHECK(sub({}) == std::nullopt);
  CHECK(sub({0x48, 0x65, 0x6C, 0x6C, 0x6F}) == std::nullopt);  // "Hello"
  CHECK(sub({0xC3, 0xA9}) == std::nullopt);                    // é
  CHECK(sub({0xE4, 0xB8, 0xAD}) == std::nullopt);              // 中
  CHECK(sub({0xF0, 0x9F, 0x98, 0x80}) == std::nullopt);        // 😀
}

TEST_CASE("SurrogateReassembly — invalid start bytes") {
  CHECK(sub({0xC0, 0x80}) == std::optional<std::string>{"InvalidStartByte"});
  CHECK(sub({0xC0, 0xAF}) == std::optional<std::string>{"InvalidStartByte"});
  CHECK(sub({0xFE}) == std::optional<std::string>{"InvalidStartByte"});
  CHECK(sub({0x80}) == std::optional<std::string>{"InvalidStartByte"});
  CHECK(sub({0xFF}) == std::optional<std::string>{"InvalidStartByte"});
}

TEST_CASE("SurrogateReassembly — overlong encodings") {
  CHECK(sub({0xE0, 0x80, 0xAF}) == std::optional<std::string>{"Overlong"});
  CHECK(sub({0xF0, 0x80, 0x80, 0xAF}) ==
        std::optional<std::string>{"Overlong"});
}

TEST_CASE("SurrogateReassembly — CESU-8 surrogate codepoints") {
  CHECK(sub({0xED, 0xA0, 0x80}) == std::optional<std::string>{"Cesu8"});
  CHECK(sub({0xED, 0xAF, 0xBF}) == std::optional<std::string>{"Cesu8"});
}

TEST_CASE("SurrogateReassembly — truncated sequences") {
  CHECK(sub({0xC3}) == std::optional<std::string>{"Truncated"});
  CHECK(sub({0xF0, 0x9F, 0x98}) == std::optional<std::string>{"Truncated"});
}

static bool byte_stream(const std::vector<std::uint32_t> &input) {
  return sr::looks_like_byte_stream(
      std::span<const std::uint32_t>{input.data(), input.size()});
}

TEST_CASE("SurrogateReassembly — non-byte-stream unit clamps, scan gates") {
  // The module `detect` clamps any value > 0xFF to 0xFF (mirroring the Lean
  // `toBytes` helper), which the strict decoder rejects as an invalid start
  // byte.  The scan orchestrator gates such input out via
  // `looks_like_byte_stream` (mirroring `runAll`).
  CHECK(sub({0x1F600}) == std::optional<std::string>{"InvalidStartByte"});
  CHECK(sub({0x41, 0x100}) == std::optional<std::string>{"InvalidStartByte"});
  CHECK(byte_stream({0x1F600}) == false);
  CHECK(byte_stream({0x41, 0xFF}) == true);
}
