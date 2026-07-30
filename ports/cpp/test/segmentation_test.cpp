#include <cstdint>
#include <vector>

#include <doctest/doctest.h>

#include "unicode_cpp/segmentation/grapheme.hpp"

using unicode_cpp::segmentation::grapheme_breaks;
using unicode_cpp::segmentation::grapheme_clusters;

TEST_CASE("grapheme breaks cover core UAX #29 cases") {
  const std::vector<std::uint32_t> ascii{0x61, 0x62, 0x63};
  CHECK(grapheme_breaks(ascii) == std::vector<bool>{true, true, true, true});

  const std::vector<std::uint32_t> combining{0x65, 0x0301};
  CHECK(grapheme_breaks(combining) == std::vector<bool>{true, false, true});

  const std::vector<std::uint32_t> crlf{0x0d, 0x0a};
  CHECK(grapheme_breaks(crlf) == std::vector<bool>{true, false, true});

  const std::vector<std::uint32_t> flag{0x1f1ef, 0x1f1f5};
  CHECK(grapheme_breaks(flag) == std::vector<bool>{true, false, true});
}

TEST_CASE("grapheme clusters cover RI parity and ZWJ sequence") {
  const std::vector<std::uint32_t> four_ri{0x1f1ef, 0x1f1f5, 0x1f1fa, 0x1f1f8};
  CHECK(grapheme_clusters(four_ri).size() == 2);

  const std::vector<std::uint32_t> family{0x1f468, 0x200d, 0x1f469, 0x200d,
                                          0x1f467};
  CHECK(grapheme_clusters(family).size() == 1);
}
