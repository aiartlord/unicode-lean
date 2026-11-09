#include <cstdint>
#include <span>
#include <vector>

#include <doctest/doctest.h>

#include "unicode_cpp/segmentation/grapheme.hpp"

#include "grapheme_corpus.hpp"
#include "vector_cases.hpp"

// UAX #29 extended grapheme clusters, judged against the published corpus.
//
// Those two gates are the spec repo's own: agree with every published row, and
// separately account for the whole file so a row lost between the table and
// the fold fails rather than shrinking the denominator.

using unicode_cpp::segmentation::grapheme_breaks;
using unicode_cpp::segmentation::grapheme_clusters;

// Both the corpus header and the vector header put their grapheme members in
// this namespace, and their names do not overlap.
namespace data = unicode_cpp::test::grapheme;

namespace {

// Whether a produced flag vector equals the published span.
bool agrees(const std::vector<bool> &produced, std::span<const bool> published) {
  if (produced.size() != published.size()) {
    return false;
  }
  for (std::size_t i = 0; i < produced.size(); ++i) {
    if (produced[i] != published[i]) {
      return false;
    }
  }
  return true;
}

}  // namespace

// What the corpus must be before it can judge anything: every published row
// reaches the fold, and each row carries one more flag than code points.
TEST_CASE("the grapheme corpus is well formed") {
  const auto &rows = data::kPublishedRows;
  CHECK(rows.size() == data::kPublishedCount);
  std::size_t ragged = 0;
  for (const auto &row : rows) {
    if (row.flag_len != row.cp_len + 1) {
      ++ragged;
    }
  }
  CHECK(ragged == 0);
}

// Hand-written vectors cannot establish a segmentation algorithm, so the
// implementation answers to every row the Unicode Consortium publishes.
TEST_CASE("grapheme clustering agrees with every published row") {
  const auto &rows = data::kPublishedRows;
  std::size_t disagreements = 0;
  std::size_t first_index = 0;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    const auto produced = grapheme_breaks(data::row_codepoints(rows[i]));
    if (!agrees(produced, data::row_flags(rows[i]))) {
      if (disagreements == 0) {
        first_index = i;
      }
      ++disagreements;
    }
  }
  CHECK(disagreements == 0);
  if (disagreements != 0) {
    // A conformance red is only actionable if it says which row disagreed.
    MESSAGE("first disagreeing row index: " << first_index);
  }
}

// One case per UAX #29 rule, the same bytes every port replays, so no port can
// carry a weaker set of rule checks than another. The published corpus above is
// the authority; these name which rule each boundary exercises.
TEST_CASE("the shared grapheme vectors replay") {
  REQUIRE(data::kCases.size() > 0);
  for (const auto &entry : data::kCases) {
    const auto produced = grapheme_breaks(data::case_codepoints(entry));
    const bool matched = agrees(produced, data::case_flags(entry));
    if (!matched) {
      MESSAGE(entry.rule << ": " << entry.name);
    }
    CHECK(matched);
  }
}

// Both gates count the same published file, so they cannot drift apart.
TEST_CASE("the grapheme corpus and vectors agree on the row count") {
  CHECK(data::kPublishedRowCount == data::kPublishedCount);
}

TEST_CASE("the output carries one flag per boundary") {
  for (std::size_t length = 0; length < 8; ++length) {
    std::vector<std::uint32_t> cps;
    for (std::size_t i = 0; i < length; ++i) {
      cps.push_back(static_cast<std::uint32_t>(0x61 + i));
    }
    CHECK(grapheme_breaks(cps).size() == length + 1);
  }
}

TEST_CASE("grapheme clusters cover RI parity and ZWJ sequence") {
  // Cluster counts are a shape the boundary masks do not state.
  const std::vector<std::uint32_t> four_ri{0x1f1ef, 0x1f1f5, 0x1f1fa, 0x1f1f8};
  CHECK(grapheme_clusters(four_ri).size() == 2);

  const std::vector<std::uint32_t> family{0x1f468, 0x200d, 0x1f469, 0x200d,
                                          0x1f467};
  CHECK(grapheme_clusters(family).size() == 1);

  const std::vector<std::uint32_t> ascii{0x61, 0x62, 0x63};
  CHECK(grapheme_clusters(ascii).size() == 3);
}
