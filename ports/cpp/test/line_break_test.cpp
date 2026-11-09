#include <cstdint>
#include <span>
#include <vector>

#include <doctest/doctest.h>

#include "unicode_cpp/segmentation/line_break.hpp"

#include "line_break_corpus.hpp"
#include "vector_cases.hpp"

using unicode_cpp::segmentation::Lb;
using unicode_cpp::segmentation::line_breaks;
using unicode_cpp::segmentation::line_runs;
using unicode_cpp::segmentation::raw_class;
using unicode_cpp::segmentation::resolved_class;

// Both the corpus header and the vector header put their line-break members in
// this namespace, and their names do not overlap.
namespace data = unicode_cpp::test::line_break;

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
TEST_CASE("the line-break corpus is well formed") {
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
// Agreeing with all of them is also the evidence the two departures declared
// at line_break.hpp's head needed -- span reads in place of positional
// lits[i]!, and dropping the Lean's write-only spSinceNoSp snapshot field.
TEST_CASE("the line breaker agrees with every published row") {
  const auto &rows = data::kPublishedRows;
  std::size_t disagreements = 0;
  std::size_t first_index = 0;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    const auto produced =
        line_breaks(data::row_codepoints(rows[i]));
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

// One case per UAX #14 rule, the same bytes every port replays, so no port can
// carry a weaker set of rule checks than another. The published corpus above is
// the authority; these name which rule each boundary exercises.
TEST_CASE("the shared line-break vectors replay") {
  REQUIRE(data::kCases.size() > 0);
  for (const auto &entry : data::kCases) {
    const auto produced = line_breaks(data::case_codepoints(entry));
    const bool matched = agrees(produced, data::case_flags(entry));
    if (!matched) {
      MESSAGE(entry.rule << ": " << entry.name);
    }
    CHECK(matched);
  }
}

// Both gates count the same published file, so they cannot drift apart.
TEST_CASE("the line-break corpus and vectors agree on the row count") {
  CHECK(data::kPublishedRowCount == data::kPublishedCount);
}

TEST_CASE("the output carries one flag per boundary") {
  // The Lean lineBreaks_length theorem: cps.size() + 1 flags.
  for (std::size_t length = 0; length < 8; ++length) {
    std::vector<std::uint32_t> cps;
    for (std::size_t i = 0; i < length; ++i) {
      cps.push_back(static_cast<std::uint32_t>(0x61 + i));
    }
    CHECK(line_breaks(cps).size() == length + 1);
  }
}

TEST_CASE("a space opens the next run") {
  // LB18 breaks after a space, so the space stays with the word before it. The
  // run split is a shape the boundary masks do not state.
  const std::vector<std::uint32_t> spaced{0x61, 0x20, 0x62};
  const auto runs = line_runs(spaced);
  REQUIRE(runs.size() == 2);
  CHECK(runs[0] == std::vector<std::uint32_t>{0x61, 0x20});
  CHECK(runs[1] == std::vector<std::uint32_t>{0x62});
}

TEST_CASE("a numeric chain is one run") {
  // LB25: "1,000" is one run across its separator.
  const std::vector<std::uint32_t> cps{0x31, 0x2C, 0x30, 0x30, 0x30};
  CHECK(line_runs(cps).size() == 1);
}

TEST_CASE("LB1 resolves the tailorable classes") {
  // U+3041 HIRAGANA LETTER SMALL A is CJ, resolving to NS.
  CHECK(raw_class(0x3041) == Lb::Cj);
  CHECK(resolved_class(0x3041) == Lb::Ns);
  // U+00A7 SECTION SIGN is AI, resolving to AL.
  CHECK(raw_class(0x00A7) == Lb::Ai);
  CHECK(resolved_class(0x00A7) == Lb::Al);
  // A surrogate code point is SG, resolving to AL.
  CHECK(raw_class(0xD800) == Lb::Sg);
  CHECK(resolved_class(0xD800) == Lb::Al);
  // U+05EB lies in the Hebrew block's unassigned gap, which no range covers,
  // so it takes the @missing XX default and LB1 reads it as AL.
  CHECK(raw_class(0x05EB) == Lb::Xx);
  CHECK(resolved_class(0x05EB) == Lb::Al);
}

TEST_CASE("LB1 resolves SA by General_Category") {
  // U+0E31 THAI CHARACTER MAI HAN-AKAT is SA with General_Category Mn, so LB1
  // reads it as CM; U+0E01 THAI CHARACTER KO KAI is SA with category Lo, so
  // LB1 reads it as AL.
  CHECK(raw_class(0x0E31) == Lb::Sa);
  CHECK(resolved_class(0x0E31) == Lb::Cm);
  CHECK(raw_class(0x0E01) == Lb::Sa);
  CHECK(resolved_class(0x0E01) == Lb::Al);
}
