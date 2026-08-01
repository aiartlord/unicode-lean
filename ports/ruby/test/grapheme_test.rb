# frozen_string_literal: true

require_relative "test_helper"

# UAX #29 default extended grapheme cluster segmentation.
#
# Validates the port's segmentation against the official Unicode
# GraphemeBreakTest.txt (bundled under ports/ruby/testdata/ so the port stays
# self-contained), plus the targeted vectors from the Rust reference's
# tests/segmentation.rs.  Every break opportunity (÷) and non-break (×) in the
# official file must be reproduced exactly.
class GraphemeTest < Minitest::Test
  Grapheme = UnicodeRuby::Segmentation::Grapheme

  BREAK = "÷"     # ÷ : break opportunity
  NO_BREAK = "×"  # × : no break

  GRAPHEME_BREAK_TEST = File.join(PORT_ROOT, "testdata", "GraphemeBreakTest.txt")

  # Parse one data line into [codepoints, expected_break_mask].
  #
  # A line is a sequence of alternating boundary markers and hex code points,
  # beginning and ending with a marker: e.g. "÷ 0061 × 0300 ÷".  The markers
  # form the expected boundary mask (÷ -> true, × -> false) of length
  # codepoints.length + 1; the hex tokens are the code points.
  def parse_line(body)
    tokens = body.split(/\s+/).reject(&:empty?)
    codepoints = []
    mask = []
    tokens.each do |tok|
      case tok
      when BREAK
        mask << true
      when NO_BREAK
        mask << false
      else
        codepoints << Integer(tok, 16)
      end
    end
    [codepoints, mask]
  end

  def test_official_grapheme_break_test
    rows = 0
    File.foreach(GRAPHEME_BREAK_TEST, encoding: "UTF-8") do |raw|
      line = raw.split("#", 2).first.to_s.strip
      next if line.empty?

      codepoints, expected = parse_line(line)
      actual = Grapheme.grapheme_breaks(codepoints)
      assert_equal expected, actual,
                   "row #{rows + 1}: cps=#{codepoints.map { |c| format('%04X', c) }.join(' ')}"
      rows += 1
    end

    # Full UCD 17.0.0 GraphemeBreakTest.txt carries 766 data rows.
    assert_equal 766, rows, "expected to validate every GraphemeBreakTest row"
  end

  # Targeted vectors mirrored from ports/rust/tests/segmentation.rs.

  def test_ascii_each_its_own_cluster
    assert_equal [true, true, true, true],
                 Grapheme.grapheme_breaks([0x61, 0x62, 0x63])
    assert_equal 3, Grapheme.grapheme_clusters([0x61, 0x62, 0x63]).length
  end

  def test_combining_mark_joins
    # e + COMBINING ACUTE (U+0301) is one cluster (GB9).
    assert_equal [true, false, true], Grapheme.grapheme_breaks([0x65, 0x0301])
    assert_equal 1, Grapheme.grapheme_clusters([0x65, 0x0301]).length
  end

  def test_crlf_is_one_cluster
    # CR LF is a single cluster (GB3).
    assert_equal [true, false, true], Grapheme.grapheme_breaks([0x0D, 0x0A])
  end

  def test_flag_pair_is_one_cluster
    # Regional indicators 🇯🇵 (U+1F1EF U+1F1F5) form one cluster (GB12).
    assert_equal [true, false, true], Grapheme.grapheme_breaks([0x1F1EF, 0x1F1F5])
    assert_equal 1, Grapheme.grapheme_clusters([0x1F1EF, 0x1F1F5]).length
  end

  def test_four_flags_are_two_clusters
    # Four regional indicators = two flags = two clusters (GB12/13 parity).
    cps = [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8]
    assert_equal 2, Grapheme.grapheme_clusters(cps).length
  end

  def test_emoji_zwj_sequence_is_one_cluster
    # 👨‍👩‍👧 : man ZWJ woman ZWJ girl is one cluster (GB11).
    cps = [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467]
    assert_equal 1, Grapheme.grapheme_clusters(cps).length
  end
end
