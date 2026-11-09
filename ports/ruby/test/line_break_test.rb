# frozen_string_literal: true

require_relative "test_helper"

# UAX #14 default line breaking.
#
# Validates the port's line breaker against the official Unicode
# LineBreakTest.txt (bundled under ports/ruby/testdata/ so the port stays
# self-contained), plus targeted vectors pinning the individual rules and the
# output shape the Lean lineBreaks_length theorem fixes.  Every break
# opportunity (÷) and non-break (×) in the official file must be reproduced
# exactly.
class LineBreakTest < Minitest::Test
  include RubyPortTestHelpers

  LineBreak = UnicodeRuby::Segmentation::LineBreak
  LineBreakTables = UnicodeRuby::Segmentation::LineBreakTables

  BREAK = "÷"     # ÷ : break opportunity
  NO_BREAK = "×"  # × : no break

  LINE_BREAK_TEST = File.join(PORT_ROOT, "testdata", "LineBreakTest.txt")

  # Parse one data line into [codepoints, expected_break_mask].
  #
  # A line is a sequence of alternating boundary markers and hex code points,
  # beginning and ending with a marker: e.g. "× 0061 ÷ 0062 ÷".  The markers
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

  # What the corpus must be before it can judge anything: every row carries one
  # more flag than code points, and the vendored copy carries every row the
  # canonical file did.  Without the second check a row lost between the two
  # would shrink the denominator instead of failing.
  def test_corpus_is_well_formed
    rows = 0
    ragged = 0
    File.foreach(LINE_BREAK_TEST, encoding: "UTF-8") do |raw|
      line = raw.split("#", 2).first.to_s.strip
      next if line.empty?

      codepoints, expected = parse_line(line)
      ragged += 1 if expected.length != codepoints.length + 1
      rows += 1
    end

    assert_equal 0, ragged, "every row carries one flag per boundary"
    assert_equal LineBreakTables::PUBLISHED_ROW_COUNT, rows,
                 "the vendored corpus carries every published row"
  end

  # Hand-written vectors cannot establish a segmentation algorithm: its rules
  # read context on both sides of a boundary and the answer depends on state
  # carried from earlier in the sequence, so a wrong rule survives any vector a
  # person would pick.  Agreeing with all of them is also the evidence the two
  # departures declared at line_break.rb's head needed — nil-yielding reads in
  # place of the Lean's positional lits[i]!, and dropping its write-only
  # spSinceNoSp snapshot field.
  def test_official_line_break_test
    rows = 0
    File.foreach(LINE_BREAK_TEST, encoding: "UTF-8") do |raw|
      line = raw.split("#", 2).first.to_s.strip
      next if line.empty?

      codepoints, expected = parse_line(line)
      actual = LineBreak.line_breaks(codepoints)
      assert_equal expected, actual,
                   "row #{rows + 1}: cps=#{codepoints.map { |c| format('%04X', c) }.join(' ')}"
      rows += 1
    end

    assert_equal LineBreakTables::PUBLISHED_ROW_COUNT, rows,
                 "expected to validate every LineBreakTest row"
  end

  # The shared vector fixture: one case per UAX #14 rule, the same bytes in
  # every port, so no port can carry a weaker set of rule checks than another.
  # The published corpus above is the authority; these name which rule each
  # boundary exercises.
  def test_shared_line_break_vectors
    fixture = segmentation_fixture_json("line_break_vectors.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "uax14-line-break", fixture.fetch("algorithm")

    cases = fixture.fetch("cases")
    refute_empty cases
    cases.each do |line_case|
      cps = line_case.fetch("input")
      expected = line_case.fetch("breaks")
      actual = LineBreak.line_breaks(cps)
      assert_equal expected, actual,
                   "#{line_case.fetch('rule')}: #{line_case.fetch('name')} " \
                   "(cps=#{cps.map { |c| format('%04X', c) }.join(' ')})"
    end
  end

  # The vendored corpus and the vendored vectors must agree on how many rows
  # the published file carries, so the two gates cannot drift apart.
  def test_published_row_count_agrees_with_the_shared_fixture
    fixture = segmentation_fixture_json("line_break_vectors.json")
    assert_equal LineBreakTables::PUBLISHED_ROW_COUNT,
                 fixture.fetch("published_row_count")
  end

  def test_output_carries_one_flag_per_boundary
    # The Lean lineBreaks_length theorem: cps.length + 1 flags.
    (0...8).each do |length|
      cps = (0...length).map { |i| 0x61 + i }
      assert_equal length + 1, LineBreak.line_breaks(cps).length
    end
  end

  def test_a_space_opens_the_next_run
    # LB18 breaks after a space, so the space stays with the word before it.
    runs = LineBreak.line_runs([0x61, 0x20, 0x62])
    assert_equal 2, runs.length
    assert_equal [0x61, 0x20], runs[0]
    assert_equal [0x62], runs[1]
  end

  def test_numeric_chain_is_one_run
    # LB25: "1,000" is one run across its separator.
    assert_equal 1, LineBreak.line_runs([0x31, 0x2C, 0x30, 0x30, 0x30]).length
  end

  def test_lb1_resolves_the_tailorable_classes
    # U+3041 HIRAGANA LETTER SMALL A is CJ, resolving to NS.
    assert_equal :cj, LineBreak.raw_class(0x3041)
    assert_equal :ns, LineBreak.resolved_class(0x3041)
    # U+00A7 SECTION SIGN is AI, resolving to AL.
    assert_equal :ai, LineBreak.raw_class(0x00A7)
    assert_equal :al, LineBreak.resolved_class(0x00A7)
    # A surrogate code point is SG, resolving to AL.
    assert_equal :sg, LineBreak.raw_class(0xD800)
    assert_equal :al, LineBreak.resolved_class(0xD800)
    # U+05EB lies in the Hebrew block's unassigned gap, which no range covers,
    # so it takes the @missing XX default and LB1 reads it as AL.
    assert_equal :xx, LineBreak.raw_class(0x05EB)
    assert_equal :al, LineBreak.resolved_class(0x05EB)
  end

  def test_lb1_resolves_sa_by_general_category
    # U+0E31 THAI CHARACTER MAI HAN-AKAT is SA with General_Category Mn, so LB1
    # reads it as CM; U+0E01 THAI CHARACTER KO KAI is SA with category Lo, so
    # LB1 reads it as AL.
    assert_equal :sa, LineBreak.raw_class(0x0E31)
    assert_equal :cm, LineBreak.resolved_class(0x0E31)
    assert_equal :sa, LineBreak.raw_class(0x0E01)
    assert_equal :al, LineBreak.resolved_class(0x0E01)
  end
end
