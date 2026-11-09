defmodule UnicodeSecurity.Segmentation.LineBreakTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Segmentation.LineBreak
  alias UnicodeSecurity.Segmentation.LineBreakTables
  import UnicodeSecurity.TestHelpers

  @break_test_path Path.join([__DIR__, "fixtures", "LineBreakTest.txt"])

  # --------------------------------------------------------------------------
  # Full LineBreakTest.txt conformance.
  #
  # Hand-written vectors cannot establish a segmentation algorithm: its rules
  # read context on both sides of a boundary and the answer depends on state
  # carried from earlier in the sequence, so a wrong rule survives any vector a
  # person would pick. Agreeing with every published row is also the evidence
  # the two departures declared in LineBreak's moduledoc needed — reads from a
  # suffix the caller holds in place of the Lean's positional `lits[i]!`, and
  # dropping its write-only `spSinceNoSp` snapshot field.
  # --------------------------------------------------------------------------

  @tag timeout: 600_000
  test "every LineBreakTest.txt row reproduces exactly" do
    rows = parse_break_test(@break_test_path)

    failures =
      Enum.reduce(rows, [], fn {line_no, cps, expected}, acc ->
        actual = LineBreak.line_breaks(cps)

        if actual == expected do
          acc
        else
          [{line_no, cps, expected, actual} | acc]
        end
      end)

    assert failures == [],
           "LineBreakTest.txt mismatches:\n" <>
             Enum.map_join(Enum.take(Enum.reverse(failures), 10), "\n", fn {line_no, cps,
                                                                           expected, actual} ->
               "  line #{line_no}: cps=#{inspect(cps, base: :hex)} " <>
                 "expected=#{inspect(expected)} actual=#{inspect(actual)}"
             end)

    # The whole file must be accounted for, so a row lost between the file and
    # this fold fails rather than quietly shrinking the denominator. Both gates
    # count the same published file, so they cannot drift apart.
    assert length(rows) == LineBreakTables.published_row_count()

    fixture = segmentation_fixture("line_break_vectors.json", "uax14-line-break")
    assert fixture["published_row_count"] == LineBreakTables.published_row_count()
  end

  # One case per UAX #14 rule, the same bytes every port replays, so no port
  # carries a weaker set of rule checks than another. The published corpus
  # above is the authority; these name which rule each boundary exercises.
  test "the shared line-break vectors replay" do
    fixture = segmentation_fixture("line_break_vectors.json", "uax14-line-break")
    assert replay_segmentation_vectors(fixture, &LineBreak.line_breaks/1) > 0
  end

  # --------------------------------------------------------------------------
  # Targeted vectors: the output shape the Lean lineBreaks_length theorem
  # fixes, the run split the boundary masks do not state, and the four
  # properties the rules read.
  # --------------------------------------------------------------------------

  test "the output carries one flag per boundary" do
    for count <- 0..7 do
      cps = Enum.map(0..(count - 1)//1, &(0x61 + &1))
      assert length(LineBreak.line_breaks(cps)) == count + 1
    end
  end

  test "a space opens the next run" do
    # LB18 breaks after a space, so the space stays with the word before it.
    assert LineBreak.line_runs([0x61, 0x20, 0x62]) == [[0x61, 0x20], [0x62]]
  end

  test "a numeric chain is one run" do
    # LB25: "1,000" is one run across its separator.
    assert length(LineBreak.line_runs([0x31, 0x2C, 0x30, 0x30, 0x30])) == 1
  end

  test "LB1 resolves the tailorable classes" do
    # U+3041 HIRAGANA LETTER SMALL A is CJ, resolving to NS; U+00A7 SECTION
    # SIGN is AI and a surrogate is SG, both resolving to AL; U+05EB lies in
    # the Hebrew block's unassigned gap, which no range covers, so it takes the
    # @missing XX default and reads as AL.
    assert LineBreak.raw_class(0x3041) == :cj
    assert LineBreak.resolved_class(0x3041) == :ns
    assert LineBreak.raw_class(0x00A7) == :ai
    assert LineBreak.resolved_class(0x00A7) == :al
    assert LineBreak.raw_class(0xD800) == :sg
    assert LineBreak.resolved_class(0xD800) == :al
    assert LineBreak.raw_class(0x05EB) == :xx
    assert LineBreak.resolved_class(0x05EB) == :al
  end

  test "LB1 resolves SA by General_Category" do
    # U+0E31 THAI CHARACTER MAI HAN-AKAT is SA with category Mn, so it reads as
    # CM; U+0E01 THAI CHARACTER KO KAI is SA with category Lo, so it reads as
    # AL.
    assert LineBreak.raw_class(0x0E31) == :sa
    assert LineBreak.resolved_class(0x0E31) == :cm
    assert LineBreak.raw_class(0x0E01) == :sa
    assert LineBreak.resolved_class(0x0E01) == :al
  end

  test "the properties LB15a, LB19a, LB25, LB30 and LB30b read" do
    # U+FF21 FULLWIDTH LATIN CAPITAL LETTER A is F and U+0041 is Na.
    assert LineBreak.width_of(0xFF21) == :f
    assert LineBreak.width_of(0x0041) == :na
    # The initial and final punctuation the quote refinements tell apart.
    assert LineBreak.category_of(0x2018) == :pi
    assert LineBreak.category_of(0x2019) == :pf
    # LB30b reads Extended_Pictographic.
    assert LineBreak.ext_pict?(0x1F466)
    refute LineBreak.ext_pict?(0x0061)
  end

  # --------------------------------------------------------------------------
  # Corpus parser. Each data row is a sequence of boundary markers and hex code
  # points: × hex (× | ÷) hex ... ÷, optionally trailed by a `#` comment. The
  # markers form the expected mask (÷ -> true, × -> false), one longer than the
  # code point list.
  # --------------------------------------------------------------------------

  defp parse_break_test(path) do
    path
    |> File.read!()
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.flat_map(fn {raw, line_no} ->
      case parse_row(raw) do
        :skip -> []
        {cps, expected} -> [{line_no, cps, expected}]
      end
    end)
  end

  defp parse_row(raw) do
    payload = raw |> String.split("#", parts: 2) |> hd() |> String.trim()

    case String.split(payload) do
      [] ->
        :skip

      tokens ->
        {markers, hexes} = Enum.split_with(tokens, &boundary_marker?/1)
        {Enum.map(hexes, &String.to_integer(&1, 16)), Enum.map(markers, &marker_to_break/1)}
    end
  end

  defp boundary_marker?("÷"), do: true
  defp boundary_marker?("×"), do: true
  defp boundary_marker?(_token), do: false

  defp marker_to_break("÷"), do: true
  defp marker_to_break("×"), do: false

  defp marker_to_break(other),
    do: raise("unexpected line-break boundary marker: #{inspect(other)}")
end
