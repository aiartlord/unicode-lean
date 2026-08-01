defmodule UnicodeSecurity.Segmentation.GraphemeTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Segmentation.Grapheme

  @break_test_path Path.join([__DIR__, "fixtures", "GraphemeBreakTest.txt"])

  # --------------------------------------------------------------------------
  # Core UAX #29 vectors, mirroring `ports/rust/tests/segmentation.rs` and the
  # unit tests in `ports/rust/src/segmentation/grapheme.rs`.
  # --------------------------------------------------------------------------

  test "ASCII: each code point is its own cluster (GB999)" do
    assert Grapheme.grapheme_breaks([0x61, 0x62, 0x63]) == [true, true, true, true]
    assert length(Grapheme.grapheme_clusters([0x61, 0x62, 0x63])) == 3
  end

  test "combining mark joins the base (GB9)" do
    # e + COMBINING ACUTE ACCENT (U+0301) is one cluster.
    assert Grapheme.grapheme_breaks([0x65, 0x0301]) == [true, false, true]
    assert length(Grapheme.grapheme_clusters([0x65, 0x0301])) == 1
  end

  test "CR LF is a single cluster (GB3)" do
    assert Grapheme.grapheme_breaks([0x0D, 0x0A]) == [true, false, true]
  end

  test "regional-indicator flag pair is one cluster (GB12)" do
    # 🇯🇵 (U+1F1EF U+1F1F5).
    assert Grapheme.grapheme_breaks([0x1F1EF, 0x1F1F5]) == [true, false, true]
    assert length(Grapheme.grapheme_clusters([0x1F1EF, 0x1F1F5])) == 1
  end

  test "four regional indicators = two flags = two clusters (GB12/GB13 parity)" do
    cps = [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8]
    assert length(Grapheme.grapheme_clusters(cps)) == 2
  end

  test "emoji ZWJ sequence is one cluster (GB11)" do
    # 👨‍👩‍👧 : man ZWJ woman ZWJ girl.
    cps = [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467]
    assert length(Grapheme.grapheme_clusters(cps)) == 1
  end

  # --------------------------------------------------------------------------
  # Full GraphemeBreakTest.txt conformance: every ÷ / × boundary must reproduce.
  # --------------------------------------------------------------------------

  test "every GraphemeBreakTest.txt row reproduces exactly" do
    rows = parse_break_test(@break_test_path)

    # The bundled Unicode 17.0.0 file carries 766 test rows.
    assert length(rows) == 766

    failures =
      Enum.reduce(rows, [], fn {line_no, cps, expected}, acc ->
        actual = Grapheme.grapheme_breaks(cps)

        if actual == expected do
          acc
        else
          [{line_no, cps, expected, actual} | acc]
        end
      end)

    assert failures == [],
           "GraphemeBreakTest.txt mismatches:\n" <>
             Enum.map_join(Enum.reverse(failures), "\n", fn {line_no, cps, expected, actual} ->
               "  line #{line_no}: cps=#{inspect(cps, base: :hex)} " <>
                 "expected=#{inspect(expected)} actual=#{inspect(actual)}"
             end)
  end

  # --------------------------------------------------------------------------
  # Fixture parser. Each data row is a sequence of boundary markers and hex code
  # points: ÷ hex (× | ÷) hex ... ÷, optionally trailed by a `#` comment.
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
    # Drop any trailing comment, then whitespace-tokenize.
    payload = raw |> String.split("#", parts: 2) |> hd() |> String.trim()

    case String.split(payload) do
      [] ->
        :skip

      tokens ->
        {markers, hexes} = Enum.split_with(tokens, &boundary_marker?/1)
        expected = Enum.map(markers, &marker_to_break/1)
        cps = Enum.map(hexes, &String.to_integer(&1, 16))
        {cps, expected}
    end
  end

  defp boundary_marker?("÷"), do: true
  defp boundary_marker?("×"), do: true
  defp boundary_marker?(_token), do: false

  defp marker_to_break("÷"), do: true
  defp marker_to_break("×"), do: false

  defp marker_to_break(other),
    do: raise("unexpected grapheme boundary marker: #{inspect(other)}")
end
