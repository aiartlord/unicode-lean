defmodule UnicodeSecurity.Ucd do
  @moduledoc """
  UCD-table-backed support for the identity-spoofing detector family — canonical
  and compatibility normalization (NFC/NFD/NFKC/NFKD), Bidi_Class lookup, script
  resolution, and the UTS #39 §5.1 restriction-level classification.

  All tables are parsed once from the bundled UCD files under `priv/data/` and
  memoised. The spec's `@missing` defaults (CCC = 0 for unlisted codepoints per
  UAX #44 §5.7.4, Bidi_Class L for codepoints outside every listed range) are
  written as explicit fall-through returns, not silent lookup defaults.

  Normalization is implemented directly against the pinned UnicodeData /
  CompositionExclusions tables; it does not call any platform normalization
  routine, whose canonical data can diverge from the pinned UCD 17.0.0.
  """

  alias UnicodeSecurity.Data

  # ── Range-table binary search ──────────────────────────────────────────
  # Ranges are stored as a tuple of `{lo, hi, value}` sorted by `lo`; lookup
  # finds the rightmost range whose `lo <= cp` and confirms `cp <= hi`.

  defp find_range(ranges_tuple, cp) do
    size = tuple_size(ranges_tuple)
    idx = partition_point(ranges_tuple, size, cp)

    if idx > 0 do
      {lo, hi, value} = elem(ranges_tuple, idx - 1)

      if lo <= cp and cp <= hi do
        value
      else
        nil
      end
    else
      nil
    end
  end

  # Smallest index whose element's `lo` is strictly greater than `cp`.
  defp partition_point(ranges_tuple, size, cp) do
    do_partition(ranges_tuple, 0, size, cp)
  end

  defp do_partition(_ranges, lo, hi, _cp) when lo >= hi, do: lo

  defp do_partition(ranges, lo, hi, cp) do
    mid = div(lo + hi, 2)
    {rlo, _rhi, _v} = elem(ranges, mid)

    if rlo <= cp do
      do_partition(ranges, mid + 1, hi, cp)
    else
      do_partition(ranges, lo, mid, cp)
    end
  end

  # ── Line / field parsing helpers ───────────────────────────────────────

  defp strip_comment_and_trim(line) do
    case :binary.split(line, "#") do
      [body | _] -> String.trim(body)
      [] -> String.trim(line)
    end
  end

  defp parse_hex(s), do: String.to_integer(String.trim(s), 16)

  defp parse_range_field(s) do
    s = String.trim(s)

    case String.split(s, "..", parts: 2) do
      [single] -> {parse_hex(single), parse_hex(single)}
      [lo, hi] -> {parse_hex(lo), parse_hex(hi)}
    end
  end

  # ── UnicodeData.txt — CCC + canonical/compat decomposition ─────────────

  @doc "Canonical Combining Class of `cp` (UAX #44 §5.7.4 default 0)."
  @spec ccc(integer()) :: non_neg_integer()
  def ccc(cp) do
    case Map.get(ucd_table(), cp) do
      nil -> 0
      {c, _canon, _compat} -> c
    end
  end

  defp ucd_table do
    Data.cached(:ucd_table, &parse_unicode_data/0)
  end

  defp parse_unicode_data do
    Data.read("UnicodeData.txt")
    |> String.split("\n")
    |> Enum.reduce(%{}, fn line, acc ->
      cond do
        line == "" or String.starts_with?(line, "#") ->
          acc

        true ->
          fields = String.split(line, ";")

          if length(fields) < 6 do
            acc
          else
            cp = parse_hex(Enum.at(fields, 0))
            ccc_val = String.to_integer(String.trim(Enum.at(fields, 3)))
            {canon, compat} = parse_decomp(String.trim(Enum.at(fields, 5)))
            Map.put(acc, cp, {ccc_val, canon, compat})
          end
      end
    end)
  end

  defp parse_decomp(""), do: {nil, nil}

  defp parse_decomp("<" <> _ = field) do
    after_tag =
      case :binary.split(field, ">") do
        [_tag, rest] -> rest
        [only] -> only
      end

    parts = after_tag |> String.split(~r/\s+/, trim: true) |> Enum.map(&parse_hex/1)

    case parts do
      [] -> {nil, nil}
      _ -> {nil, parts}
    end
  end

  defp parse_decomp(field) do
    parts = field |> String.split(~r/\s+/, trim: true) |> Enum.map(&parse_hex/1)

    case parts do
      [] -> {nil, nil}
      _ -> {parts, nil}
    end
  end

  # ── DerivedBidiClass.txt — strong Bidi_Class ───────────────────────────

  @doc "Full Bidi_Class lookup, collapsed to the strong distinction (:r/:al/:l/:other)."
  @spec bidi_strong(integer()) :: :r | :al | :l | :other
  def bidi_strong(cp) do
    {explicit, defaults} = bidi_table()

    case find_range(explicit, cp) do
      nil ->
        Enum.reduce(defaults, :l, fn {rlo, rhi, cls}, acc ->
          if rlo <= cp and cp <= rhi, do: cls, else: acc
        end)

      cls ->
        cls
    end
  end

  @doc "True iff `cp` has Bidi_Class R or AL (strong RTL)."
  @spec strong_rtl?(integer()) :: boolean()
  def strong_rtl?(cp), do: bidi_strong(cp) in [:r, :al]

  @doc "True iff `cp` has Bidi_Class L (strong LTR)."
  @spec strong_ltr?(integer()) :: boolean()
  def strong_ltr?(cp), do: bidi_strong(cp) == :l

  defp bidi_table do
    Data.cached(:bidi_table, &parse_derived_bidi/0)
  end

  defp parse_derived_bidi do
    lines = Data.read("DerivedBidiClass.txt") |> String.split("\n")

    {explicit, defaults} =
      Enum.reduce(lines, {[], []}, fn line, {exp, defs} ->
        cond do
          String.starts_with?(line, "# @missing:") ->
            rest = String.replace_prefix(line, "# @missing:", "")

            case String.split(rest, ";", parts: 2) do
              [range, cls] ->
                {lo, hi} = parse_range_field(range)
                {exp, [{lo, hi, strong_of_long(String.trim(cls))} | defs]}

              _ ->
                {exp, defs}
            end

          true ->
            body = strip_comment_and_trim(line)

            if body == "" do
              {exp, defs}
            else
              case String.split(body, ";", parts: 2) do
                [range, cls] ->
                  {lo, hi} = parse_range_field(range)
                  {[{lo, hi, strong_of_short(String.trim(cls))} | exp], defs}

                _ ->
                  {exp, defs}
              end
            end
        end
      end)

    sorted_explicit =
      explicit |> Enum.sort_by(fn {lo, _hi, _v} -> lo end) |> List.to_tuple()

    {sorted_explicit, Enum.reverse(defaults)}
  end

  defp strong_of_short("R"), do: :r
  defp strong_of_short("AL"), do: :al
  defp strong_of_short("L"), do: :l
  defp strong_of_short(_other), do: :other

  defp strong_of_long("Right_To_Left"), do: :r
  defp strong_of_long("Arabic_Letter"), do: :al
  defp strong_of_long("Left_To_Right"), do: :l
  defp strong_of_long(_other), do: :other

  # ── CompositionExclusions.txt + composition table ──────────────────────

  defp composition_exclusions do
    Data.cached(:composition_exclusions, fn ->
      Data.read("CompositionExclusions.txt")
      |> String.split("\n")
      |> Enum.reduce(MapSet.new(), fn line, acc ->
        case strip_comment_and_trim(line) do
          "" -> acc
          stripped -> MapSet.put(acc, parse_hex(stripped))
        end
      end)
    end)
  end

  defp composition_table do
    Data.cached(:composition_table, fn ->
      exclusions = composition_exclusions()

      Enum.reduce(ucd_table(), %{}, fn {cp, {_ccc, canon, _compat}}, acc ->
        with true <- match?([_a, _b], canon),
             [a, b] <- canon,
             false <- MapSet.member?(exclusions, cp),
             true <- ccc(a) == 0 do
          Map.put(acc, {a, b}, cp)
        else
          _ -> acc
        end
      end)
    end)
  end

  # ── Hangul algorithmic decomposition + composition (UAX #15 §1.3) ───────

  @s_base 0xAC00
  @l_base 0x1100
  @v_base 0x1161
  @t_base 0x11A7
  @l_count 19
  @v_count 21
  @t_count 28
  @n_count @v_count * @t_count
  @s_count @l_count * @n_count

  defp hangul_decompose(cp) do
    if cp >= @s_base and cp < @s_base + @s_count do
      s_index = cp - @s_base
      l = @l_base + div(s_index, @n_count)
      v = @v_base + div(rem(s_index, @n_count), @t_count)
      t_index = rem(s_index, @t_count)

      if t_index != 0 do
        [l, v, @t_base + t_index]
      else
        [l, v]
      end
    else
      nil
    end
  end

  defp hangul_compose(a, b) do
    cond do
      a >= @l_base and a < @l_base + @l_count and b >= @v_base and b < @v_base + @v_count ->
        l_index = a - @l_base
        v_index = b - @v_base
        @s_base + (l_index * @v_count + v_index) * @t_count

      a >= @s_base and a < @s_base + @s_count and rem(a - @s_base, @t_count) == 0 and
        b >= @t_base + 1 and b < @t_base + @t_count ->
        a + (b - @t_base)

      true ->
        nil
    end
  end

  # ── Canonical decompose / reorder / compose ────────────────────────────

  defp decompose_one(cp, out, decomp_field) do
    case hangul_decompose(cp) do
      nil ->
        entry = Map.get(ucd_table(), cp)
        decomp = if entry, do: elem(entry, decomp_field), else: nil

        case decomp do
          nil ->
            [cp | out]

          children ->
            Enum.reduce(children, out, fn child, acc -> decompose_one(child, acc, 1) end)
        end

      parts ->
        # Hangul syllables have no further decomposition.
        Enum.reduce(parts, out, fn part, acc -> [part | acc] end)
    end
  end

  defp canonical_decompose(cps) do
    cps
    |> Enum.reduce([], fn cp, acc -> decompose_one(cp, acc, 1) end)
    |> Enum.reverse()
  end

  # Compatibility decompose prefers the compat mapping (field index 2), falling
  # back to the canonical mapping, then Hangul.
  defp compat_decompose_one(cp, out) do
    case hangul_decompose(cp) do
      nil ->
        entry = Map.get(ucd_table(), cp)

        cond do
          entry == nil ->
            [cp | out]

          elem(entry, 2) != nil ->
            Enum.reduce(elem(entry, 2), out, fn child, acc -> compat_decompose_one(child, acc) end)

          elem(entry, 1) != nil ->
            Enum.reduce(elem(entry, 1), out, fn child, acc -> compat_decompose_one(child, acc) end)

          true ->
            [cp | out]
        end

      parts ->
        Enum.reduce(parts, out, fn part, acc -> [part | acc] end)
    end
  end

  defp compat_decompose(cps) do
    cps
    |> Enum.reduce([], fn cp, acc -> compat_decompose_one(cp, acc) end)
    |> Enum.reverse()
  end

  # Stable-sort each maximal non-starter run (CCC != 0) by CCC.
  defp canonical_reorder([]), do: []

  defp canonical_reorder([h | t] = list) do
    if ccc(h) == 0 do
      [h | canonical_reorder(t)]
    else
      {run, rest} = Enum.split_while(list, fn cp -> ccc(cp) != 0 end)
      Enum.sort_by(run, &ccc/1) ++ canonical_reorder(rest)
    end
  end

  # Canonical recomposition (UAX #15 D115). See `canonical_compose/1`.
  defp canonical_compose([]), do: []

  defp canonical_compose(seq) do
    comp = composition_table()

    {done_rev, starter, pending_rev} =
      Enum.reduce(seq, {[], :none, [], -1}, fn cp, {done_rev, starter, pending_rev, last_ccc} ->
        cp_ccc = ccc(cp)

        composed =
          if starter != :none do
            case hangul_compose(starter, cp) do
              nil -> Map.get(comp, {starter, cp})
              value -> value
            end
          else
            nil
          end

        blocked = last_ccc != 0 and (cp_ccc == 0 or last_ccc >= cp_ccc)

        if starter != :none and not blocked and composed != nil do
          {done_rev, composed, pending_rev, last_ccc}
        else
          append_compose(cp, cp_ccc, done_rev, starter, pending_rev)
        end
      end)
      |> then(fn {done_rev, starter, pending_rev, _last_ccc} ->
        {done_rev, starter, pending_rev}
      end)

    tail =
      case starter do
        :none -> []
        s -> [s | Enum.reverse(pending_rev)]
      end

    Enum.reverse(done_rev) ++ tail
  end

  defp append_compose(cp, 0, done_rev, :none, _pending_rev) do
    {done_rev, cp, [], 0}
  end

  defp append_compose(cp, 0, done_rev, starter, pending_rev) do
    {pending_rev ++ [starter] ++ done_rev, cp, [], 0}
  end

  defp append_compose(cp, cp_ccc, done_rev, :none, _pending_rev) do
    {[cp | done_rev], :none, [], cp_ccc}
  end

  defp append_compose(cp, cp_ccc, done_rev, starter, pending_rev) do
    {done_rev, starter, [cp | pending_rev], cp_ccc}
  end

  @doc "The full UAX #15 NFC pipeline (decompose, reorder, recompose)."
  @spec to_nfc([integer()]) :: [integer()]
  def to_nfc(cps) do
    cps |> canonical_decompose() |> canonical_reorder() |> canonical_compose()
  end

  @doc "UAX #15 NFD — canonical decompose + canonical reorder, no recomposition."
  @spec to_nfd([integer()]) :: [integer()]
  def to_nfd(cps) do
    cps |> canonical_decompose() |> canonical_reorder()
  end

  @doc "UAX #15 NFKD — full compatibility decompose + canonical reorder."
  @spec to_nfkd([integer()]) :: [integer()]
  def to_nfkd(cps) do
    cps |> compat_decompose() |> canonical_reorder()
  end

  @doc "UAX #15 NFKC — NFKD followed by canonical recomposition."
  @spec to_nfkc([integer()]) :: [integer()]
  def to_nfkc(cps) do
    cps |> to_nfkd() |> canonical_compose()
  end

  # ── CaseFolding.txt — default full case folding (RFC 8265 §5.2.4) ───────

  defp case_folding_table do
    Data.cached(:case_folding_table, fn ->
      Data.read("CaseFolding.txt")
      |> String.split("\n")
      |> Enum.reduce(%{}, fn line, acc ->
        case strip_comment_and_trim(line) do
          "" ->
            acc

          stripped ->
            parts = stripped |> String.split(";") |> Enum.map(&String.trim/1)

            case parts do
              [src, status, tgt | _] when status in ["C", "F"] ->
                targets = tgt |> String.split(~r/\s+/, trim: true) |> Enum.map(&parse_hex/1)

                case targets do
                  [] -> acc
                  _ -> Map.put(acc, parse_hex(src), targets)
                end

              _ ->
                acc
            end
        end
      end)
    end)
  end

  @doc "Default full case folding of a codepoint sequence (CaseFolding.txt C ∪ F)."
  @spec case_fold([integer()]) :: [integer()]
  def case_fold(cps) do
    table = case_folding_table()

    Enum.flat_map(cps, fn cp ->
      case Map.get(table, cp) do
        nil -> [cp]
        replacement -> replacement
      end
    end)
  end

  # ── PropertyValueAliases.txt — script long name ↔ 4-letter abbrev ───────

  defp script_name_to_abbrev do
    Data.cached(:script_name_to_abbrev, fn ->
      Data.read("PropertyValueAliases.txt")
      |> String.split("\n")
      |> Enum.reduce(%{}, fn line, acc ->
        case strip_comment_and_trim(line) do
          "" ->
            acc

          stripped ->
            parts = stripped |> String.split(";") |> Enum.map(&String.trim/1)

            case parts do
              ["sc", short, long_name | _] -> Map.put(acc, long_name, short)
              _ -> acc
            end
        end
      end)
    end)
  end

  defp script_long_to_abbrev(name) do
    case Map.get(script_name_to_abbrev(), name) do
      nil -> raise "script_long_to_abbrev: #{inspect(name)} not in PropertyValueAliases.txt"
      short -> short
    end
  end

  # ── Scripts.txt — codepoint → primary script (long name) ───────────────

  defp scripts_table do
    Data.cached(:scripts_table, fn ->
      Data.read("Scripts.txt")
      |> String.split("\n")
      |> Enum.reduce([], fn line, acc ->
        case strip_comment_and_trim(line) do
          "" ->
            acc

          stripped ->
            case String.split(stripped, ";", parts: 2) do
              [range, value] ->
                {lo, hi} = parse_range_field(range)
                [{lo, hi, String.trim(value)} | acc]

              _ ->
                acc
            end
        end
      end)
      |> Enum.sort_by(fn {lo, _hi, _v} -> lo end)
      |> List.to_tuple()
    end)
  end

  @doc "Primary script long name for `cp`, or \"Unknown\"."
  @spec script_of(integer()) :: String.t()
  def script_of(cp) do
    case find_range(scripts_table(), cp) do
      nil -> "Unknown"
      value -> value
    end
  end

  # ── ScriptExtensions.txt — codepoint → multi-script abbrev list ─────────

  defp script_extensions_table do
    Data.cached(:script_extensions_table, fn ->
      Data.read("ScriptExtensions.txt")
      |> String.split("\n")
      |> Enum.reduce([], fn line, acc ->
        case strip_comment_and_trim(line) do
          "" ->
            acc

          stripped ->
            case String.split(stripped, ";", parts: 2) do
              [range, value] ->
                {lo, hi} = parse_range_field(range)
                scripts = value |> String.trim() |> String.split(~r/\s+/, trim: true)

                case scripts do
                  [] -> acc
                  _ -> [{lo, hi, scripts} | acc]
                end

              _ ->
                acc
            end
        end
      end)
      |> Enum.sort_by(fn {lo, _hi, _v} -> lo end)
      |> List.to_tuple()
    end)
  end

  @doc "Resolved-script abbreviations for `cp` (ScriptExtensions, else primary script)."
  @spec resolve_scripts(integer()) :: [String.t()]
  def resolve_scripts(cp) do
    case find_range(script_extensions_table(), cp) do
      nil -> [script_long_to_abbrev(script_of(cp))]
      scripts -> scripts
    end
  end

  @doc "True iff `cp`'s primary script is Common."
  @spec common_script?(integer()) :: boolean()
  def common_script?(cp), do: script_of(cp) == "Common"

  @doc "True iff `cp`'s primary script is Inherited."
  @spec inherited_script?(integer()) :: boolean()
  def inherited_script?(cp), do: script_of(cp) == "Inherited"

  @doc "True iff `cp` is ignored for script-intersection purposes (Common/Inherited)."
  @spec ignored_for_intersection?(integer()) :: boolean()
  def ignored_for_intersection?(cp), do: common_script?(cp) or inherited_script?(cp)

  @doc "Ordered union of resolved scripts across the sequence, ignoring Common/Inherited."
  @spec string_script_union([integer()]) :: [String.t()]
  def string_script_union(cps) do
    Enum.reduce(cps, [], fn cp, acc ->
      if ignored_for_intersection?(cp) do
        acc
      else
        Enum.reduce(resolve_scripts(cp), acc, fn s, inner ->
          if s in inner, do: inner, else: inner ++ [s]
        end)
      end
    end)
  end

  # ── IdentifierStatus.txt — UTS #39 Allowed set ─────────────────────────

  defp id_allowed_ranges do
    Data.cached(:id_allowed_ranges, fn ->
      Data.read("IdentifierStatus.txt")
      |> String.split("\n")
      |> Enum.reduce([], fn line, acc ->
        case strip_comment_and_trim(line) do
          "" ->
            acc

          stripped ->
            case String.split(stripped, ";", parts: 2) do
              [range, status] ->
                if String.trim(status) == "Allowed" do
                  {lo, hi} = parse_range_field(range)
                  [{lo, hi, true} | acc]
                else
                  acc
                end

              _ ->
                acc
            end
        end
      end)
      |> Enum.sort_by(fn {lo, _hi, _v} -> lo end)
      |> List.to_tuple()
    end)
  end

  @doc "True iff `cp` is in the UTS #39 General-Security-Profile Allowed set."
  @spec id_allowed?(integer()) :: boolean()
  def id_allowed?(cp), do: find_range(id_allowed_ranges(), cp) == true

  # ── DerivedCoreProperties.txt — Default_Ignorable_Code_Point ───────────

  defp default_ignorable_ranges do
    Data.cached(:default_ignorable_ranges, fn ->
      Data.read("DerivedCoreProperties.txt")
      |> String.split("\n")
      |> Enum.reduce([], fn line, acc ->
        case strip_comment_and_trim(line) do
          "" ->
            acc

          stripped ->
            case String.split(stripped, ";", parts: 2) do
              [range, prop] ->
                if String.trim(prop) == "Default_Ignorable_Code_Point" do
                  {lo, hi} = parse_range_field(range)
                  [{lo, hi, true} | acc]
                else
                  acc
                end

              _ ->
                acc
            end
        end
      end)
      |> Enum.sort_by(fn {lo, _hi, _v} -> lo end)
      |> List.to_tuple()
    end)
  end

  @doc "UAX #44 Default_Ignorable_Code_Point membership."
  @spec default_ignorable?(integer()) :: boolean()
  def default_ignorable?(cp), do: find_range(default_ignorable_ranges(), cp) == true

  @doc """
  UCD PropList White_Space membership. Hardcoded — the range set is small and
  stable (ASCII tab/newline/space, NBSP, NNBSP, the space separators, line and
  paragraph separators, medium math space, ideographic space).
  """
  @spec white_space?(integer()) :: boolean()
  def white_space?(cp) do
    (cp >= 0x0009 and cp <= 0x000D) or cp == 0x0020 or cp == 0x0085 or cp == 0x00A0 or
      cp == 0x1680 or (cp >= 0x2000 and cp <= 0x200A) or (cp >= 0x2028 and cp <= 0x2029) or
      cp == 0x202F or cp == 0x205F or cp == 0x3000
  end

  # ── UTS #39 §5.1 Restriction-level classification ──────────────────────

  @typedoc "UTS #39 §5.1 restriction level."
  @type restriction_level ::
          :ascii_only
          | :single_script
          | :highly_restrictive
          | :moderately_restrictive
          | :minimally_restrictive
          | :unrestricted

  @doc "Wire tag for a restriction level."
  @spec restriction_level_tag(restriction_level()) :: String.t()
  def restriction_level_tag(:ascii_only), do: "ASCIIOnly"
  def restriction_level_tag(:single_script), do: "SingleScript"
  def restriction_level_tag(:highly_restrictive), do: "HighlyRestrictive"
  def restriction_level_tag(:moderately_restrictive), do: "ModeratelyRestrictive"
  def restriction_level_tag(:minimally_restrictive), do: "MinimallyRestrictive"
  def restriction_level_tag(:unrestricted), do: "Unrestricted"

  @doc "True iff every codepoint is below U+0080."
  @spec ascii_only?([integer()]) :: boolean()
  def ascii_only?(cps), do: Enum.all?(cps, fn cp -> cp < 0x80 end)

  defp intersect_many([]), do: []

  defp intersect_many([first | rest]) do
    Enum.reduce(rest, first, fn s, acc -> Enum.filter(acc, fn x -> x in s end) end)
  end

  @doc "Intersection of resolved-script sets across the sequence (Common/Inherited ignored)."
  @spec string_resolved_scripts([integer()]) :: [String.t()]
  def string_resolved_scripts(cps) do
    non_ignored = Enum.reject(cps, &ignored_for_intersection?/1)

    case non_ignored do
      [] -> []
      _ -> non_ignored |> Enum.map(&resolve_scripts/1) |> intersect_many()
    end
  end

  @doc "True iff the sequence is non-ASCII yet resolves to a single common script."
  @spec single_script?([integer()]) :: boolean()
  def single_script?(cps) do
    not ascii_only?(cps) and string_resolved_scripts(cps) != []
  end

  @covered_japanese ["Latn", "Hani", "Hira", "Kana"]
  @covered_chinese ["Latn", "Hani", "Bopo"]
  @covered_korean ["Latn", "Hani", "Hang"]

  defp intersects?(a, b), do: Enum.any?(a, fn x -> x in b end)

  defp all_within_covered?(cps, covered) do
    Enum.all?(cps, fn cp ->
      if ignored_for_intersection?(cp) do
        true
      else
        r = resolve_scripts(cp)
        r != [] and intersects?(r, covered)
      end
    end)
  end

  @doc "True iff the sequence stays within a single covered CJK cover set."
  @spec covered_cjk?([integer()]) :: boolean()
  def covered_cjk?(cps) do
    all_within_covered?(cps, @covered_japanese) or all_within_covered?(cps, @covered_chinese) or
      all_within_covered?(cps, @covered_korean)
  end

  @doc "True iff the sequence is Highly Restrictive (single-script or covered CJK)."
  @spec highly_restrictive?([integer()]) :: boolean()
  def highly_restrictive?(cps), do: single_script?(cps) or covered_cjk?(cps)

  defp moderately_restrictive_shape?(cps) do
    Enum.reduce_while(cps, {:ok, nil}, fn cp, {:ok, other} ->
      if ignored_for_intersection?(cp) do
        {:cont, {:ok, other}}
      else
        r = resolve_scripts(cp)

        cond do
          r == [] -> {:halt, :fail}
          "Latn" in r -> {:cont, {:ok, other}}
          true -> classify_moderate_script(hd(r), other)
        end
      end
    end)
    |> case do
      {:ok, other} -> other != nil
      :fail -> false
    end
  end

  defp classify_moderate_script(s, _other) when s in ["Cyrl", "Grek"], do: {:halt, :fail}
  defp classify_moderate_script(s, nil), do: {:cont, {:ok, s}}
  defp classify_moderate_script(s, other) when s == other, do: {:cont, {:ok, other}}
  defp classify_moderate_script(_s, _other), do: {:halt, :fail}

  @doc "True iff every codepoint is in the UTS #39 Allowed set."
  @spec minimally_restrictive?([integer()]) :: boolean()
  def minimally_restrictive?(cps), do: Enum.all?(cps, &id_allowed?/1)

  @doc "UTS #39 §5.1 restriction level of a codepoint sequence."
  @spec restriction_level([integer()]) :: restriction_level()
  def restriction_level(cps) do
    cond do
      ascii_only?(cps) -> :ascii_only
      single_script?(cps) -> :single_script
      highly_restrictive?(cps) -> :highly_restrictive
      moderately_restrictive_shape?(cps) -> :moderately_restrictive
      minimally_restrictive?(cps) -> :minimally_restrictive
      true -> :unrestricted
    end
  end
end
