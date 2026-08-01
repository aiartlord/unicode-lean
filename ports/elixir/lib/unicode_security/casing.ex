defmodule UnicodeSecurity.Casing do
  @moduledoc """
  UAX #21 case mapping (`to_lower` / `to_upper`).

  Full case mappings from `SpecialCasing.txt` (one-to-many and
  context/locale-dependent rows) combined with the simple case mappings in
  `UnicodeData.txt` field 13 (lowercase) / 12 (uppercase). Context predicates
  (Final_Sigma, After_Soft_Dotted, More_Above, Not_Before_Dot, After_I) use
  canonical combining class plus the `Cased` and `Soft_Dotted` properties from
  `DerivedCoreProperties.txt`.

  Case mapping is computed directly from the pinned tables; it does not call any
  platform case-mapping routine.
  """

  alias UnicodeSecurity.Data
  alias UnicodeSecurity.Ucd

  @typedoc "Locales distinguished by SpecialCasing.txt."
  @type locale :: :default | :turkish | :azeri | :lithuanian

  @locale_conditions ["tr", "az", "lt"]

  defp parse_hex(s), do: String.to_integer(String.trim(s), 16)

  defp parse_cp_list(field) do
    field |> String.split(~r/\s+/, trim: true) |> Enum.map(&parse_hex/1)
  end

  # ── SpecialCasing.txt rows: code => [{lower, title, upper, conditions}] ──

  defp special_rows do
    Data.cached(:special_casing_rows, fn ->
      Data.read("SpecialCasing.txt")
      |> String.split("\n")
      |> Enum.reduce(%{}, fn raw, acc ->
        line =
          case :binary.split(raw, "#") do
            [body | _] -> String.trim(body)
            [] -> String.trim(raw)
          end

        if line == "" do
          acc
        else
          fields = line |> String.split(";") |> Enum.map(&String.trim/1)

          if length(fields) < 4 do
            acc
          else
            code = parse_hex(Enum.at(fields, 0))
            lower = parse_cp_list(Enum.at(fields, 1))
            title = parse_cp_list(Enum.at(fields, 2))
            upper = parse_cp_list(Enum.at(fields, 3))

            conditions =
              case Enum.at(fields, 4) do
                nil -> []
                "" -> []
                conds -> String.split(conds, ~r/\s+/, trim: true)
              end

            row = {lower, title, upper, conditions}
            Map.update(acc, code, [row], fn existing -> existing ++ [row] end)
          end
        end
      end)
    end)
  end

  # ── Simple case mappings from UnicodeData.txt fields 13 / 12 ────────────

  defp simple_maps do
    Data.cached(:simple_case_maps, fn ->
      Data.read("UnicodeData.txt")
      |> String.split("\n")
      |> Enum.reduce({%{}, %{}}, fn line, {lower, upper} ->
        if line == "" do
          {lower, upper}
        else
          fields = String.split(line, ";")

          if length(fields) < 15 do
            {lower, upper}
          else
            cp = parse_hex(Enum.at(fields, 0))
            upper2 = maybe_put_hex(upper, cp, Enum.at(fields, 12))
            lower2 = maybe_put_hex(lower, cp, Enum.at(fields, 13))
            {lower2, upper2}
          end
        end
      end)
    end)
  end

  defp maybe_put_hex(map, _cp, ""), do: map
  defp maybe_put_hex(map, cp, value), do: Map.put(map, cp, parse_hex(value))

  @doc "Simple lowercase of `cp` (self when unmapped)."
  @spec simple_lowercase(integer()) :: integer()
  def simple_lowercase(cp) do
    {lower, _upper} = simple_maps()
    Map.get(lower, cp, cp)
  end

  @doc "Simple uppercase of `cp` (self when unmapped)."
  @spec simple_uppercase(integer()) :: integer()
  def simple_uppercase(cp) do
    {_lower, upper} = simple_maps()
    Map.get(upper, cp, cp)
  end

  # ── Cased / Soft_Dotted derived-property ranges ────────────────────────

  defp derived_property(name) do
    Data.cached({:derived_property, name}, fn ->
      Data.read("DerivedCoreProperties.txt")
      |> String.split("\n")
      |> Enum.reduce([], fn raw, acc ->
        line =
          case :binary.split(raw, "#") do
            [body | _] -> String.trim(body)
            [] -> String.trim(raw)
          end

        if line == "" do
          acc
        else
          case String.split(line, ";", parts: 2) do
            [range, prop] ->
              if String.trim(prop) == name do
                field = String.trim(range)

                case String.split(field, "..", parts: 2) do
                  [single] -> [{parse_hex(single), parse_hex(single)} | acc]
                  [lo, hi] -> [{parse_hex(lo), parse_hex(hi)} | acc]
                end
              else
                acc
              end

            _ ->
              acc
          end
        end
      end)
      |> Enum.sort_by(fn {lo, _hi} -> lo end)
    end)
  end

  defp in_ranges?(ranges, cp), do: Enum.any?(ranges, fn {lo, hi} -> lo <= cp and cp <= hi end)

  defp cased?(cp), do: in_ranges?(derived_property("Cased"), cp)
  defp soft_dotted?(cp), do: in_ranges?(derived_property("Soft_Dotted"), cp)

  # ── UAX #21 context predicates ─────────────────────────────────────────
  # `rev_prefix` is the preceding codepoints nearest-first; `suffix` the
  # strictly-following ones.

  defp more_above_after(suffix) do
    Enum.reduce_while(suffix, false, fn cp, _acc ->
      case Ucd.ccc(cp) do
        230 -> {:halt, true}
        0 -> {:halt, false}
        _ -> {:cont, false}
      end
    end)
  end

  defp after_soft_dotted(rev_prefix) do
    Enum.reduce_while(rev_prefix, false, fn cp, _acc ->
      cond do
        soft_dotted?(cp) -> {:halt, true}
        Ucd.ccc(cp) in [0, 230] -> {:halt, false}
        true -> {:cont, false}
      end
    end)
  end

  defp after_i(rev_prefix) do
    Enum.reduce_while(rev_prefix, false, fn cp, _acc ->
      cond do
        cp == 0x0049 -> {:halt, true}
        Ucd.ccc(cp) in [0, 230] -> {:halt, false}
        true -> {:cont, false}
      end
    end)
  end

  defp before_dot(suffix) do
    Enum.reduce_while(suffix, false, fn cp, _acc ->
      cond do
        cp == 0x0307 -> {:halt, true}
        Ucd.ccc(cp) == 0 -> {:halt, false}
        true -> {:cont, false}
      end
    end)
  end

  defp has_cased_before(rev_prefix) do
    Enum.reduce_while(rev_prefix, false, fn cp, _acc ->
      cond do
        cased?(cp) -> {:halt, true}
        Ucd.ccc(cp) == 0 -> {:halt, false}
        true -> {:cont, false}
      end
    end)
  end

  defp has_cased_after(suffix) do
    Enum.reduce_while(suffix, false, fn cp, _acc ->
      cond do
        cased?(cp) -> {:halt, true}
        Ucd.ccc(cp) == 0 -> {:halt, false}
        true -> {:cont, false}
      end
    end)
  end

  defp final_sigma(rev_prefix, suffix) do
    has_cased_before(rev_prefix) and not has_cased_after(suffix)
  end

  defp locale_matches?(loc, conds) do
    if not Enum.any?(conds, fn c -> c in @locale_conditions end) do
      true
    else
      Enum.any?(conds, fn c ->
        (c == "tr" and loc == :turkish) or (c == "az" and loc == :azeri) or
          (c == "lt" and loc == :lithuanian)
      end)
    end
  end

  defp conditions_hold?(loc, rev_prefix, suffix, conds) do
    if not locale_matches?(loc, conds) do
      false
    else
      Enum.all?(conds, fn c ->
        cond do
          c in @locale_conditions -> true
          c == "Final_Sigma" -> final_sigma(rev_prefix, suffix)
          c == "Not_Final_Sigma" -> not final_sigma(rev_prefix, suffix)
          c == "After_Soft_Dotted" -> after_soft_dotted(rev_prefix)
          c == "More_Above" -> more_above_after(suffix)
          c == "Not_Before_Dot" -> not before_dot(suffix)
          c == "After_I" -> after_i(rev_prefix)
          true -> false
        end
      end)
    end
  end

  defp find_special_row(loc, rev_prefix, suffix, cp) do
    case Map.get(special_rows(), cp) do
      nil ->
        nil

      candidates ->
        conditional =
          Enum.find(candidates, fn {_l, _t, _u, conds} ->
            conds != [] and conditions_hold?(loc, rev_prefix, suffix, conds)
          end)

        case conditional do
          nil -> Enum.find(candidates, fn {_l, _t, _u, conds} -> conds == [] end)
          row -> row
        end
    end
  end

  @doc "Lowercase a single codepoint in context (UAX #21 full mapping)."
  @spec lower_codepoint(locale(), [integer()], [integer()], integer()) :: [integer()]
  def lower_codepoint(loc, rev_prefix, suffix, cp) do
    case find_special_row(loc, rev_prefix, suffix, cp) do
      {lower, _title, _upper, _conds} -> lower
      nil -> [simple_lowercase(cp)]
    end
  end

  @doc "Uppercase a single codepoint in context (UAX #21 full mapping)."
  @spec upper_codepoint(locale(), [integer()], [integer()], integer()) :: [integer()]
  def upper_codepoint(loc, rev_prefix, suffix, cp) do
    case find_special_row(loc, rev_prefix, suffix, cp) do
      {_lower, _title, upper, _conds} -> upper
      nil -> [simple_uppercase(cp)]
    end
  end

  @doc "Lowercase a codepoint sequence under `loc`."
  @spec to_lower(locale(), [integer()]) :: [integer()]
  def to_lower(loc, cps), do: map_cased(loc, cps, &lower_codepoint/4)

  @doc "Uppercase a codepoint sequence under `loc`."
  @spec to_upper(locale(), [integer()]) :: [integer()]
  def to_upper(loc, cps), do: map_cased(loc, cps, &upper_codepoint/4)

  defp map_cased(loc, cps, mapper) do
    {out_rev, _rev_prefix} =
      cps
      |> tag_suffixes()
      |> Enum.reduce({[], []}, fn {cp, suffix}, {out_rev, rev_prefix} ->
        mapped = mapper.(loc, rev_prefix, suffix, cp)
        {Enum.reverse(mapped) ++ out_rev, [cp | rev_prefix]}
      end)

    Enum.reverse(out_rev)
  end

  # Pair each codepoint with the strictly-following suffix.
  defp tag_suffixes(cps) do
    do_tag_suffixes(cps, [])
  end

  defp do_tag_suffixes([], acc), do: Enum.reverse(acc)

  defp do_tag_suffixes([cp | rest], acc) do
    do_tag_suffixes(rest, [{cp, rest} | acc])
  end
end
