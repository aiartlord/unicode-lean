defmodule UnicodeSecurity.Display.RtlInjection do
  alias UnicodeSecurity.Covert.BidiControlBalance
  alias UnicodeSecurity.Ucd

  @typedoc """
  The declared display direction of the field holding an input.

  A caller handling Hebrew, Arabic or Persian UI text declares its field
  right-to-left. Every other reading treats the input as a declared-LTR string,
  under which right-to-left content is itself the hazard.

  Mirrors `FieldDirection` in `Unicode/Security/Display/RtlInjection.lean`, that
  spec's alias for the UAX #9 paragraph-direction vocabulary.
  """
  @type field_direction :: :ltr | :rtl

  @doc """
  Detection in a field whose declared display direction is `direction`.

  A bidi format control reorders what a reviewer sees whichever way the field
  runs, so Phase 1 holds unconditionally and trumps all.

  Phases 2 and 3 ask whether right-to-left text has taken over or been spliced
  into a left-to-right field. That question has no premise in a right-to-left
  field, where right-to-left text is the content. The mirror-image hazard,
  strong-LTR injection into a right-to-left field, belongs to the separate
  detector the scope note assigns it to.
  """
  @spec detect_with_context(field_direction(), [integer()]) :: map()
  def detect_with_context(direction, input) do
    strong_rtl = Enum.count(input, &Ucd.strong_rtl?/1)
    {run_len, run_start} = longest_rtl_run(input)

    cond do
      # Phase 1: bidi format-control trumps all, in either direction.
      (pos = first_pos(input, &BidiControlBalance.bidi_format_control?/1)) != nil ->
        %{sub: "BidiControlInLTRField", positions: [pos]}

      # A right-to-left field carrying right-to-left text carries its content.
      direction == :rtl ->
        %{sub: nil, positions: []}

      match?({_pos, true}, first_strong_char(input)) ->
        {pos, true} = first_strong_char(input)
        %{sub: "FieldTakeover", positions: [pos]}

      strong_rtl == 0 ->
        %{sub: nil, positions: []}

      run_len >= 4 ->
        %{sub: "MixedOverflow", positions: [run_start]}

      true ->
        case first_pos(input, &Ucd.strong_rtl?/1) do
          nil -> %{sub: nil, positions: []}
          pos -> %{sub: "StrongRTLInLTR", positions: [pos]}
        end
    end
  end

  @doc """
  Detection in a field declared left-to-right, the reading the module scope note
  fixes for an undeclared field.
  """
  def detect(input), do: detect_with_context(:ltr, input)

  defp first_pos(input, pred) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, i} -> if pred.(cp), do: i, else: nil end)
  end

  defp first_strong_char(input) do
    input
    |> Enum.with_index()
    |> Enum.find_value({nil, nil}, fn {cp, i} ->
      cond do
        Ucd.strong_rtl?(cp) -> {i, true}
        Ucd.strong_ltr?(cp) -> {i, false}
        true -> nil
      end
    end)
  end

  defp longest_rtl_run(input) do
    input
    |> Enum.with_index()
    |> Enum.reduce({0, 0, 0, 0}, fn {cp, i}, {longest, longest_start, current, current_start} ->
      if Ucd.strong_rtl?(cp) do
        start = if current == 0, do: i, else: current_start
        current = current + 1

        if current > longest,
          do: {current, start, current, start},
          else: {longest, longest_start, current, start}
      else
        {longest, longest_start, 0, 0}
      end
    end)
    |> then(fn {longest, start, _cur, _cur_start} -> {longest, start} end)
  end
end
