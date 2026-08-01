defmodule UnicodeSecurity.Display.RtlInjection do
  alias UnicodeSecurity.Covert.BidiControlBalance
  alias UnicodeSecurity.Ucd

  def detect(input) do
    strong_rtl = Enum.count(input, &Ucd.strong_rtl?/1)
    {run_len, run_start} = longest_rtl_run(input)

    cond do
      (pos = first_pos(input, &BidiControlBalance.bidi_format_control?/1)) != nil ->
        %{sub: "RloInLTRField", positions: [pos]}

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
