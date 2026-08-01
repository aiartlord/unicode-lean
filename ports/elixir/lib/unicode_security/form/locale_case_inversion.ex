defmodule UnicodeSecurity.Form.LocaleCaseInversion do
  alias UnicodeSecurity.Casing

  def detect(input) do
    cond do
      (pos = first_locale_divergence(:turkish, input)) != nil ->
        %{sub: "TurkishCaseDivergence", positions: [pos]}

      (pos = first_locale_divergence(:lithuanian, input)) != nil ->
        %{sub: "LithuanianCaseDivergence", positions: [pos]}

      true ->
        %{sub: nil, positions: []}
    end
  end

  defp first_locale_divergence(locale, input) do
    input
    |> Enum.with_index()
    |> Enum.reduce_while([], fn {cp, i}, rev_prefix ->
      suffix = Enum.drop(input, i + 1)
      default = Casing.lower_codepoint(:default, rev_prefix, suffix, cp)
      locale_lower = Casing.lower_codepoint(locale, rev_prefix, suffix, cp)
      if default != locale_lower, do: {:halt, i}, else: {:cont, [cp | rev_prefix]}
    end)
    |> case do
      rev when is_list(rev) -> nil
      pos -> pos
    end
  end
end
