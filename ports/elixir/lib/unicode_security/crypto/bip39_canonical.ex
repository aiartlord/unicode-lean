defmodule UnicodeSecurity.Crypto.Bip39Canonical do
  alias UnicodeSecurity.{Casing, Data, Ucd, Utf8}

  @wordlist_files [
    {"english", "english.txt"},
    {"japanese", "japanese.txt"},
    {"korean", "korean.txt"},
    {"spanish", "spanish.txt"},
    {"chinese_simplified", "chinese_simplified.txt"},
    {"chinese_traditional", "chinese_traditional.txt"},
    {"french", "french.txt"},
    {"italian", "italian.txt"},
    {"czech", "czech.txt"},
    {"portuguese", "portuguese.txt"}
  ]

  def bip39_canonical(cps),
    do:
      cps
      |> Ucd.to_nfkd()
      |> then(&Casing.to_lower(:default, &1))
      |> collapse_whitespace_to_single()
      |> trim_leading_trailing()

  def detect(input) do
    canonical = bip39_canonical(input)
    words = split_words(canonical)
    word_count = length(words)
    trailing_count = count_trailing_whitespace(input)
    uppercase_pos = Enum.find_index(input, fn cp -> cp >= ?A and cp <= ?Z end)
    whitespace_pos = first_whitespace_run_pos(input)
    nfkd = Ucd.to_nfkd(input)
    non_nfkd_pos = if input == nfkd, do: nil, else: first_divergence(input, nfkd)
    unknown_idx = Enum.find_index(words, fn word -> wordlists_containing(word) == [] end)
    lang = unique_language(words)

    cond do
      trailing_count > 0 ->
        %{
          sub: "TrailingWhitespace",
          positions: [length(input) - trailing_count],
          language: nil,
          canonical: canonical,
          word_count: word_count
        }

      uppercase_pos != nil ->
        %{
          sub: "MixedCase",
          positions: [uppercase_pos],
          language: nil,
          canonical: canonical,
          word_count: word_count
        }

      whitespace_pos != nil ->
        %{
          sub: "WhitespaceAnomaly",
          positions: [whitespace_pos],
          language: nil,
          canonical: canonical,
          word_count: word_count
        }

      non_nfkd_pos != nil ->
        %{
          sub: "NonNFKD",
          positions: [non_nfkd_pos],
          language: nil,
          canonical: canonical,
          word_count: word_count
        }

      unknown_idx != nil ->
        %{
          sub: "WordlistMismatch",
          positions: [unknown_idx],
          language: nil,
          canonical: canonical,
          word_count: word_count
        }

      lang == nil ->
        %{
          sub: "LanguageAmbiguous",
          positions: [],
          language: nil,
          canonical: canonical,
          word_count: word_count
        }

      true ->
        %{sub: nil, positions: [], language: lang, canonical: canonical, word_count: word_count}
    end
  end

  defp wordlists do
    Data.cached(:bip39_wordlists, fn ->
      Enum.map(@wordlist_files, fn {name, file} ->
        set =
          Data.read("bip39/" <> file)
          |> String.split("\n", trim: true)
          |> Enum.map(fn line -> line |> Utf8.decode_to_codepoints() |> key() end)
          |> MapSet.new()

        %{name: name, set: set}
      end)
    end)
  end

  defp key(cps), do: Enum.join(cps, ",")
  defp bip39_whitespace?(cp), do: cp == 0x20 or cp == 0x3000

  defp collapse_whitespace_to_single(cps) do
    {out, _in_ws} =
      Enum.reduce(cps, {[], false}, fn cp, {out, in_ws} ->
        if bip39_whitespace?(cp) do
          if in_ws, do: {out, true}, else: {[0x20 | out], true}
        else
          {[cp | out], false}
        end
      end)

    Enum.reverse(out)
  end

  defp trim_leading_trailing(cps) do
    cps
    |> Enum.drop_while(&(&1 == 0x20))
    |> Enum.reverse()
    |> Enum.drop_while(&(&1 == 0x20))
    |> Enum.reverse()
  end

  defp split_words(canonical) do
    canonical
    |> Enum.chunk_by(&(&1 == 0x20))
    |> Enum.reject(fn chunk -> chunk == [0x20] or Enum.all?(chunk, &(&1 == 0x20)) end)
  end

  defp wordlists_containing(word) do
    k = key(word)
    wordlists() |> Enum.filter(fn wl -> MapSet.member?(wl.set, k) end) |> Enum.map(& &1.name)
  end

  defp unique_language(words) do
    Enum.find_value(wordlists(), fn wl ->
      if Enum.all?(words, fn word -> MapSet.member?(wl.set, key(word)) end),
        do: wl.name,
        else: nil
    end)
  end

  defp count_trailing_whitespace(cps),
    do: cps |> Enum.reverse() |> Enum.take_while(&bip39_whitespace?/1) |> length()

  defp first_whitespace_run_pos(cps) do
    count = length(cps)

    Enum.find(0..max(count - 1, 0), fn i ->
      bip39_whitespace?(Enum.at(cps, i)) and
        (i == 0 or (i < count - 1 and bip39_whitespace?(Enum.at(cps, i + 1))))
    end)
  end

  defp first_divergence(a, b) do
    n = min(length(a), length(b))
    pos = Enum.find(0..max(n - 1, 0), fn i -> n > 0 and Enum.at(a, i) != Enum.at(b, i) end)

    cond do
      pos != nil -> pos
      length(a) != length(b) -> n
      true -> nil
    end
  end
end
