defmodule UnicodeSecurity.Identity.EmojiZwjIntegrity do
  @moduledoc """
  emoji-zwj-integrity — detection of malformed / unsanctioned emoji ZWJ-sequence
  shapes per UTS #51 (the identity-layer detector I3).

  Direct port of `Unicode/Security/Identity/EmojiZwjIntegrity.lean` (via the
  verified rust reference
  `ports/rust/src/security/identity/emoji_zwj_integrity.rs`).

  Threat model. An adversary crafts an emoji-shaped codepoint sequence
  containing one or more `U+200D` ZERO WIDTH JOINERs but violating the
  sanctioned RGI ZWJ-sequence shape — by exceeding the RGI length cap, by
  joining a non-emoji codepoint, by emitting adjacent ZWJ pairs, or by
  overflowing the skin-tone count. Any non-RGI ZWJ-containing sequence is
  renderer-dependent, and that renderer divergence is the attack surface.

  Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
  `emoji-zwj-sequences.txt`, bundled in the port's own
  `priv/data/emoji-zwj-sequences.txt` (never a host emoji library). The
  registered set gives both the exact-match membership test
  (`is_registered_zwj_sequence?`) and the ZWJ *alphabet* — every distinct
  codepoint occurring at any position of any registered sequence, excluding the
  joiner — which is the canonical "what may flank a ZWJ?" predicate. The file is
  parsed with the port's own text-file idiom (mirroring the AiWatermark
  detector's `emoji-data.txt` parser).

  Algorithm (one pass over `input`).
    Phase 1 — collect ZWJ positions and the skin-tone count.
    Phase 2 — short-circuit `Clear` if there are no ZWJs and the skin-tone
              count is at most 1.
    Phase 3 — a registered RGI sequence is always `Clear`.
    Phase 4 — check sub-threats by priority:
                1. `DoubleZWJ`            ZWJ-ZWJ adjacency
                2. `NonEmojiInjection`    ZWJ adjacent to a non-emoji codepoint
                3. `OverLength`           sequence longer than the RGI cap
                4. `SkinToneOverflow`     skin-tone count >= 5
                5. `UnregisteredSequence` catch-all when ZWJs are present but
                                          the sequence is not registered.
  """

  alias UnicodeSecurity.Data

  # ───────────────────────────────────────────────────────────────────
  # §1 Constants
  # ───────────────────────────────────────────────────────────────────

  # Conservative cap on the length of a sanctioned RGI ZWJ sequence
  # (`maxRgiLength` in the Lean spec). The longest current entry (a four-person
  # family with skin tones) reaches ~13-14 codepoints; 16 is a safe upper bound.
  @max_rgi_length 16

  # The ZERO WIDTH JOINER codepoint.
  @zwj 0x200D

  @doc "Conservative RGI ZWJ-sequence length cap (`maxRgiLength`)."
  def max_rgi_length, do: @max_rgi_length

  @doc "The ZERO WIDTH JOINER codepoint (`U+200D`)."
  def zwj, do: @zwj

  # ───────────────────────────────────────────────────────────────────
  # §2 Classification tags
  # ───────────────────────────────────────────────────────────────────

  @doc "Fixture-row tag string for a sub-threat map (matches `SubThreat.tag`)."
  def sub_threat_tag(%{kind: :double_zwj}), do: "DoubleZWJ"
  def sub_threat_tag(%{kind: :non_emoji_injection}), do: "NonEmojiInjection"
  def sub_threat_tag(%{kind: :over_length}), do: "OverLength"
  def sub_threat_tag(%{kind: :skin_tone_overflow}), do: "SkinToneOverflow"
  def sub_threat_tag(%{kind: :unregistered_sequence}), do: "UnregisteredSequence"

  @doc "True iff the classification is `Clear`."
  def is_clear(%{kind: :clear}), do: true
  def is_clear(%{kind: :hazard}), do: false

  @doc "Human-facing tag for a hazard classification, or `nil` when clear."
  def classification_tag(%{kind: :clear}), do: nil
  def classification_tag(%{kind: :hazard, sub: sub}), do: sub_threat_tag(sub)

  @doc "Implicated codepoint positions of a classification (empty when clear)."
  def classification_positions(%{kind: :clear}), do: []
  def classification_positions(%{kind: :hazard, positions: positions}), do: positions

  # ───────────────────────────────────────────────────────────────────
  # §3 RGI ZWJ-sequence data (bundled priv/data/emoji-zwj-sequences.txt)
  # ───────────────────────────────────────────────────────────────────

  # Parse the registered RGI ZWJ sequences. Each non-comment row is
  # `<cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ; <desc> # <cmt>`; the codepoint list
  # is the whitespace-separated hex field before the first `;`.
  defp zwj_sequences do
    Data.cached(:emoji_zwj_sequences, fn ->
      Data.read("emoji-zwj-sequences.txt")
      |> String.split("\n")
      |> Enum.reduce([], fn line, acc ->
        [body | _rest] = String.split(line, "#", parts: 2)

        case String.trim(body) do
          "" ->
            acc

          stripped ->
            [seq_field | _tail] = String.split(stripped, ";")

            case parse_sequence(seq_field) do
              {:ok, seq} -> [seq | acc]
              :skip -> acc
            end
        end
      end)
      |> Enum.reverse()
    end)
  end

  # Parse one whitespace-separated hex codepoint field into a codepoint list.
  # Yields `:skip` when the field is empty or any token is not a full hex number.
  defp parse_sequence(field) do
    tokens = String.split(field, ~r/\s+/, trim: true)

    parsed =
      Enum.reduce_while(tokens, [], fn token, acc ->
        case Integer.parse(token, 16) do
          {cp, ""} -> {:cont, [cp | acc]}
          _malformed -> {:halt, :error}
        end
      end)

    case parsed do
      :error -> :skip
      [] -> :skip
      cps -> {:ok, Enum.reverse(cps)}
    end
  end

  # The ZWJ alphabet: every distinct codepoint occurring at any position of any
  # registered RGI ZWJ sequence, excluding the joiner `U+200D` itself.
  defp zwj_alphabet do
    Data.cached(:emoji_zwj_alphabet, fn ->
      zwj_sequences()
      |> Enum.reduce(MapSet.new(), fn seq, set ->
        Enum.reduce(seq, set, fn cp, s ->
          if cp == @zwj, do: s, else: MapSet.put(s, cp)
        end)
      end)
    end)
  end

  @doc "True iff `cps` is exactly a registered RGI ZWJ sequence."
  def is_registered_zwj_sequence?(cps), do: Enum.any?(zwj_sequences(), fn seq -> seq == cps end)

  @doc """
  True iff `cp` appears at some position of a registered RGI ZWJ sequence
  (the canonical "what may flank a ZWJ?" predicate).
  """
  def is_emoji_target?(cp), do: MapSet.member?(zwj_alphabet(), cp)

  # ───────────────────────────────────────────────────────────────────
  # §4 Core predicates
  # ───────────────────────────────────────────────────────────────────

  @doc "True iff `cp` is the ZWJ codepoint."
  def is_zwj?(cp), do: cp == @zwj

  @doc "True iff `cp` is an emoji skin-tone modifier (`U+1F3FB..U+1F3FF`)."
  def is_emoji_modifier?(cp), do: cp >= 0x1F3FB and cp <= 0x1F3FF

  # Positions of every ZWJ in `input`.
  defp zwj_positions(input) do
    input
    |> Enum.with_index()
    |> Enum.filter(fn {cp, _idx} -> is_zwj?(cp) end)
    |> Enum.map(fn {_cp, idx} -> idx end)
  end

  # Count of skin-tone modifier codepoints.
  defp skin_tone_count(input), do: Enum.count(input, &is_emoji_modifier?/1)

  # Positions of the first ZWJ in each ZWJ-ZWJ adjacent pair. `arr` is the input
  # as a tuple (O(1) neighbour access) and `n` its length.
  defp double_zwj_positions(_arr, n) when n < 2, do: []

  defp double_zwj_positions(arr, n) do
    Enum.filter(0..(n - 2)//1, fn idx ->
      is_zwj?(elem(arr, idx)) and is_zwj?(elem(arr, idx + 1))
    end)
  end

  # The first ZWJ position where either neighbour is a non-emoji codepoint, as
  # `{zwj_pos, offending_cp}`, or `nil` if none. A ZWJ at an input edge (no
  # preceding or no following codepoint) is itself an injection-class hazard,
  # reported with offending codepoint 0.
  defp first_non_emoji_injection(arr, n) do
    Enum.reduce_while(0..(n - 1)//1, nil, fn idx, _acc ->
      if is_zwj?(elem(arr, idx)) do
        prev = if idx == 0, do: :none, else: {:some, elem(arr, idx - 1)}
        next = if idx + 1 < n, do: {:some, elem(arr, idx + 1)}, else: :none

        case {prev, next} do
          {{:some, prev_cp}, {:some, next_cp}} ->
            cond do
              not is_emoji_target?(prev_cp) -> {:halt, {idx, prev_cp}}
              not is_emoji_target?(next_cp) -> {:halt, {idx, next_cp}}
              true -> {:cont, nil}
            end

          {:none, _next} ->
            {:halt, {idx, 0}}

          {{:some, _prev_cp}, :none} ->
            {:halt, {idx, 0}}
        end
      else
        {:cont, nil}
      end
    end)
  end

  # ───────────────────────────────────────────────────────────────────
  # §5 Top-level detection
  # ───────────────────────────────────────────────────────────────────

  @doc """
  The EmojiZwjIntegrity detection function. Returns a verdict map mirroring the
  Lean `Verdict`: `input`, `classify`, `zwj_positions`, `chain_length`,
  `is_registered_rgi`, and `skin_tone_count`.
  """
  def detect(input) do
    arr = List.to_tuple(input)
    n = length(input)
    zwjs = zwj_positions(input)
    st_count = skin_tone_count(input)
    is_rgi = is_registered_zwj_sequence?(input)
    chain_len = if zwjs == [], do: 0, else: n

    classify =
      cond do
        # Phase 2: no ZWJs and at most one skin tone is unconditionally clear.
        zwjs == [] and st_count <= 1 -> %{kind: :clear}
        # Phase 3: a registered RGI sequence is always clear.
        is_rgi -> %{kind: :clear}
        # Phase 4: sub-threat priority ladder.
        true -> classify_hazard(arr, n, zwjs, st_count)
      end

    %{
      input: input,
      classify: classify,
      zwj_positions: zwjs,
      chain_length: chain_len,
      is_registered_rgi: is_rgi,
      skin_tone_count: st_count
    }
  end

  # Phase 4 sub-threat ladder for a non-registered, ZWJ-or-multi-skin-tone input.
  defp classify_hazard(arr, n, zwjs, st_count) do
    dzwj = double_zwj_positions(arr, n)

    cond do
      # Phase 4.1: ZWJ-ZWJ adjacency.
      dzwj != [] ->
        %{
          kind: :hazard,
          sub: %{kind: :double_zwj, positions: dzwj},
          positions: dzwj,
          decoded: []
        }

      # Phase 4.2 .. 4.5.
      true ->
        case first_non_emoji_injection(arr, n) do
          # Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
          {zwj_pos, offend_cp} ->
            %{
              kind: :hazard,
              sub: %{kind: :non_emoji_injection, zwj_pos: zwj_pos, non_emoji_cp: offend_cp},
              positions: [zwj_pos],
              decoded: []
            }

          nil ->
            cond do
              # Phase 4.3: length cap.
              n > @max_rgi_length ->
                %{
                  kind: :hazard,
                  sub: %{kind: :over_length, length: n, max_length: @max_rgi_length},
                  positions: [],
                  decoded: []
                }

              # Phase 4.4: skin-tone overflow.
              st_count >= 5 ->
                %{
                  kind: :hazard,
                  sub: %{kind: :skin_tone_overflow, count: st_count},
                  positions: [],
                  decoded: []
                }

              # Phase 4.5: catch-all for unregistered ZWJ sequences.
              zwjs != [] ->
                %{
                  kind: :hazard,
                  sub: %{kind: :unregistered_sequence, chain_len: n},
                  positions: zwjs,
                  decoded: []
                }

              true ->
                %{kind: :clear}
            end
        end
    end
  end
end
