defmodule UnicodeSecurity.Form.StreamSafeViolation do
  @moduledoc """
  Stream-Safe-Text-Format-violation detection — inputs whose consecutive
  non-starter run exceeds the UAX #15 §13 `streamSafeLimit` of 30. Such an
  input (the canonical "Zalgo" shape, a single base codepoint followed by a
  long combining-mark run) forces unbounded combining-mark buffers in
  receiver-side streaming normalization (`toNFC` / `toNFD` / `toNFKC` /
  `toNFKD`) and is a known DoS vector.

  Byte-faithful port of `ports/rust/src/security/form/stream_safe_violation.rs`,
  itself a direct port of `Unicode/Security/Form/StreamSafeViolation.lean`.
  UAX #15 §13 defines Stream-Safe Text Format as the remediation: insert U+034F
  COMBINING GRAPHEME JOINER (a starter) after every 30 consecutive non-starters,
  which bounds the normalization buffer.

  A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
  (UAX #15 D49). This module reads CCC from the port's own bundled UCD table via
  `UnicodeSecurity.Ucd.ccc/1`, never a host normalizer.

  Sub-threat: `StreamSafeOverrun` with `base_pos` (the index of the offending
  run's first non-starter codepoint) and `run_len` (the run's length) — the
  first non-starter run whose length exceeds `stream_safe_limit`.
  """

  alias UnicodeSecurity.Ucd

  # UAX #15 §13 Stream-Safe limit: the maximum number of consecutive
  # non-starters permitted before a COMBINING GRAPHEME JOINER must be inserted.
  @stream_safe_limit 30

  @doc "UAX #15 §13 Stream-Safe limit (30)."
  def stream_safe_limit, do: @stream_safe_limit

  @doc """
  Detect a Stream-Safe violation. Returns a verdict map exposing the full
  run inventory alongside the `sub`/`positions` shape the policy layer consumes.
  Fires `StreamSafeOverrun` on the first non-starter run longer than
  `stream_safe_limit`.
  """
  def detect(input) do
    {classify, sub, positions} =
      case first_overrun(input) do
        nil ->
          {%{kind: :clear}, nil, []}

        {base_pos, run_len} ->
          {%{
             kind: :hazard,
             sub: %{tag: "StreamSafeOverrun", base_pos: base_pos, run_len: run_len},
             positions: [base_pos],
             decoded: []
           }, "StreamSafeOverrun", [base_pos]}
      end

    %{
      input: input,
      classify: classify,
      max_run_len: max_run_len(input),
      overrun_count: overrun_count(input),
      total_non_starters: total_non_starters(input),
      sub: sub,
      positions: positions
    }
  end

  # True iff `cp` is a non-starter — a codepoint with non-zero
  # Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0.
  defp non_starter?(cp), do: Ucd.ccc(cp) != 0

  # Inventory of `{start_index, length}` for every maximal non-starter run in
  # `input`. A run opens on the first non-starter, its start index is fixed to
  # that codepoint's absolute index, and it closes (emitting its `{start,
  # length}` pair) on the next starter or at end of input.
  defp non_starter_runs(input) do
    {runs_rev, cur_start, cur_len} =
      input
      |> Enum.with_index()
      |> Enum.reduce({[], nil, 0}, fn {cp, i}, {runs, cur_start, cur_len} ->
        if non_starter?(cp) do
          opened = if cur_start == nil, do: i, else: cur_start
          {runs, opened, cur_len + 1}
        else
          case cur_start do
            nil -> {runs, nil, 0}
            s -> {[{s, cur_len} | runs], nil, 0}
          end
        end
      end)

    closed_rev =
      case cur_start do
        nil -> runs_rev
        s -> [{s, cur_len} | runs_rev]
      end

    Enum.reverse(closed_rev)
  end

  # First non-starter run whose length exceeds `@stream_safe_limit`, as
  # `{start_index, length}`, or `nil`.
  defp first_overrun(input) do
    Enum.find(non_starter_runs(input), fn {_start, len} -> len > @stream_safe_limit end)
  end

  # Longest non-starter run length in `input`.
  defp max_run_len(input) do
    Enum.reduce(non_starter_runs(input), 0, fn {_start, len}, acc ->
      if len > acc, do: len, else: acc
    end)
  end

  # Number of distinct non-starter runs that exceed `@stream_safe_limit`.
  defp overrun_count(input) do
    Enum.reduce(non_starter_runs(input), 0, fn {_start, len}, acc ->
      if len > @stream_safe_limit, do: acc + 1, else: acc
    end)
  end

  # Total non-starter codepoints in `input` (sum of all run lengths).
  defp total_non_starters(input) do
    Enum.reduce(non_starter_runs(input), 0, fn {_start, len}, acc -> acc + len end)
  end
end
