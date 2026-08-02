%% stream-safe-violation — detection of inputs whose consecutive non-starter
%% run exceeds the UAX #15 §13 stream-safe limit of 30. Such an input (the
%% canonical "Zalgo" shape, a single base codepoint followed by a long
%% combining-mark run) forces unbounded combining-mark buffers in receiver-side
%% streaming normalization (`to_nfc' / `to_nfd' / `to_nfkc' / `to_nfkd') and is
%% a known DoS vector.
%%
%% Direct port of `ports/rust/src/security/form/stream_safe_violation.rs'. UAX
%% #15 §13 defines Stream-Safe Text Format as the remediation: insert U+034F
%% COMBINING GRAPHEME JOINER (a starter) after every 30 consecutive
%% non-starters, which bounds the normalization buffer. `stream_safe_violation'
%% is the security verdict over the same property — distinct from renderer
%% divergence's cosmetic 4-mark combining-stack threshold, this is the
%% spec-mandated DoS-prevention bound.
%%
%% A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
%% (UAX #15 D49). This module reads CCC from the port's own bundled UCD table
%% via `usec_ucd:ccc', never a host normalizer.
%%
%% Sub-threat: `{stream_safe_overrun, BasePos, RunLen}' — the first non-starter
%% run whose length exceeds the stream-safe limit. `BasePos' is the index of
%% that run's first non-starter codepoint; `RunLen' is the run's length.

-module(usec_stream_safe_violation).

-export([stream_safe_limit/0, detect/1,
         sub_threat_tag/1, classify_tag/1, classify_positions/1, is_clear/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Run inventory
%% ─────────────────────────────────────────────────────────────────────

%% @doc UAX #15 §13 Stream-Safe limit: the maximum number of consecutive
%% non-starters permitted before a COMBINING GRAPHEME JOINER must be inserted.
-define(STREAM_SAFE_LIMIT, 30).

%% @doc The Stream-Safe limit as a value.
stream_safe_limit() -> ?STREAM_SAFE_LIMIT.

%% @doc True iff `Cp' is a non-starter — a codepoint with non-zero
%% Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0.
is_non_starter(Cp) ->
    usec_ucd:ccc(Cp) =/= 0.

%% @doc Inventory of `{StartIndex, Length}' for every maximal non-starter run in
%% `Input'. Mirrors `collectRunsGo': a run opens on the first non-starter, its
%% start index is fixed to that codepoint's absolute index, and it closes
%% (emitting its `{Start, Length}' pair) on the next starter or at end of input.
non_starter_runs(Input) -> non_starter_runs(Input, 0, none, 0, []).

non_starter_runs([], _I, none, _CurLen, Acc) ->
    lists:reverse(Acc);
non_starter_runs([], _I, Start, CurLen, Acc) ->
    lists:reverse([{Start, CurLen} | Acc]);
non_starter_runs([Cp | Rest], I, CurStart, CurLen, Acc) ->
    case is_non_starter(Cp) of
        true ->
            NewStart = case CurStart of
                           none -> I;
                           Existing -> Existing
                       end,
            non_starter_runs(Rest, I + 1, NewStart, CurLen + 1, Acc);
        false ->
            NewAcc = case CurStart of
                         none -> Acc;
                         Start -> [{Start, CurLen} | Acc]
                     end,
            non_starter_runs(Rest, I + 1, none, 0, NewAcc)
    end.

%% @doc First non-starter run whose length exceeds the stream-safe limit, as
%% `{StartIndex, Length}', or `none'.
first_overrun(Input) ->
    Overrunning = lists:dropwhile(fun({_Start, Len}) -> Len =< ?STREAM_SAFE_LIMIT end,
                                  non_starter_runs(Input)),
    case Overrunning of
        [] -> none;
        [{Start, Len} | _Rest] -> {Start, Len}
    end.

%% @doc Longest non-starter run length in `Input'.
max_run_len(Input) ->
    lists:foldl(fun({_Start, Len}, Acc) ->
                        case Len > Acc of
                            true -> Len;
                            false -> Acc
                        end
                end, 0, non_starter_runs(Input)).

%% @doc Number of distinct non-starter runs that exceed the stream-safe limit.
overrun_count(Input) ->
    lists:foldl(fun({_Start, Len}, Acc) ->
                        case Len > ?STREAM_SAFE_LIMIT of
                            true -> Acc + 1;
                            false -> Acc
                        end
                end, 0, non_starter_runs(Input)).

%% @doc Total non-starter codepoints in `Input' (sum of all run lengths).
total_non_starters(Input) ->
    lists:foldl(fun({_Start, Len}, Acc) -> Acc + Len end, 0, non_starter_runs(Input)).

%% ─────────────────────────────────────────────────────────────────────
%% §2 Classification accessors
%% ─────────────────────────────────────────────────────────────────────

%% @doc Human-facing classification tag for a sub-threat tuple.
sub_threat_tag({stream_safe_overrun, _BasePos, _RunLen}) -> <<"StreamSafeOverrun">>.

%% @doc Human-facing tag for a classification, or `none' when clear.
classify_tag(clear) -> none;
classify_tag({hazard, Sub, _Positions}) -> sub_threat_tag(Sub).

%% @doc Implicated positions (empty when clear).
classify_positions(clear) -> [];
classify_positions({hazard, _Sub, Positions}) -> Positions.

%% @doc True iff the classification is clear.
is_clear(clear) -> true;
is_clear({hazard, _Sub, _Positions}) -> false.

%% ─────────────────────────────────────────────────────────────────────
%% §3 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The stream-safe detection function. Fires `stream_safe_overrun' on the
%% first non-starter run whose length exceeds the stream-safe limit. The
%% run-inventory summaries (`max_run_len', `overrun_count',
%% `total_non_starters') are exposed so downstream callers can size the buffer
%% pressure a streaming normalizer would see.
detect(Input) ->
    Classification = case first_overrun(Input) of
                         none -> clear;
                         {BasePos, RunLen} ->
                             {hazard, {stream_safe_overrun, BasePos, RunLen}, [BasePos]}
                     end,
    #{input => Input,
      classify => Classification,
      max_run_len => max_run_len(Input),
      overrun_count => overrun_count(Input),
      total_non_starters => total_non_starters(Input)}.
