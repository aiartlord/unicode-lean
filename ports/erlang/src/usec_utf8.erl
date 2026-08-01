%%% Strict UTF-8 codec — validator and decoder, mirroring
%%% `unicode_python.utf8` / `Unicode.Utf8`.
%%%
%%% The accepted byte set is exactly the strict RFC 3629 acceptance
%%% language: it rejects overlong encodings, surrogate codepoints
%%% (U+D800..U+DFFF), codepoints beyond U+10FFFF, truncated multi-byte
%%% sequences, invalid start bytes, and invalid continuation bytes.  The
%%% codec does not delegate to any built-in decode; the accepted byte set
%%% is closed-form per the spec.
%%%
%%% Offset convention for `first_invalid_utf8_offset/1`: the returned
%%% offset is the index of the byte on which the state machine transitions
%%% to reject.  For `overlong_encoding` (decided on emission of a
%%% multi-byte sequence) the offset is the start byte of the sequence; for
%%% `truncated_sequence` the offset equals the byte length of the input.
-module(usec_utf8).

-export([reject_tag/1, first_invalid_utf8_offset/1, is_valid_utf8/1,
         decode_to_codepoints/1]).

-export_type([reject_kind/0]).

-type reject_kind() ::
        overlong_encoding
      | surrogate_codepoint
      | codepoint_beyond_max
      | truncated_sequence
      | invalid_start_byte
      | invalid_continuation_byte.

%% @doc Stable sub-threat tag string for a strict-UTF-8 reject kind,
%% matching the `Utf8RejectKind` enum values.
-spec reject_tag(reject_kind()) -> binary().
reject_tag(overlong_encoding) -> <<"OverlongEncoding">>;
reject_tag(surrogate_codepoint) -> <<"SurrogateCodepoint">>;
reject_tag(codepoint_beyond_max) -> <<"CodepointBeyondMax">>;
reject_tag(truncated_sequence) -> <<"TruncatedSequence">>;
reject_tag(invalid_start_byte) -> <<"InvalidStartByte">>;
reject_tag(invalid_continuation_byte) -> <<"InvalidContinuationByte">>.

%% @doc First reject offset, or `none` when the input is valid UTF-8.
-spec first_invalid_utf8_offset(binary() | [byte()]) ->
          none | {non_neg_integer(), reject_kind()}.
first_invalid_utf8_offset(Data) when is_binary(Data) ->
    first_invalid_utf8_offset(binary_to_list(Data));
first_invalid_utf8_offset(Bytes) when is_list(Bytes) ->
    walk(Bytes, start, 0, 0).

%% State: `start` | {cont, Remaining, Accum, MinCp}.
%% `I` is the index of the next byte; `SeqStart` the index of the byte that
%% opened the current sequence (only meaningful in `cont` states).
walk([], start, _I, _SeqStart) ->
    none;
walk([], {cont, _R, _A, _M}, I, _SeqStart) ->
    {I, truncated_sequence};
walk([B | Rest], start, I, _SeqStart) ->
    case step(start, B) of
        {emit, _Cp, NextState} -> walk(Rest, NextState, I + 1, I + 1);
        {continue, NextState} -> walk(Rest, NextState, I + 1, I);
        {reject, Kind} -> {I, Kind}
    end;
walk([B | Rest], {cont, _R, _A, _M} = State, I, SeqStart) ->
    case step(State, B) of
        {emit, _Cp, NextState} -> walk(Rest, NextState, I + 1, I + 1);
        {continue, NextState} -> walk(Rest, NextState, I + 1, SeqStart);
        {reject, overlong_encoding} -> {SeqStart, overlong_encoding};
        {reject, Kind} -> {I, Kind}
    end.

%% Single-byte decode step per RFC 3629.
step(start, N0) ->
    N = N0 band 16#FF,
    if
        N < 16#80 -> {emit, N, start};
        N < 16#C2 -> {reject, invalid_start_byte};
        N < 16#E0 -> {continue, {cont, 1, N band 16#1F, 16#80}};
        N < 16#F0 -> {continue, {cont, 2, N band 16#0F, 16#800}};
        N < 16#F5 -> {continue, {cont, 3, N band 16#07, 16#10000}};
        true -> {reject, invalid_start_byte}
    end;
step({cont, Remaining, Accum, MinCp}, N0) ->
    N = N0 band 16#FF,
    if
        N < 16#80 orelse N >= 16#C0 ->
            {reject, invalid_continuation_byte};
        true ->
            Nxt = (Accum bsl 6) bor (N band 16#3F),
            case Remaining of
                1 ->
                    if
                        Nxt < MinCp -> {reject, overlong_encoding};
                        Nxt >= 16#D800 andalso Nxt =< 16#DFFF ->
                            {reject, surrogate_codepoint};
                        Nxt > 16#10FFFF -> {reject, codepoint_beyond_max};
                        true -> {emit, Nxt, start}
                    end;
                _ ->
                    {continue, {cont, Remaining - 1, Nxt, MinCp}}
            end
    end.

%% @doc Whole-input validity predicate.
-spec is_valid_utf8(binary() | [byte()]) -> boolean().
is_valid_utf8(Data) ->
    first_invalid_utf8_offset(Data) =:= none.

%% @doc Decode a UTF-8 byte string to a codepoint list.  On malformed
%% input the walker yields the longest valid prefix and stops, matching
%% the reference `decode_to_codepoints`.
-spec decode_to_codepoints(binary() | [byte()]) -> [non_neg_integer()].
decode_to_codepoints(Data) when is_binary(Data) ->
    decode_to_codepoints(binary_to_list(Data));
decode_to_codepoints(Bytes) when is_list(Bytes) ->
    decode(Bytes, start, []).

decode([], _State, Acc) ->
    lists:reverse(Acc);
decode([B | Rest], State, Acc) ->
    case step(State, B) of
        {emit, Cp, NextState} -> decode(Rest, NextState, [Cp | Acc]);
        {continue, NextState} -> decode(Rest, NextState, Acc);
        {reject, _Kind} -> lists:reverse(Acc)
    end.
