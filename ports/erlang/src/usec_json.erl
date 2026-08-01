%%% Minimal self-contained JSON decoder/encoder for the Unicode Security
%%% Conformance Layer test harness.  No rebar3 / hex dependency.
%%%
%%% `decode/1` parses a JSON document into:
%%%   * object -> map with binary keys
%%%   * array  -> list
%%%   * string -> binary (UTF-8, with `\uXXXX` escapes decoded)
%%%   * number -> integer when it has no fraction/exponent, else float
%%%   * true/false/null -> the atoms `true` / `false` / `null`
%%%
%%% `encode/1` renders the same shape back to a compact JSON binary
%%% (no insignificant whitespace), mirroring Python's
%%% `json.dumps(..., separators=(",", ":"))`.  Object keys are emitted in
%%% the order supplied via `usec_policy:verdict_to_wire/1`, which builds an
%%% ordered proplist-backed map, so callers that need a fixed key order use
%%% `encode_pairs/1`.
-module(usec_json).

-export([decode/1, encode/1, encode_pairs/1]).

%% ─────────────────────────────────────────────────────────────────────
%% Decoder
%% ─────────────────────────────────────────────────────────────────────

-spec decode(binary()) -> term().
decode(Bin) when is_binary(Bin) ->
    {Value, Rest} = parse_value(skip_ws(Bin)),
    case skip_ws(Rest) of
        <<>> -> Value;
        Trailing -> error({json_trailing_data, Trailing})
    end.

skip_ws(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t; C =:= $\n; C =:= $\r ->
    skip_ws(Rest);
skip_ws(Bin) ->
    Bin.

parse_value(<<${, _/binary>> = Bin) -> parse_object(Bin);
parse_value(<<$[, _/binary>> = Bin) -> parse_array(Bin);
parse_value(<<$", _/binary>> = Bin) -> parse_string(Bin);
parse_value(<<"true", Rest/binary>>) -> {true, Rest};
parse_value(<<"false", Rest/binary>>) -> {false, Rest};
parse_value(<<"null", Rest/binary>>) -> {null, Rest};
parse_value(Bin) -> parse_number(Bin).

parse_object(<<${, Rest0/binary>>) ->
    case skip_ws(Rest0) of
        <<$}, Rest1/binary>> -> {#{}, Rest1};
        Body -> parse_members(Body, #{})
    end.

parse_members(Bin, Acc) ->
    {Key, Rest0} = parse_string(skip_ws(Bin)),
    case skip_ws(Rest0) of
        <<$:, Rest1/binary>> ->
            {Value, Rest2} = parse_value(skip_ws(Rest1)),
            Acc1 = maps:put(Key, Value, Acc),
            case skip_ws(Rest2) of
                <<$,, Rest3/binary>> -> parse_members(skip_ws(Rest3), Acc1);
                <<$}, Rest3/binary>> -> {Acc1, Rest3}
            end
    end.

parse_array(<<$[, Rest0/binary>>) ->
    case skip_ws(Rest0) of
        <<$], Rest1/binary>> -> {[], Rest1};
        Body -> parse_elements(Body, [])
    end.

parse_elements(Bin, Acc) ->
    {Value, Rest0} = parse_value(skip_ws(Bin)),
    Acc1 = [Value | Acc],
    case skip_ws(Rest0) of
        <<$,, Rest1/binary>> -> parse_elements(skip_ws(Rest1), Acc1);
        <<$], Rest1/binary>> -> {lists:reverse(Acc1), Rest1}
    end.

parse_string(<<$", Rest/binary>>) ->
    parse_string_chars(Rest, []).

parse_string_chars(<<$", Rest/binary>>, Acc) ->
    {unicode:characters_to_binary(lists:reverse(Acc)), Rest};
parse_string_chars(<<$\\, Esc, Rest/binary>>, Acc) ->
    case Esc of
        $" -> parse_string_chars(Rest, [$" | Acc]);
        $\\ -> parse_string_chars(Rest, [$\\ | Acc]);
        $/ -> parse_string_chars(Rest, [$/ | Acc]);
        $b -> parse_string_chars(Rest, [8 | Acc]);
        $f -> parse_string_chars(Rest, [12 | Acc]);
        $n -> parse_string_chars(Rest, [$\n | Acc]);
        $r -> parse_string_chars(Rest, [$\r | Acc]);
        $t -> parse_string_chars(Rest, [$\t | Acc]);
        $u -> parse_unicode_escape(Rest, Acc)
    end;
parse_string_chars(<<C/utf8, Rest/binary>>, Acc) ->
    parse_string_chars(Rest, [C | Acc]).

parse_unicode_escape(<<H1, H2, H3, H4, Rest/binary>>, Acc) ->
    High = hex4(H1, H2, H3, H4),
    case High of
        _ when High >= 16#D800, High =< 16#DBFF ->
            <<$\\, $u, L1, L2, L3, L4, Rest1/binary>> = Rest,
            Low = hex4(L1, L2, L3, L4),
            Cp = 16#10000 + ((High - 16#D800) bsl 10) + (Low - 16#DC00),
            parse_string_chars(Rest1, [Cp | Acc]);
        _ ->
            parse_string_chars(Rest, [High | Acc])
    end.

hex4(A, B, C, D) ->
    (hexval(A) bsl 12) bor (hexval(B) bsl 8) bor (hexval(C) bsl 4) bor hexval(D).

hexval(C) when C >= $0, C =< $9 -> C - $0;
hexval(C) when C >= $a, C =< $f -> C - $a + 10;
hexval(C) when C >= $A, C =< $F -> C - $A + 10.

parse_number(Bin) ->
    {NumStr, Rest} = take_number(Bin, []),
    Str = lists:reverse(NumStr),
    Value =
        case has_float_marker(Str) of
            true -> list_to_float(Str);
            false -> list_to_integer(Str)
        end,
    {Value, Rest}.

take_number(<<C, Rest/binary>>, Acc)
  when (C >= $0 andalso C =< $9);
       C =:= $-; C =:= $+; C =:= $.; C =:= $e; C =:= $E ->
    take_number(Rest, [C | Acc]);
take_number(Bin, Acc) ->
    {Acc, Bin}.

has_float_marker([]) -> false;
has_float_marker([$. | _]) -> true;
has_float_marker([$e | _]) -> true;
has_float_marker([$E | _]) -> true;
has_float_marker([_ | T]) -> has_float_marker(T).

%% ─────────────────────────────────────────────────────────────────────
%% Encoder
%% ─────────────────────────────────────────────────────────────────────

%% @doc Encode a decoded-shape term to compact JSON.
-spec encode(term()) -> binary().
encode(Term) ->
    iolist_to_binary(enc(Term)).

%% @doc Encode from an ordered list of `{Key, Value}` pairs, preserving
%% key order (used for byte-stable verdict serialisation).
-spec encode_pairs([{binary(), term()}]) -> binary().
encode_pairs(Pairs) ->
    iolist_to_binary(enc_object(Pairs)).

enc(null) -> <<"null">>;
enc(true) -> <<"true">>;
enc(false) -> <<"false">>;
enc(I) when is_integer(I) -> integer_to_binary(I);
enc(F) when is_float(F) -> float_to_binary(F, [short]);
enc(B) when is_binary(B) -> enc_string(B);
enc(L) when is_list(L) -> enc_array(L);
enc(M) when is_map(M) -> enc_object(maps:to_list(M)).

enc_array(L) ->
    [$[, lists:join($,, [enc(E) || E <- L]), $]].

enc_object(Pairs) ->
    [${,
     lists:join($,, [[enc_string(K), $:, enc(V)] || {K, V} <- Pairs]),
     $}].

enc_string(B) ->
    [$", escape(B), $"].

escape(B) ->
    escape(B, []).

escape(<<>>, Acc) ->
    lists:reverse(Acc);
escape(<<C/utf8, Rest/binary>>, Acc) ->
    Chunk =
        case C of
            $" -> "\\\"";
            $\\ -> "\\\\";
            $\n -> "\\n";
            $\r -> "\\r";
            $\t -> "\\t";
            8 -> "\\b";
            12 -> "\\f";
            _ when C < 16#20 ->
                io_lib:format("\\u~4.16.0b", [C]);
            _ ->
                <<C/utf8>>
        end,
    escape(Rest, [Chunk | Acc]).
