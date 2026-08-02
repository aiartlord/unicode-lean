%% emoji-zwj-integrity — detection of malformed / unsanctioned emoji ZWJ-sequence
%% shapes per UTS #51 (the identity-layer detector I3). Answers the question:
%% is this emoji-shaped codepoint sequence a sanctioned RGI ZWJ sequence, or a
%% renderer-dependent shape whose divergence is an attack surface?
%%
%% Direct port of the verified Rust reference implementation
%% (itself a port of `Unicode/Security/Identity/EmojiZwjIntegrity.lean`).
%%
%% Threat model. An adversary crafts an emoji-shaped codepoint sequence
%% containing one or more U+200D ZERO WIDTH JOINERs but violating the sanctioned
%% RGI ZWJ-sequence shape — by exceeding the RGI length cap, by joining a
%% non-emoji codepoint, by emitting adjacent ZWJ pairs, or by overflowing the
%% skin-tone count. Any non-RGI ZWJ-containing sequence is renderer-dependent,
%% and that renderer divergence is the attack surface.
%%
%% Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
%% `emoji-zwj-sequences.txt`, bundled byte-identical in the port's own
%% priv/data/emoji-zwj-sequences.txt and parsed here via `usec_data` (never a
%% host emoji library, never String normalization). The registered set gives
%% both the exact-match membership test (`is_registered_zwj_sequence`) and the
%% ZWJ *alphabet* — every distinct codepoint occurring at any position of any
%% registered sequence, excluding the joiner — which is the canonical
%% "what may flank a ZWJ?" predicate.
%%
%% Algorithm (one pass over `Input').
%%   Phase 1 — collect ZWJ positions and the skin-tone count.
%%   Phase 2 — short-circuit `clear' if there are no ZWJs and the skin-tone
%%             count is at most 1.
%%   Phase 3 — a registered RGI sequence is always `clear'.
%%   Phase 4 — check sub-threats by priority:
%%               1. DoubleZWJ            ZWJ-ZWJ adjacency
%%               2. NonEmojiInjection    ZWJ adjacent to a non-emoji codepoint
%%               3. OverLength           sequence longer than the RGI cap
%%               4. SkinToneOverflow     skin-tone count >= 5
%%               5. UnregisteredSequence catch-all when ZWJs are present but the
%%                                       sequence is not registered.

-module(usec_emoji_zwj_integrity).

-export([sub_threat_tag/1,
         classify_tag/1, classify_positions/1, is_clear/1,
         is_registered_zwj_sequence/1, is_emoji_target/1,
         is_zwj/1, is_emoji_modifier/1,
         detect/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Constants
%% ─────────────────────────────────────────────────────────────────────

%% Conservative cap on the length of a sanctioned RGI ZWJ sequence
%% (`maxRgiLength' in the Lean spec). The longest current entry (a four-person
%% family with skin tones) reaches ~13-14 codepoints; 16 is a safe upper bound.
-define(MAX_RGI_LENGTH, 16).

%% The ZERO WIDTH JOINER codepoint.
-define(ZWJ, 16#200D).

%% ─────────────────────────────────────────────────────────────────────
%% §2 Types
%% ─────────────────────────────────────────────────────────────────────
%%
%% SubThreat — one tuple per rust variant, in priority order:
%%   {double_zwj, Positions}                    ZWJ-ZWJ adjacency; positions are
%%                                              the first ZWJ of each pair.
%%   {non_emoji_injection, ZwjPos, NonEmojiCp}  offending ZWJ position and the
%%                                              non-emoji flank (0 for an edge ZWJ).
%%   {over_length, Length, MaxLength}           observed length and the RGI cap.
%%   {skin_tone_overflow, Count}                observed skin-tone modifier count.
%%   {unregistered_sequence, ChainLen}          length of the unregistered chain.
%%
%% Classification — `clear' | {hazard, SubThreat, Positions, Decoded}. `Decoded'
%% is always the empty list here; it is kept for shape parity with the Lean
%% `Classification.hazard' decoded-byte projection.
%%
%% Verdict — a map #{input, classify, zwj_positions, chain_length,
%% is_registered_rgi, skin_tone_count}.

%% @doc Fixture-row tag string for a sub-threat tuple (matches `SubThreat.tag').
sub_threat_tag({double_zwj, _Positions}) -> <<"DoubleZWJ">>;
sub_threat_tag({non_emoji_injection, _ZwjPos, _NonEmojiCp}) -> <<"NonEmojiInjection">>;
sub_threat_tag({over_length, _Length, _MaxLength}) -> <<"OverLength">>;
sub_threat_tag({skin_tone_overflow, _Count}) -> <<"SkinToneOverflow">>;
sub_threat_tag({unregistered_sequence, _ChainLen}) -> <<"UnregisteredSequence">>.

%% @doc Human-facing tag for a classification, or `none' when clear.
classify_tag(clear) -> none;
classify_tag({hazard, Sub, _Positions, _Decoded}) -> sub_threat_tag(Sub).

%% @doc Implicated positions (empty when clear).
classify_positions(clear) -> [];
classify_positions({hazard, _Sub, Positions, _Decoded}) -> Positions.

%% @doc True iff the classification is `clear'.
is_clear(clear) -> true;
is_clear({hazard, _Sub, _Positions, _Decoded}) -> false.

%% ─────────────────────────────────────────────────────────────────────
%% §3 RGI ZWJ-sequence data (bundled priv/data/emoji-zwj-sequences.txt)
%% ─────────────────────────────────────────────────────────────────────

%% @doc The memoised list of registered RGI ZWJ sequences (each a codepoint list).
zwj_sequences() ->
    usec_data:cached(emoji_zwj_sequences, fun parse_zwj_sequences/0).

%% @doc Parse the registered RGI ZWJ sequences from `emoji-zwj-sequences.txt'.
%% Each non-comment row is `<cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ; <desc> # <cmt>';
%% the codepoint list is the field before the first `;'.
parse_zwj_sequences() ->
    Ls = binary:split(usec_data:read_file("emoji-zwj-sequences.txt"), <<"\n">>, [global]),
    lists:reverse(lists:foldl(fun zwj_line/2, [], Ls)).

zwj_line(Line, Acc) ->
    Body = case binary:split(Line, <<"#">>) of
               [Before | _Comment] -> Before
           end,
    case string:trim(Body) of
        <<>> -> Acc;
        Stripped ->
            SeqField = case binary:split(Stripped, <<";">>) of
                           [Field | _Rest] -> Field
                       end,
            case parse_hex_tokens(SeqField) of
                [] -> Acc;
                Seq -> [Seq | Acc]
            end
    end.

%% @doc Split a field on ASCII space / tab / carriage-return, drop empty tokens,
%% and parse each remaining token as a hexadecimal codepoint.
parse_hex_tokens(Field) ->
    Toks = [T || T <- binary:split(Field, [<<" ">>, <<"\t">>, <<"\r">>], [global]), T =/= <<>>],
    [binary_to_integer(T, 16) || T <- Toks].

%% @doc The memoised ZWJ alphabet: every distinct codepoint occurring at any
%% position of any registered RGI ZWJ sequence, excluding the joiner U+200D,
%% held as a map for O(1) membership.
zwj_alphabet() ->
    usec_data:cached(emoji_zwj_alphabet, fun build_zwj_alphabet/0).

build_zwj_alphabet() ->
    lists:foldl(fun(Seq, Outer) ->
                        lists:foldl(fun(Cp, Inner) ->
                                            case Cp =:= ?ZWJ of
                                                true -> Inner;
                                                false -> maps:put(Cp, true, Inner)
                                            end
                                    end, Outer, Seq)
                end, #{}, zwj_sequences()).

%% @doc True iff `Cps' is exactly a registered RGI ZWJ sequence.
is_registered_zwj_sequence(Cps) ->
    lists:member(Cps, zwj_sequences()).

%% @doc True iff `Cp' appears at some position of a registered RGI ZWJ sequence
%% (the canonical "what may flank a ZWJ?" predicate).
is_emoji_target(Cp) ->
    maps:is_key(Cp, zwj_alphabet()).

%% ─────────────────────────────────────────────────────────────────────
%% §4 Core predicates
%% ─────────────────────────────────────────────────────────────────────

%% @doc True iff `Cp' is the ZWJ codepoint.
is_zwj(Cp) -> Cp =:= ?ZWJ.

%% @doc True iff `Cp' is an emoji skin-tone modifier (U+1F3FB..U+1F3FF).
is_emoji_modifier(Cp) -> Cp >= 16#1F3FB andalso Cp =< 16#1F3FF.

%% @doc 0-based positions of every ZWJ in `Input'.
zwj_positions([]) -> [];
zwj_positions(Input) ->
    [I || {Cp, I} <- lists:zip(Input, lists:seq(0, length(Input) - 1)), is_zwj(Cp)].

%% @doc Count of skin-tone modifier codepoints.
skin_tone_count(Input) ->
    length([Cp || Cp <- Input, is_emoji_modifier(Cp)]).

%% @doc 0-based positions of the first ZWJ in each ZWJ-ZWJ adjacent pair.
double_zwj_positions(Input) -> double_zwj_positions(Input, 0, []).

double_zwj_positions([A, B | Rest], I, Acc) ->
    case is_zwj(A) andalso is_zwj(B) of
        true -> double_zwj_positions([B | Rest], I + 1, [I | Acc]);
        false -> double_zwj_positions([B | Rest], I + 1, Acc)
    end;
double_zwj_positions([_Last], _I, Acc) -> lists:reverse(Acc);
double_zwj_positions([], _I, Acc) -> lists:reverse(Acc).

%% @doc The first ZWJ position where either neighbour is a non-emoji codepoint,
%% as `{ZwjPos, OffendingCp}', or `none'. A ZWJ at an input edge (no preceding
%% or no following codepoint) is itself an injection-class hazard, reported with
%% offending codepoint 0. `Prev' is `none' before the first element, else
%% `{ok, Cp}' for the immediately preceding codepoint.
first_non_emoji_injection(Input) ->
    first_non_emoji_injection(Input, none, 0).

first_non_emoji_injection([], _Prev, _I) -> none;
first_non_emoji_injection([Cp | Rest], Prev, I) ->
    case is_zwj(Cp) of
        false ->
            first_non_emoji_injection(Rest, {ok, Cp}, I + 1);
        true ->
            Next = case Rest of
                       [] -> none;
                       [NextCp | _Tail] -> {ok, NextCp}
                   end,
            case {Prev, Next} of
                {{ok, PrevCp}, {ok, NextCp2}} ->
                    case not is_emoji_target(PrevCp) of
                        true -> {I, PrevCp};
                        false ->
                            case not is_emoji_target(NextCp2) of
                                true -> {I, NextCp2};
                                false -> first_non_emoji_injection(Rest, {ok, Cp}, I + 1)
                            end
                    end;
                {none, _AnyNext} -> {I, 0};
                {{ok, _PrevCp}, none} -> {I, 0}
            end
    end.

%% ─────────────────────────────────────────────────────────────────────
%% §5 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The EmojiZwjIntegrity detection function.
detect(Input) ->
    Zwjs = zwj_positions(Input),
    StCount = skin_tone_count(Input),
    IsRgi = is_registered_zwj_sequence(Input),
    ChainLen = case Zwjs of
                   [] -> 0;
                   _Nonempty -> length(Input)
               end,
    case Zwjs =:= [] andalso StCount =< 1 of
        true ->
            #{input => Input,
              classify => clear,
              zwj_positions => [],
              chain_length => 0,
              is_registered_rgi => IsRgi,
              skin_tone_count => StCount};
        false ->
            Classification = classify(Input, Zwjs, StCount, IsRgi),
            #{input => Input,
              classify => Classification,
              zwj_positions => Zwjs,
              chain_length => ChainLen,
              is_registered_rgi => IsRgi,
              skin_tone_count => StCount}
    end.

%% @doc Phase 3 + Phase 4: a registered RGI sequence is always clear; otherwise
%% run the priority ladder DoubleZWJ -> NonEmojiInjection -> OverLength ->
%% SkinToneOverflow -> UnregisteredSequence.
classify(_Input, _Zwjs, _StCount, true) ->
    clear;
classify(Input, Zwjs, StCount, false) ->
    case double_zwj_positions(Input) of
        [] -> classify_after_double(Input, Zwjs, StCount);
        [_First | _More] = Dzwj -> {hazard, {double_zwj, Dzwj}, Dzwj, []}
    end.

classify_after_double(Input, Zwjs, StCount) ->
    case first_non_emoji_injection(Input) of
        {ZwjPos, OffendCp} ->
            {hazard, {non_emoji_injection, ZwjPos, OffendCp}, [ZwjPos], []};
        none ->
            classify_length(Input, Zwjs, StCount)
    end.

classify_length(Input, Zwjs, StCount) ->
    Len = length(Input),
    if
        Len > ?MAX_RGI_LENGTH ->
            {hazard, {over_length, Len, ?MAX_RGI_LENGTH}, [], []};
        StCount >= 5 ->
            {hazard, {skin_tone_overflow, StCount}, [], []};
        Zwjs =/= [] ->
            {hazard, {unregistered_sequence, Len}, Zwjs, []};
        true ->
            clear
    end.
