%% ai-watermark-detectability — character-level detector for inputs carrying
%% codepoint patterns consistent with a known AI watermark scheme. Answers the
%% question: does this input contain markers attributable to a watermarking
%% protocol?
%%
%% Direct port of `ports/rust/src/security/crypto/ai_watermark_detectability.rs`
%% (itself a port of `Unicode/Security/Crypto/AiWatermarkDetectability.lean`).
%%
%% Threat model — provenance-attribution attacker. An input either (a) carries
%% an AI provider's watermark codepoints (a legitimate provenance marker) or
%% (b) carries injected markers that impersonate a provider's scheme to
%% discredit the content as AI-generated. Character-level detection alone cannot
%% distinguish (a) from (b); the detector reports the matched scheme and leaves
%% provider-specific authentication to downstream code.
%%
%% Probe inventory (priority order, first match wins):
%%
%%   1. adversarial              — NNBSP count >= 3 at arithmetic-progression positions.
%%   2. gpt5ZwspModulo           — ZWSP count >= 3 at arithmetic-progression positions.
%%   3. unknown                  — invisible markers from >= 2 distinct categories.
%%   4. nnbspBoundary            — single-category NNBSP.
%%   5. variationSelectorCarrier — VS NOT adjacent to an emoji codepoint.
%%   6. zwjNonEmoji              — ZWJ NOT adjacent to an emoji codepoint.
%%   7. smartQuoteAlternation    — paired curly quotes, no ASCII straight quotes.
%%   8. emDashPattern            — em-dashes, no ASCII hyphen-minus.
%%   9. statisticalTokenChoice   — input contains an AI-favored lexical pattern.
%%  10. defaultIgnorableCarrier  — single-category residual Default_Ignorable.
%%
%% The Emoji property table is bundled in the port's own priv/data/emoji-data.txt
%% (UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
%% adjacency probe parses the `Emoji` rows from it via `usec_data`, never a host
%% emoji library. Default_Ignorable reuses the port's own `usec_ucd` table.

-module(usec_ai_watermark_detectability).

-export([cue_class/1, sub_threat_tag/1,
         classify_tag/1, classify_positions/1, is_clear/1,
         detect/1, detect_with_context/2]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Types
%% ─────────────────────────────────────────────────────────────────────
%%
%% CueClass — the conceptual watermark cue class a sub-threat probes for:
%%   `green_list_bias' | `pseudorandom_seq' | `semantic_drift'.
%%
%% SubThreat — one tuple per rust variant, in declaration order:
%%   {nnbsp_boundary, MarkerCount}
%%   {variation_selector_carrier, MarkerCount}
%%   {zwj_non_emoji, MarkerCount}
%%   {default_ignorable_carrier, MarkerCount}
%%   {gpt5_zwsp_modulo, FirstPos}
%%   {em_dash_pattern, FirstPos}
%%   {smart_quote_alternation, FirstPos}
%%   {statistical_token_choice, FirstPos}
%%   {adversarial, ImpersonatedScheme, FirstPos}
%%   {unknown, AnomalyMarker}
%%
%% Classification — `clear' | {hazard, SubThreat, Positions}.
%%
%% Verdict — a map #{input, classify, marker_count}.
%%
%% Context — a map with optional keys `zwsp_modulo_tolerance' and
%% `adversarial_tolerance'; each absent key defaults to 0 (exact arithmetic).

%% @doc Human-facing classification tag for a sub-threat tuple.
sub_threat_tag({nnbsp_boundary, _MarkerCount}) -> <<"NnbspBoundary">>;
sub_threat_tag({variation_selector_carrier, _MarkerCount}) -> <<"VariationSelectorCarrier">>;
sub_threat_tag({zwj_non_emoji, _MarkerCount}) -> <<"ZwjNonEmoji">>;
sub_threat_tag({default_ignorable_carrier, _MarkerCount}) -> <<"DefaultIgnorableCarrier">>;
sub_threat_tag({gpt5_zwsp_modulo, _FirstPos}) -> <<"Gpt5ZwspModulo">>;
sub_threat_tag({em_dash_pattern, _FirstPos}) -> <<"EmDashPattern">>;
sub_threat_tag({smart_quote_alternation, _FirstPos}) -> <<"SmartQuoteAlternation">>;
sub_threat_tag({statistical_token_choice, _FirstPos}) -> <<"StatisticalTokenChoice">>;
sub_threat_tag({adversarial, _ImpersonatedScheme, _FirstPos}) -> <<"Adversarial">>;
sub_threat_tag({unknown, _AnomalyMarker}) -> <<"Unknown">>.

%% @doc Map a sub-threat to the conceptual watermark cue class it probes for.
%% Marker-encoded sub-threats route to `pseudorandom_seq'; vocabulary-bias to
%% `green_list_bias'; stylistic-distribution to `semantic_drift'; `unknown'
%% (multi-category mixing) implicates no single scheme and returns `none'.
cue_class({nnbsp_boundary, _MarkerCount}) -> pseudorandom_seq;
cue_class({variation_selector_carrier, _MarkerCount}) -> pseudorandom_seq;
cue_class({zwj_non_emoji, _MarkerCount}) -> pseudorandom_seq;
cue_class({default_ignorable_carrier, _MarkerCount}) -> pseudorandom_seq;
cue_class({gpt5_zwsp_modulo, _FirstPos}) -> pseudorandom_seq;
cue_class({em_dash_pattern, _FirstPos}) -> semantic_drift;
cue_class({smart_quote_alternation, _FirstPos}) -> semantic_drift;
cue_class({statistical_token_choice, _FirstPos}) -> green_list_bias;
cue_class({adversarial, _ImpersonatedScheme, _FirstPos}) -> pseudorandom_seq;
cue_class({unknown, _AnomalyMarker}) -> none.

%% @doc Human-facing tag for a classification, or `none' when clear.
classify_tag(clear) -> none;
classify_tag({hazard, Sub, _Positions}) -> sub_threat_tag(Sub).

%% @doc Implicated positions (empty when clear).
classify_positions(clear) -> [];
classify_positions({hazard, _Sub, Positions}) -> Positions.

%% @doc True iff no watermark marker was detected.
is_clear(clear) -> true;
is_clear({hazard, _Sub, _Positions}) -> false.

%% ─────────────────────────────────────────────────────────────────────
%% §2 Emoji property table (bundled priv/data/emoji-data.txt, Emoji rows)
%% ─────────────────────────────────────────────────────────────────────

%% @doc The memoised list of closed `Emoji=Yes' intervals from emoji-data.txt.
emoji_ranges() ->
    usec_data:cached(ai_watermark_emoji, fun parse_emoji_ranges/0).

%% @doc Parse the `Emoji' (`Emoji=Yes') closed intervals from emoji-data.txt.
%% Each non-comment row is `<range> ; <property> # <comment>'; keep only rows
%% whose property is exactly `Emoji'.
parse_emoji_ranges() ->
    Ls = binary:split(usec_data:read_file("emoji-data.txt"), <<"\n">>, [global]),
    lists:foldl(fun emoji_line/2, [], Ls).

emoji_line(Line, Acc) ->
    Body = case binary:split(Line, <<"#">>) of
               [Before | _Comment] -> Before
           end,
    case string:trim(Body) of
        <<>> -> Acc;
        Stripped ->
            case binary:split(Stripped, <<";">>) of
                [RangeField, PropField] ->
                    case string:trim(PropField) =:= <<"Emoji">> of
                        true -> [parse_emoji_range(RangeField) | Acc];
                        false -> Acc
                    end;
                _Malformed -> Acc
            end
    end.

parse_emoji_range(Field) ->
    Trim = string:trim(Field),
    case binary:split(Trim, <<"..">>) of
        [Single] ->
            Cp = binary_to_integer(Single, 16),
            {Cp, Cp};
        [Lo, Hi] ->
            {binary_to_integer(string:trim(Lo), 16), binary_to_integer(string:trim(Hi), 16)}
    end.

%% @doc True iff `Cp' has the `Emoji = Yes' property per emoji-data.txt.
is_emoji(Cp) ->
    lists:any(fun({Lo, Hi}) -> Lo =< Cp andalso Cp =< Hi end, emoji_ranges()).

%% ─────────────────────────────────────────────────────────────────────
%% §3 Codepoint probes
%% ─────────────────────────────────────────────────────────────────────

%% @doc True iff `Cp' is U+202F NARROW NO-BREAK SPACE.
is_nnbsp(Cp) -> Cp =:= 16#202F.

%% @doc True iff `Cp' is U+200D ZERO WIDTH JOINER.
is_zwj(Cp) -> Cp =:= 16#200D.

%% @doc True iff `Cp' is a Variation Selector — the basic block U+FE00..U+FE0F
%% (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
is_variation_selector(Cp) ->
    (Cp >= 16#FE00 andalso Cp =< 16#FE0F)
        orelse (Cp >= 16#E0100 andalso Cp =< 16#E01EF).

%% @doc True iff `Cp' is Default_Ignorable_Code_Point per DerivedCoreProperties.
%% Reuses the port's own UCD table, never a host normalizer.
is_default_ignorable(Cp) ->
    usec_ucd:is_default_ignorable(Cp).

%% @doc True iff `Cp' is U+200B ZERO WIDTH SPACE.
is_zwsp(Cp) -> Cp =:= 16#200B.

%% @doc True iff `Cp' is U+2014 EM DASH.
is_em_dash(Cp) -> Cp =:= 16#2014.

%% @doc True iff `Cp' is U+002D HYPHEN-MINUS (ASCII).
is_hyphen_minus(Cp) -> Cp =:= 16#002D.

%% @doc True iff `Cp' is one of the four "curly" quotation marks: U+2018 / U+2019
%% (single open/close) and U+201C / U+201D (double open/close).
is_curly_quote(Cp) ->
    Cp =:= 16#2018 orelse Cp =:= 16#2019 orelse Cp =:= 16#201C orelse Cp =:= 16#201D.

%% @doc True iff `Cp' is an ASCII straight quote — U+0022 (double) or U+0027
%% (single / apostrophe).
is_straight_quote(Cp) ->
    Cp =:= 16#0022 orelse Cp =:= 16#0027.

%% @doc Codepoint at 0-based index `J' of the tuple view (length `N'), or `none'.
at(_Tuple, N, J) when J < 0 orelse J >= N -> none;
at(Tuple, _N, J) -> {ok, element(J + 1, Tuple)}.

cp_is_emoji({ok, Cp}) -> is_emoji(Cp);
cp_is_emoji(none) -> false.

%% @doc True iff `input[I]' is adjacent (immediate predecessor OR immediate
%% successor) to an emoji codepoint. Two-sided check. Used by the VS and ZWJ
%% probes to exclude legitimate emoji-context occurrences.
is_adjacent_to_emoji(Tuple, N, I) ->
    PrevIsEmoji = case I of
                      0 -> false;
                      _Nonzero -> cp_is_emoji(at(Tuple, N, I - 1))
                  end,
    NextIsEmoji = cp_is_emoji(at(Tuple, N, I + 1)),
    PrevIsEmoji orelse NextIsEmoji.

%% @doc All 0-based positions in `Input' matching predicate `Pred'.
all_positions(Pred, Input) ->
    all_positions(Pred, Input, 0, []).
all_positions(_Pred, [], _I, Acc) -> lists:reverse(Acc);
all_positions(Pred, [Cp | Rest], I, Acc) ->
    case Pred(Cp) of
        true -> all_positions(Pred, Rest, I + 1, [I | Acc]);
        false -> all_positions(Pred, Rest, I + 1, Acc)
    end.

%% @doc True iff `Positions' forms an arithmetic progression with all consecutive
%% gaps within `Tolerance' of the first gap. Empty and singleton lists are
%% vacuously arithmetic. `Positions' is ascending, so gaps are non-negative.
positions_are_arithmetic_within([], _Tolerance) -> true;
positions_are_arithmetic_within([_Single], _Tolerance) -> true;
positions_are_arithmetic_within([P0, P1 | _Rest] = Positions, Tolerance) ->
    FirstGap = P1 - P0,
    gaps_within(Positions, FirstGap, Tolerance).

gaps_within([A, B | Rest], FirstGap, Tolerance) ->
    Gap = B - A,
    case Gap =< FirstGap + Tolerance andalso FirstGap =< Gap + Tolerance of
        true -> gaps_within([B | Rest], FirstGap, Tolerance);
        false -> false
    end;
gaps_within([_Last], _FirstGap, _Tolerance) -> true;
gaps_within([], _FirstGap, _Tolerance) -> true.

%% @doc First 0-based start-position at which `Pattern' appears as a contiguous
%% sub-slice of `Input', or `none' if absent (or `Pattern' is empty).
contains_sublist([], _Input) -> none;
contains_sublist(Pattern, Input) ->
    PatternLen = length(Pattern),
    InputLen = length(Input),
    case PatternLen > InputLen of
        true -> none;
        false -> contains_sublist_from(Pattern, Input, 0, InputLen - PatternLen)
    end.

contains_sublist_from(_Pattern, _Input, Start, MaxStart) when Start > MaxStart -> none;
contains_sublist_from(Pattern, Input, Start, MaxStart) ->
    case lists:prefix(Pattern, lists:nthtail(Start, Input)) of
        true -> {ok, Start};
        false -> contains_sublist_from(Pattern, Input, Start + 1, MaxStart)
    end.

%% @doc First 0-based start-position of any AI-favored vocabulary word in
%% `Input' (words scanned in catalog order), or `none'.
vocab_hit(Input) -> vocab_hit(ai_favored_vocabulary(), Input).
vocab_hit([], _Input) -> none;
vocab_hit([Pattern | Rest], Input) ->
    case contains_sublist(Pattern, Input) of
        {ok, Pos} -> {ok, Pos};
        none -> vocab_hit(Rest, Input)
    end.

%% @doc The "AI-favored" lexical-pattern catalog (each word as its codepoint
%% sequence), transcribed verbatim from the pinned `aiFavoredVocabulary' literal
%% in the Lean spec (parsed from `Ucd/Security/AiFavoredVocabulary.txt' and
%% drift-gated there against a fresh parse).
ai_favored_vocabulary() ->
    [[100, 101, 108, 118, 101],
     [100, 101, 108, 118, 105, 110, 103],
     [116, 97, 112, 101, 115, 116, 114, 121],
     [105, 110, 116, 114, 105, 99, 97, 116, 101],
     [110, 117, 97, 110, 99, 101, 100],
     [109, 111, 114, 101, 111, 118, 101, 114],
     [102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101],
     [114, 101, 97, 108, 109],
     [101, 108, 117, 99, 105, 100, 97, 116, 101],
     [115, 104, 111, 119, 99, 97, 115, 105, 110, 103],
     [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115],
     [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100],
     [112, 105, 118, 111, 116, 97, 108],
     [98, 111, 108, 115, 116, 101, 114],
     [109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100],
     [116, 101, 115, 116, 97, 109, 101, 110, 116],
     [102, 111, 115, 116, 101, 114],
     [104, 111, 108, 105, 115, 116, 105, 99],
     [112, 97, 114, 97, 100, 105, 103, 109],
     [116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101],
     [115, 112, 101, 97, 114, 104, 101, 97, 100],
     [109, 101, 116, 105, 99, 117, 108, 111, 117, 115],
     [109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121],
     [101, 109, 112, 111, 119, 101, 114],
     [101, 109, 112, 111, 119, 101, 114, 105, 110, 103],
     [112, 114, 111, 102, 111, 117, 110, 100],
     [112, 114, 111, 102, 111, 117, 110, 100, 108, 121],
     [99, 111, 109, 112, 101, 108, 108, 105, 110, 103],
     [99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101],
     [99, 114, 117, 99, 105, 97, 108],
     [100, 97, 117, 110, 116, 105, 110, 103],
     [114, 111, 98, 117, 115, 116],
     [115, 116, 114, 101, 97, 109, 108, 105, 110, 101],
     [101, 110, 114, 105, 99, 104],
     [101, 120, 101, 109, 112, 108, 105, 102, 121],
     [99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103],
     [100, 105, 115, 99, 101, 114, 110, 105, 110, 103],
     [109, 101, 115, 109, 101, 114, 105, 122, 101],
     [105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121],
     [105, 109, 98, 117, 101],
     [112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108, 101],
     [112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111, 108, 101],
     [105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111, 32,
      110, 111, 116, 101],
     [105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103],
     [105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110],
     [105, 110, 32, 101, 115, 115, 101, 110, 99, 101],
     [100, 101, 108, 118, 101, 32, 105, 110, 116, 111],
     [100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111],
     [116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102],
     [114, 101, 97, 108, 109, 32, 111, 102]].

%% ─────────────────────────────────────────────────────────────────────
%% §4 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The detection function. Runs every probe in the fixed priority order
%% (most-specific first); the first hit wins. `Ctx' is a map with optional
%% `zwsp_modulo_tolerance' / `adversarial_tolerance' keys (absent ⇒ 0).
detect_with_context(Ctx, Input) ->
    Tuple = list_to_tuple(Input),
    N = length(Input),

    NnbspPositions = all_positions(fun is_nnbsp/1, Input),
    NnbspCount = length(NnbspPositions),

    %% Probe 1: adversarial — NNBSP too-regular.
    AdversarialTolerance = maps:get(adversarial_tolerance, Ctx, 0),
    AdversarialFires = NnbspCount >= 3
        andalso positions_are_arithmetic_within(NnbspPositions, AdversarialTolerance),

    %% Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
    ZwspPositions = all_positions(fun is_zwsp/1, Input),
    ZwspCount = length(ZwspPositions),
    ZwspModuloTolerance = maps:get(zwsp_modulo_tolerance, Ctx, 0),
    ZwspModuloFires = ZwspCount >= 3
        andalso positions_are_arithmetic_within(ZwspPositions, ZwspModuloTolerance),

    VsAllPos = all_positions(fun is_variation_selector/1, Input),
    VsNonEmojiPos = [I || I <- VsAllPos, not is_adjacent_to_emoji(Tuple, N, I)],
    VsNonEmojiCount = length(VsNonEmojiPos),

    ZwjAllPos = all_positions(fun is_zwj/1, Input),
    ZwjNonEmojiPos = [I || I <- ZwjAllPos, not is_adjacent_to_emoji(Tuple, N, I)],
    ZwjNonEmojiCount = length(ZwjNonEmojiPos),

    %% Probe 7: smartQuoteAlternation — curly quotes only.
    CurlyPositions = all_positions(fun is_curly_quote/1, Input),
    CurlyCount = length(CurlyPositions),
    HasStraightQuote = lists:any(fun is_straight_quote/1, Input),
    SmartQuoteFires = CurlyCount >= 2 andalso not HasStraightQuote,

    %% Probe 8: emDashPattern — em-dashes without hyphen-minus.
    EmDashPositions = all_positions(fun is_em_dash/1, Input),
    EmDashCount = length(EmDashPositions),
    HasHyphenMinus = lists:any(fun is_hyphen_minus/1, Input),
    EmDashFires = EmDashCount >= 2 andalso not HasHyphenMinus,

    %% Probe 9: statisticalTokenChoice — scan the pinned vocabulary.
    VocabHit = vocab_hit(Input),

    %% Residual default-ignorables (excluding VS and ZWJ, handled above).
    IsResidualDi = fun(Cp) ->
                           is_default_ignorable(Cp)
                               andalso not is_variation_selector(Cp)
                               andalso not is_zwj(Cp)
                   end,
    DiPositions = all_positions(IsResidualDi, Input),
    DiCount = length(DiPositions),

    %% Probe 3: unknown — invisible markers from >= 2 distinct categories.
    CategoryCount = bool_to_int(NnbspCount > 0)
        + bool_to_int(VsNonEmojiCount > 0)
        + bool_to_int(ZwjNonEmojiCount > 0)
        + bool_to_int(DiCount > 0),
    UnknownFires = CategoryCount >= 2,
    TotalInvisibleCount = NnbspCount + VsNonEmojiCount + ZwjNonEmojiCount + DiCount,

    {Classification, FiredCount} =
        if
            AdversarialFires ->
                FirstPos = first_or_zero(NnbspPositions),
                {{hazard, {adversarial, <<"nnbspBoundary">>, FirstPos}, NnbspPositions}, NnbspCount};
            ZwspModuloFires ->
                FirstPos = first_or_zero(ZwspPositions),
                {{hazard, {gpt5_zwsp_modulo, FirstPos}, ZwspPositions}, ZwspCount};
            UnknownFires ->
                AllInvisiblePos = all_positions(fun is_any_invisible/1, Input),
                {{hazard, {unknown, TotalInvisibleCount}, AllInvisiblePos}, TotalInvisibleCount};
            NnbspCount > 0 ->
                {{hazard, {nnbsp_boundary, NnbspCount}, NnbspPositions}, NnbspCount};
            VsNonEmojiCount > 0 ->
                {{hazard, {variation_selector_carrier, VsNonEmojiCount}, VsNonEmojiPos}, VsNonEmojiCount};
            ZwjNonEmojiCount > 0 ->
                {{hazard, {zwj_non_emoji, ZwjNonEmojiCount}, ZwjNonEmojiPos}, ZwjNonEmojiCount};
            SmartQuoteFires ->
                FirstPos = first_or_zero(CurlyPositions),
                {{hazard, {smart_quote_alternation, FirstPos}, CurlyPositions}, CurlyCount};
            EmDashFires ->
                FirstPos = first_or_zero(EmDashPositions),
                {{hazard, {em_dash_pattern, FirstPos}, EmDashPositions}, EmDashCount};
            true ->
                resolve_vocab_or_di(VocabHit, DiPositions, DiCount)
        end,

    #{input => Input,
      classify => Classification,
      marker_count => FiredCount}.

%% @doc The `unknown'-probe position set: every invisible marker of any category.
is_any_invisible(Cp) ->
    is_nnbsp(Cp)
        orelse is_variation_selector(Cp)
        orelse is_zwj(Cp)
        orelse is_default_ignorable(Cp).

%% @doc Fallthrough after the boolean probes: vocabulary hit (probe 9), then
%% residual default-ignorable (probe 10), then clear.
resolve_vocab_or_di({ok, Pos}, _DiPositions, _DiCount) ->
    {{hazard, {statistical_token_choice, Pos}, [Pos]}, 1};
resolve_vocab_or_di(none, DiPositions, DiCount) when DiCount > 0 ->
    {{hazard, {default_ignorable_carrier, DiCount}, DiPositions}, DiCount};
resolve_vocab_or_di(none, _DiPositions, 0) ->
    {clear, 0}.

first_or_zero([]) -> 0;
first_or_zero([Head | _Tail]) -> Head.

bool_to_int(true) -> 1;
bool_to_int(false) -> 0.

%% @doc Convenience wrapper over `detect_with_context/2' with the empty context —
%% exact-arithmetic settings (`zwsp_modulo_tolerance = 0',
%% `adversarial_tolerance = 0').
detect(Input) ->
    detect_with_context(#{}, Input).
