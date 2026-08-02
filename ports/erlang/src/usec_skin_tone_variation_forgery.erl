%% skin-tone-variation-forgery — skin-tone modifier and variation-selector abuse
%% on emoji bases per UTS #51 (the identity-layer detector). Answers the
%% question: is a skin-tone modifier or a text-style variation selector applied
%% to a codepoint that must not bear it?
%%
%% Direct port of the verified Rust reference implementation (itself a port of
%% `Unicode/Security/Identity/SkinToneVariationForgery.lean`).
%%
%% Threat model. An adversary places a skin-tone modifier on a codepoint that
%% does NOT carry `Emoji_Modifier_Base', stacks multiple skin tones on one base,
%% or forces a text-style render on an emoji-default codepoint via U+FE0E
%% (VS15) — sometimes to hide a payload-bearing glyph in plain sight. Distinct
%% from the pair-aligned variation-selector-payload case: this catches the
%% orthogonal *semantic* skin-tone / VS misuse on a single base.
%%
%% Emoji property tables. The port's own priv/data/emoji-data.txt (UTS #51,
%% byte-identical to the UCD source the Lean spec cites) already backs the
%% AiWatermarkDetectability and EmojiZwjIntegrity detectors; the skin-tone
%% modifier predicate is reused straight from `usec_emoji_zwj_integrity'. The
%% two additional properties this detector needs — `Emoji_Modifier_Base' and
%% `Emoji_Presentation' — are parsed from that same already-bundled file via
%% `usec_data', never from a host emoji library and never a new data file.
%%
%% Sub-threats (priority order):
%%   1. StackedSkinTones      a base immediately followed by >= 2 skin-tone modifiers.
%%   2. InvalidSkinToneTarget a skin-tone modifier on a non-`Emoji_Modifier_Base'.
%%   3. ForcedTextStyle       U+FE0E on an `Emoji_Presentation' codepoint.

-module(usec_skin_tone_variation_forgery).

-export([sub_threat_tag/1,
         classify_tag/1, classify_positions/1, is_clear/1,
         is_skin_tone/1, is_skin_tone_base/1, is_emoji_presentation/1,
         is_vs15/1, is_vs16/1,
         detect/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Constants
%% ─────────────────────────────────────────────────────────────────────

%% U+FE0E VARIATION SELECTOR-15 (VS15) — forces text-style presentation.
-define(VS15, 16#FE0E).

%% U+FE0F VARIATION SELECTOR-16 (VS16) — forces emoji-style presentation.
-define(VS16, 16#FE0F).

%% ─────────────────────────────────────────────────────────────────────
%% §2 Types
%% ─────────────────────────────────────────────────────────────────────
%%
%% SubThreat — one tuple per rust variant, in priority order:
%%   {stacked_skin_tones, BasePos, Modifiers}         BasePos is the base
%%                                                    position; Modifiers is the
%%                                                    first two stacked skin-tone
%%                                                    modifiers [M1, M2].
%%   {invalid_skin_tone_target, BasePos, BaseCp, ModifierCp}
%%                                                    a skin-tone ModifierCp at
%%                                                    BasePos+1 on a
%%                                                    non-modifier-base BaseCp.
%%   {forced_text_style, BasePos, BaseCp}             a U+FE0E at BasePos+1
%%                                                    forcing text style on an
%%                                                    `Emoji_Presentation' BaseCp.
%%
%% Classification — `clear' | {hazard, SubThreat, Positions, Decoded}. `Decoded'
%% is always the empty list here; it is kept for shape parity with the Lean
%% `Classification.hazard' decoded-byte projection.
%%
%% Verdict — a map #{input, classify, skin_tone_count,
%% variation_selector15_count, variation_selector16_count}.

%% @doc Fixture-row tag string for a sub-threat tuple (matches `SubThreat.tag').
sub_threat_tag({stacked_skin_tones, _BasePos, _Modifiers}) -> <<"StackedSkinTones">>;
sub_threat_tag({invalid_skin_tone_target, _BasePos, _BaseCp, _ModifierCp}) -> <<"InvalidSkinToneTarget">>;
sub_threat_tag({forced_text_style, _BasePos, _BaseCp}) -> <<"ForcedTextStyle">>.

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
%% §3 Emoji property tables (bundled priv/data/emoji-data.txt)
%% ─────────────────────────────────────────────────────────────────────

%% @doc The memoised closed intervals for `Emoji_Modifier_Base'.
emoji_modifier_base_ranges() ->
    usec_data:cached(skin_tone_emoji_modifier_base, fun() -> parse_emoji_property(<<"Emoji_Modifier_Base">>) end).

%% @doc The memoised closed intervals for `Emoji_Presentation'.
emoji_presentation_ranges() ->
    usec_data:cached(skin_tone_emoji_presentation, fun() -> parse_emoji_property(<<"Emoji_Presentation">>) end).

%% @doc Parse the closed intervals for a single emoji property from
%% emoji-data.txt. Each non-comment row is `<range> ; <property> # <comment>';
%% keep only rows whose property field matches `Property' exactly. Mirrors the
%% existing emoji-data.txt property-interval parser used by the AiWatermark
%% detector, generalised over the target property.
parse_emoji_property(Property) ->
    Ls = binary:split(usec_data:read_file("emoji-data.txt"), <<"\n">>, [global]),
    lists:foldl(fun(Line, Acc) -> property_line(Property, Line, Acc) end, [], Ls).

property_line(Property, Line, Acc) ->
    Body = case binary:split(Line, <<"#">>) of
               [Before | _Comment] -> Before
           end,
    case string:trim(Body) of
        <<>> -> Acc;
        Stripped ->
            case binary:split(Stripped, <<";">>) of
                [RangeField, PropField] ->
                    case string:trim(PropField) =:= Property of
                        true -> [parse_range(RangeField) | Acc];
                        false -> Acc
                    end;
                _Malformed -> Acc
            end
    end.

parse_range(Field) ->
    Trim = string:trim(Field),
    case binary:split(Trim, <<"..">>) of
        [Single] ->
            Cp = binary_to_integer(Single, 16),
            {Cp, Cp};
        [Lo, Hi] ->
            {binary_to_integer(string:trim(Lo), 16), binary_to_integer(string:trim(Hi), 16)}
    end.

in_ranges(Cp, Ranges) ->
    lists:any(fun({Lo, Hi}) -> Lo =< Cp andalso Cp =< Hi end, Ranges).

%% ─────────────────────────────────────────────────────────────────────
%% §4 Core predicates
%% ─────────────────────────────────────────────────────────────────────

%% @doc True iff `Cp' is an emoji skin-tone modifier (U+1F3FB..U+1F3FF). Reuses
%% the port's own predicate rather than re-deriving the range.
is_skin_tone(Cp) -> usec_emoji_zwj_integrity:is_emoji_modifier(Cp).

%% @doc True iff `Cp' has `Emoji_Modifier_Base' per emoji-data.txt.
is_skin_tone_base(Cp) -> in_ranges(Cp, emoji_modifier_base_ranges()).

%% @doc True iff `Cp' has `Emoji_Presentation' per emoji-data.txt.
is_emoji_presentation(Cp) -> in_ranges(Cp, emoji_presentation_ranges()).

%% @doc True iff `Cp' is U+FE0E (VS15, text-style variation selector).
is_vs15(Cp) -> Cp =:= ?VS15.

%% @doc True iff `Cp' is U+FE0F (VS16, emoji-style variation selector).
is_vs16(Cp) -> Cp =:= ?VS16.

%% @doc Codepoint at 0-based index `J' of the tuple view (length `N'), or `none'.
at(_Tuple, N, J) when J < 0 orelse J >= N -> none;
at(Tuple, _N, J) -> {ok, element(J + 1, Tuple)}.

%% ─────────────────────────────────────────────────────────────────────
%% §5 Sub-detectors
%% ─────────────────────────────────────────────────────────────────────

%% @doc First position `I' whose next two codepoints are both skin-tone
%% modifiers, as `{ok, BasePos, [M1, M2]}', else `none'.
first_stacked_skin_tones(Input) ->
    Tuple = list_to_tuple(Input),
    N = length(Input),
    first_stacked_skin_tones(Tuple, N, 0).

first_stacked_skin_tones(_Tuple, N, I) when I >= N -> none;
first_stacked_skin_tones(Tuple, N, I) ->
    case {at(Tuple, N, I + 1), at(Tuple, N, I + 2)} of
        {{ok, M1}, {ok, M2}} ->
            case is_skin_tone(M1) andalso is_skin_tone(M2) of
                true -> {ok, I, [M1, M2]};
                false -> first_stacked_skin_tones(Tuple, N, I + 1)
            end;
        {_Next1, _Next2} ->
            first_stacked_skin_tones(Tuple, N, I + 1)
    end.

%% @doc First skin-tone modifier whose preceding codepoint is NOT
%% `Emoji_Modifier_Base', as `{ok, BasePos, BaseCp, ModifierCp}', else `none'.
first_invalid_skin_tone_target(Input) ->
    Tuple = list_to_tuple(Input),
    N = length(Input),
    first_invalid_skin_tone_target(Tuple, N, 0).

first_invalid_skin_tone_target(_Tuple, N, I) when I >= N -> none;
first_invalid_skin_tone_target(Tuple, N, I) ->
    BaseCp = element(I + 1, Tuple),
    case at(Tuple, N, I + 1) of
        {ok, Cp} ->
            case is_skin_tone(Cp) andalso not is_skin_tone_base(BaseCp) of
                true -> {ok, I, BaseCp, Cp};
                false -> first_invalid_skin_tone_target(Tuple, N, I + 1)
            end;
        none ->
            first_invalid_skin_tone_target(Tuple, N, I + 1)
    end.

%% @doc First U+FE0E whose preceding codepoint has `Emoji_Presentation', as
%% `{ok, BasePos, BaseCp}', else `none'.
first_forced_text_style(Input) ->
    Tuple = list_to_tuple(Input),
    N = length(Input),
    first_forced_text_style(Tuple, N, 0).

first_forced_text_style(_Tuple, N, I) when I >= N -> none;
first_forced_text_style(Tuple, N, I) ->
    BaseCp = element(I + 1, Tuple),
    case at(Tuple, N, I + 1) of
        {ok, Cp} ->
            case is_vs15(Cp) andalso is_emoji_presentation(BaseCp) of
                true -> {ok, I, BaseCp};
                false -> first_forced_text_style(Tuple, N, I + 1)
            end;
        none ->
            first_forced_text_style(Tuple, N, I + 1)
    end.

%% @doc Count of skin-tone modifier codepoints.
skin_tone_count(Input) -> length([Cp || Cp <- Input, is_skin_tone(Cp)]).

%% @doc Count of U+FE0E (VS15) codepoints.
vs15_count(Input) -> length([Cp || Cp <- Input, is_vs15(Cp)]).

%% @doc Count of U+FE0F (VS16) codepoints.
vs16_count(Input) -> length([Cp || Cp <- Input, is_vs16(Cp)]).

%% ─────────────────────────────────────────────────────────────────────
%% §6 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The SkinToneVariationForgery detection function. Runs the sub-detectors
%% in priority order (StackedSkinTones -> InvalidSkinToneTarget ->
%% ForcedTextStyle); the first hit wins, else `clear'.
detect(Input) ->
    Classification = classify(Input),
    #{input => Input,
      classify => Classification,
      skin_tone_count => skin_tone_count(Input),
      variation_selector15_count => vs15_count(Input),
      variation_selector16_count => vs16_count(Input)}.

classify(Input) ->
    case first_stacked_skin_tones(Input) of
        {ok, BasePos, Modifiers} ->
            Positions = [BasePos + 1 + K || K <- lists:seq(0, length(Modifiers) - 1)],
            {hazard, {stacked_skin_tones, BasePos, Modifiers}, Positions, []};
        none ->
            classify_after_stacked(Input)
    end.

classify_after_stacked(Input) ->
    case first_invalid_skin_tone_target(Input) of
        {ok, BasePos, BaseCp, ModifierCp} ->
            {hazard, {invalid_skin_tone_target, BasePos, BaseCp, ModifierCp}, [BasePos + 1], []};
        none ->
            classify_after_invalid(Input)
    end.

classify_after_invalid(Input) ->
    case first_forced_text_style(Input) of
        {ok, BasePos, BaseCp} ->
            {hazard, {forced_text_style, BasePos, BaseCp}, [BasePos + 1], []};
        none ->
            clear
    end.
