%% renderer-divergence — detection of codepoint/sequence shapes that render one
%% way in the auditor's font + terminal + browser stack and a different way in
%% the consumer's (the display-layer detector, layer D). Answers the question:
%% is this codepoint sequence a "fingerprint-stable" shape that the Standard
%% documents as rendering identically across the renderer cohort, or one of the
%% documented variance modes whose divergence is an attack surface?
%%
%% Direct port of the verified Rust reference implementation
%% (`ports/rust/src/security/display/renderer_divergence.rs', itself a port of
%% `Unicode/Security/Display/RendererDivergence.lean').
%%
%% Threat model. An adversary crafts content that renders as a benign glyph or
%% an empty span in the auditor's renderer and as a misleading, wider, or
%% differently-composed glyph in the consumer's renderer. Clear inputs render
%% the same across the renderer cohort the Standard documents as stable.
%%
%% Sub-threats (priority order):
%%   1. CombiningStackOverflow    a Zalgo-style combining-mark stack of at least
%%                                MIN_COMBINING_STACK Extend marks on one base.
%%   2. VariationSelectorVariance any variation selector present.
%%   3. UnregisteredZwjVariance   a ZWJ-containing input not in the RGI ZWJ set.
%%   4. FullwidthVariance         a fullwidth/halfwidth (U+FF01..U+FFEF) codepoint.
%%   5. MixedDirectionVariance    both strong-LTR and strong-RTL codepoints.
%%
%% Every predicate reuses a table this port already bundles, never a host
%% rendering or shaping library:
%%   - the variation-selector set via `usec_detectors:is_vs/1' (the port's
%%     VariationSelectorPayload predicate: U+FE00..U+FE0F, U+E0100..U+E01EF,
%%     U+180B..U+180D);
%%   - the Grapheme_Cluster_Break = Extend class via `usec_grapheme:lookup_gcb/1'
%%     (the port's UAX #29 segmentation table);
%%   - the registered RGI ZWJ set via
%%     `usec_emoji_zwj_integrity:is_registered_zwj_sequence/1';
%%   - the strong bidi classes via `usec_ucd:is_strong_ltr/1' and
%%     `usec_ucd:is_strong_rtl/1' (the port's UnicodeData bidi table).

-module(usec_renderer_divergence).

-export([sub_threat_tag/1,
         classify_tag/1, classify_positions/1, is_clear/1,
         is_variation_selector/1, is_zwj/1, is_fullwidth_halfwidth/1,
         is_grapheme_extend/1,
         detect/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Constants
%% ─────────────────────────────────────────────────────────────────────

%% The combining-mark stack depth (on a single base) at or beyond which the
%% input is treated as a Zalgo-style rendering-variance hazard.
-define(MIN_COMBINING_STACK, 4).

%% The ZERO WIDTH JOINER codepoint.
-define(ZWJ, 16#200D).

%% ─────────────────────────────────────────────────────────────────────
%% §2 Types
%% ─────────────────────────────────────────────────────────────────────
%%
%% SubThreat — one tuple per rust variant, in priority order:
%%   {combining_stack_overflow, BasePos, StackLen}  a stack of StackLen Extend
%%                                                  marks on the base at BasePos.
%%   {variation_selector_variance, FirstVsPos, FirstVsCp}  first variation
%%                                                  selector position + codepoint.
%%   {unregistered_zwj_variance, FirstZwjPos}       first ZWJ of a ZWJ-containing
%%                                                  input not in the RGI set.
%%   {fullwidth_variance, FirstFwPos, FirstFwCp}    first fullwidth/halfwidth
%%                                                  position + codepoint.
%%   {mixed_direction_variance, LtrCount, RtlCount} strong-LTR and strong-RTL
%%                                                  counts (both positive).
%%
%% Classification — `clear' | {hazard, SubThreat, Positions, Decoded}. `Decoded'
%% is always the empty list here; it is kept for shape parity with the Lean
%% `Classification.hazard' decoded-byte projection.
%%
%% Verdict — a map #{input, classify, vs_count, combining_count,
%% fullwidth_count, has_zwj, strong_ltr_count, strong_rtl_count}.

%% @doc Fixture-row tag string for a sub-threat tuple (matches `SubThreat.tag').
sub_threat_tag({combining_stack_overflow, _BasePos, _StackLen}) -> <<"CombiningStackOverflow">>;
sub_threat_tag({variation_selector_variance, _FirstVsPos, _FirstVsCp}) -> <<"VariationSelectorVariance">>;
sub_threat_tag({unregistered_zwj_variance, _FirstZwjPos}) -> <<"UnregisteredZwjVariance">>;
sub_threat_tag({fullwidth_variance, _FirstFwPos, _FirstFwCp}) -> <<"FullwidthVariance">>;
sub_threat_tag({mixed_direction_variance, _LtrCount, _RtlCount}) -> <<"MixedDirectionVariance">>.

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
%% §3 Core predicates (each reuses a table the port already bundles)
%% ─────────────────────────────────────────────────────────────────────

%% @doc True iff `Cp' is a variation selector — reuses the port's own
%% VariationSelectorPayload predicate (`usec_detectors:is_vs/1').
is_variation_selector(Cp) -> usec_detectors:is_vs(Cp).

%% @doc True iff `Cp' is the ZWJ codepoint.
is_zwj(Cp) -> Cp =:= ?ZWJ.

%% @doc True iff `Cp' is in the Halfwidth/Fullwidth Forms range U+FF01..U+FFEF.
is_fullwidth_halfwidth(Cp) -> Cp >= 16#FF01 andalso Cp =< 16#FFEF.

%% @doc True iff `Cp' has `Grapheme_Cluster_Break = Extend' — reuses the port's
%% UAX #29 segmentation table (`usec_grapheme:lookup_gcb/1'). A combining mark
%% that stacks onto the preceding base; used to measure Zalgo-style stacks.
is_grapheme_extend(Cp) -> usec_grapheme:lookup_gcb(Cp) =:= extend.

%% ─────────────────────────────────────────────────────────────────────
%% §4 Sub-detectors
%% ─────────────────────────────────────────────────────────────────────

%% @doc Position and codepoint of the first variation selector, or `none'.
first_vs_pos(Input) -> first_vs_pos(Input, 0).

first_vs_pos([], _I) -> none;
first_vs_pos([Cp | Rest], I) ->
    case is_variation_selector(Cp) of
        true -> {I, Cp};
        false -> first_vs_pos(Rest, I + 1)
    end.

%% @doc Position of the first ZWJ, or `none'.
first_zwj_pos(Input) -> first_zwj_pos(Input, 0).

first_zwj_pos([], _I) -> none;
first_zwj_pos([Cp | Rest], I) ->
    case is_zwj(Cp) of
        true -> I;
        false -> first_zwj_pos(Rest, I + 1)
    end.

%% @doc Position and codepoint of the first fullwidth/halfwidth codepoint, or
%% `none'.
first_fullwidth_pos(Input) -> first_fullwidth_pos(Input, 0).

first_fullwidth_pos([], _I) -> none;
first_fullwidth_pos([Cp | Rest], I) ->
    case is_fullwidth_halfwidth(Cp) of
        true -> {I, Cp};
        false -> first_fullwidth_pos(Rest, I + 1)
    end.

%% @doc The first base position (a non-Extend codepoint) immediately followed by
%% at least `MinStack' consecutive Extend codepoints, as `{BasePos, MinStack}',
%% or `none'. Mirrors the rust `first_combining_stack': the base must be followed
%% by exactly `MinStack' further codepoints all of which are Extend.
first_combining_stack(Input, MinStack) -> first_combining_stack(Input, MinStack, 0).

first_combining_stack([], _MinStack, _I) -> none;
first_combining_stack([Cp | Rest], MinStack, I) ->
    case is_grapheme_extend(Cp) of
        true -> first_combining_stack(Rest, MinStack, I + 1);
        false ->
            Following = lists:sublist(Rest, MinStack),
            case length(Following) =:= MinStack andalso lists:all(fun is_grapheme_extend/1, Following) of
                true -> {I, MinStack};
                false -> first_combining_stack(Rest, MinStack, I + 1)
            end
    end.

%% ─────────────────────────────────────────────────────────────────────
%% §5 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The RendererDivergence detection function.
detect(Input) ->
    VsCount = length([Cp || Cp <- Input, is_variation_selector(Cp)]),
    CombiningCount = length([Cp || Cp <- Input, is_grapheme_extend(Cp)]),
    FullwidthCount = length([Cp || Cp <- Input, is_fullwidth_halfwidth(Cp)]),
    HasZwj = lists:any(fun is_zwj/1, Input),
    LtrCount = length([Cp || Cp <- Input, usec_ucd:is_strong_ltr(Cp)]),
    RtlCount = length([Cp || Cp <- Input, usec_ucd:is_strong_rtl(Cp)]),
    Classification = classify(Input, HasZwj, LtrCount, RtlCount),
    #{input => Input,
      classify => Classification,
      vs_count => VsCount,
      combining_count => CombiningCount,
      fullwidth_count => FullwidthCount,
      has_zwj => HasZwj,
      strong_ltr_count => LtrCount,
      strong_rtl_count => RtlCount}.

%% @doc Classification by first trigger in priority order:
%% CombiningStackOverflow, VariationSelectorVariance, UnregisteredZwjVariance,
%% FullwidthVariance, MixedDirectionVariance; `clear' when none fires.
classify(Input, HasZwj, LtrCount, RtlCount) ->
    case first_combining_stack(Input, ?MIN_COMBINING_STACK) of
        {BasePos, StackLen} ->
            {hazard, {combining_stack_overflow, BasePos, StackLen}, [BasePos], []};
        none ->
            classify_vs(Input, HasZwj, LtrCount, RtlCount)
    end.

classify_vs(Input, HasZwj, LtrCount, RtlCount) ->
    case first_vs_pos(Input) of
        {Pos, Cp} ->
            {hazard, {variation_selector_variance, Pos, Cp}, [Pos], []};
        none ->
            classify_zwj(Input, HasZwj, LtrCount, RtlCount)
    end.

classify_zwj(Input, HasZwj, LtrCount, RtlCount) ->
    case HasZwj andalso not usec_emoji_zwj_integrity:is_registered_zwj_sequence(Input) of
        true ->
            case first_zwj_pos(Input) of
                none -> clear;
                Pos -> {hazard, {unregistered_zwj_variance, Pos}, [Pos], []}
            end;
        false ->
            classify_fullwidth(Input, LtrCount, RtlCount)
    end.

classify_fullwidth(Input, LtrCount, RtlCount) ->
    case first_fullwidth_pos(Input) of
        {Pos, Cp} ->
            {hazard, {fullwidth_variance, Pos, Cp}, [Pos], []};
        none ->
            classify_mixed_direction(LtrCount, RtlCount)
    end.

classify_mixed_direction(LtrCount, RtlCount) ->
    case LtrCount > 0 andalso RtlCount > 0 of
        true -> {hazard, {mixed_direction_variance, LtrCount, RtlCount}, [], []};
        false -> clear
    end.
