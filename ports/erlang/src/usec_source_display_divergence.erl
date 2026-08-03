%% source-display-divergence — the aggregate "what a reviewer sees differs from
%% what the machine runs" detector (display-layer aggregator, layer D).
%%
%% Direct port of the verified Rust reference implementation (itself a port of
%% the Lean `Unicode/Security/Display/SourceDisplayDivergence' specification,
%% `detect' + `buildClassification').
%%
%% Threat model. A single covert or identity trick may be individually
%% benign-looking, but any hit means the rendered source diverges from its
%% logical content; two or more is a strong compound signal. This detector runs
%% five constituent detectors on the same codepoint stream and aggregates:
%%   zero fired  → clear;
%%   exactly one → pass through that family's tag;
%%   two or more → `Compound'.
%%
%% It owns no data table and no predicate of its own — it is pure aggregation
%% over the port's five existing constituent detectors, evaluated in this exact
%% canonical order, each contributing its family tag when its classification is
%% non-clear (`kind =/= clear'):
%%   1. `usec_detectors:tag_block_detect/1'          → `TagBlock'
%%   2. `usec_detectors:variation_selector_detect/1' → `VariationSelector'
%%   3. `usec_detectors:zero_width_detect/1'         → `ZeroWidth'
%%   4. `usec_detectors:bidi_control_detect/1'       → `BidiControl'
%%   5. `usec_detectors:homoglyph_detect/1'          → `IdentifierHomoglyph'
%%
%% Every constituent fires region-agnostically — payloads inside string literals
%% or comments count. No positions are reported at this layer (the Lean spec
%% keeps them empty; the per-family verdicts carry them).

-module(usec_source_display_divergence).

-export([sub_threat_tag/1,
         classify_tag/1, classify_positions/1, is_clear/1,
         detect/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Types
%% ─────────────────────────────────────────────────────────────────────
%%
%% SubThreat — `{source_display_divergence, Tag}' where Tag is one of the five
%% constituent family tags for a single fire, or `<<"Compound">>' for two-plus.
%%
%% Classification — `clear' | {hazard, SubThreat, Positions, Decoded}.
%% `Positions' is always the empty list (this layer carries none) and `Decoded'
%% is always the empty list, kept for shape parity with the Lean
%% `Classification.hazard' decoded-byte projection.
%%
%% Verdict — a map #{input, classify, fired} where `fired' is the ordered list
%% of constituent tags that fired.

%% @doc Fixture-row tag string for a sub-threat tuple (matches `SubThreat.tag').
sub_threat_tag({source_display_divergence, Tag}) -> Tag.

%% @doc Human-facing tag for a classification, or `none' when clear.
classify_tag(clear) -> none;
classify_tag({hazard, Sub, _Positions, _Decoded}) -> sub_threat_tag(Sub).

%% @doc Implicated positions (always empty at this layer).
classify_positions(clear) -> [];
classify_positions({hazard, _Sub, Positions, _Decoded}) -> Positions.

%% @doc True iff the classification is `clear'.
is_clear(clear) -> true;
is_clear({hazard, _Sub, _Positions, _Decoded}) -> false.

%% ─────────────────────────────────────────────────────────────────────
%% §2 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The SourceDisplayDivergence detection function. Runs the five
%% constituent detectors in canonical order and aggregates by how many fired.
detect(Input) ->
    Fired = fired_tags(Input),
    Classification =
        case Fired of
            [] -> clear;
            [Tag] -> {hazard, {source_display_divergence, Tag}, [], []};
            [_First, _Second | _Rest] ->
                {hazard, {source_display_divergence, <<"Compound">>}, [], []}
        end,
    #{input => Input,
      classify => Classification,
      fired => Fired}.

%% @doc The constituent family tags that fired, in canonical aggregation order.
%% Each constituent's classification `kind' is inspected via explicit dispatch;
%% `clear' does not fire, `hazard' does.
fired_tags(Input) ->
    Constituents =
        [{<<"TagBlock">>, usec_detectors:tag_block_detect(Input)},
         {<<"VariationSelector">>, usec_detectors:variation_selector_detect(Input)},
         {<<"ZeroWidth">>, usec_detectors:zero_width_detect(Input)},
         {<<"BidiControl">>, usec_detectors:bidi_control_detect(Input)},
         {<<"IdentifierHomoglyph">>, usec_detectors:homoglyph_detect(Input)}],
    lists:filtermap(
      fun({Tag, Verdict}) ->
              case fired(maps:get(kind, Verdict)) of
                  true -> {true, Tag};
                  false -> false
              end
      end, Constituents).

%% @doc A constituent fires iff its classification kind is not `clear'.
fired(clear) -> false;
fired(hazard) -> true.
