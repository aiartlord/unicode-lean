%% filename-disguise — detection of filename/extension disguise attacks where
%% the visible extension differs from the byte extension (the display-layer
%% detector, layer D). Answers the question: does this filename carry a codepoint
%% that could make its rendered extension diverge from its byte extension?
%%
%% Direct port of the verified Rust reference implementation (itself a port of
%% the Lean `Unicode/Security/Display/FilenameDisguise' specification).
%%
%% Threat model. An adversary delivers a file whose rendered name looks like a
%% benign type (`document.txt') but whose actual byte extension is executable —
%% the canonical attack inserts U+202E RIGHT-TO-LEFT OVERRIDE so
%% `document<RLO>txt.exe' renders as `document exe.txt'.
%%
%% Detection is presentation- and language-agnostic: it surfaces every codepoint
%% that could cause display-vs-byte divergence in the filename — any bidi
%% format-control anywhere, and any fullwidth/halfwidth or combining (grapheme
%% Extend) codepoint in the extension region (at or after the last `.'). A
%% native-RTL name with no bidi controls clears.
%%
%% Sub-threats (priority order):
%%   1. RloFlip            any bidi format-control anywhere in the input.
%%   2. WidthClassExt      a fullwidth/halfwidth (U+FF01..U+FFEF) codepoint at or
%%                         after the extension start.
%%   3. CombiningInExt     a combining (grapheme Extend) codepoint at or after the
%%                         extension start.
%%   4. MultipleExtensions three or more `.' separators (advisory).
%%
%% Every predicate reuses a table this port already bundles, never a host
%% filesystem or rendering library:
%%   - the bidi format-control set via `usec_detectors:is_bidi_format_control/1'
%%     (the port's BidiControlBalance / RtlInjection predicate: the LRE/RLE/LRO/
%%     RLO/PDF/LRI/RLI/FSI/PDI set);
%%   - the Grapheme_Cluster_Break = Extend class via `usec_grapheme:lookup_gcb/1'
%%     (the port's UAX #29 segmentation table);
%%   - the Halfwidth/Fullwidth Forms range U+FF01..U+FFEF, inlined;
%%   - the ASCII FULL STOP U+002E, inlined.

-module(usec_filename_disguise).

-export([sub_threat_tag/1,
         classify_tag/1, classify_positions/1, is_clear/1,
         is_ascii_dot/1, is_fullwidth_halfwidth/1,
         is_bidi_format_control/1, is_grapheme_extend/1,
         detect/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Types
%% ─────────────────────────────────────────────────────────────────────
%%
%% SubThreat — one tuple per rust variant, in priority order:
%%   {rlo_flip, Position, ControlCp}       a bidi format-control at Position
%%                                         (codepoint ControlCp).
%%   {width_class_ext, Position, Cp}       a fullwidth/halfwidth codepoint in the
%%                                         extension at Position.
%%   {combining_in_ext, Position, Cp}      a combining (Extend) codepoint in the
%%                                         extension at Position.
%%   {multiple_extensions, DotCount}       three or more `.' separators.
%%
%% Classification — `clear' | {hazard, SubThreat, Positions, Decoded}. `Decoded'
%% is always the empty list here; it is kept for shape parity with the Lean
%% `Classification.hazard' decoded-byte projection.
%%
%% Verdict — a map #{input, classify, dot_positions, last_dot_pos,
%% bidi_control_count, fullwidth_in_ext, combining_in_ext}. `last_dot_pos' is
%% `none' when the input carries no `.', else the index of the last `.'.

%% @doc Fixture-row tag string for a sub-threat tuple (matches `SubThreat.tag').
sub_threat_tag({rlo_flip, _Position, _ControlCp}) -> <<"RloFlip">>;
sub_threat_tag({width_class_ext, _Position, _Cp}) -> <<"WidthClassExt">>;
sub_threat_tag({combining_in_ext, _Position, _Cp}) -> <<"CombiningInExt">>;
sub_threat_tag({multiple_extensions, _DotCount}) -> <<"MultipleExtensions">>.

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
%% §2 Core predicates (each reuses a table the port already bundles)
%% ─────────────────────────────────────────────────────────────────────

%% @doc True iff `Cp' is U+002E FULL STOP (the extension separator).
is_ascii_dot(Cp) -> Cp =:= 16#002E.

%% @doc True iff `Cp' is in the Halfwidth/Fullwidth Forms range U+FF01..U+FFEF.
is_fullwidth_halfwidth(Cp) -> Cp >= 16#FF01 andalso Cp =< 16#FFEF.

%% @doc True iff `Cp' is a bidi format-control — reuses the port's own
%% BidiControlBalance / RtlInjection predicate
%% (`usec_detectors:is_bidi_format_control/1').
is_bidi_format_control(Cp) -> usec_detectors:is_bidi_format_control(Cp).

%% @doc True iff `Cp' has `Grapheme_Cluster_Break = Extend' — reuses the port's
%% UAX #29 segmentation table (`usec_grapheme:lookup_gcb/1'). A combining mark
%% that stacks onto the preceding base.
is_grapheme_extend(Cp) -> usec_grapheme:lookup_gcb(Cp) =:= extend.

%% ─────────────────────────────────────────────────────────────────────
%% §3 Sub-detectors
%% ─────────────────────────────────────────────────────────────────────

%% @doc Positions of every `.' separator in `Input'.
dot_positions(Input) -> dot_positions(Input, 0).

dot_positions([], _I) -> [];
dot_positions([Cp | Rest], I) ->
    case is_ascii_dot(Cp) of
        true -> [I | dot_positions(Rest, I + 1)];
        false -> dot_positions(Rest, I + 1)
    end.

%% @doc Position and codepoint of the first bidi format-control, or `none'.
first_bidi_control(Input) -> first_bidi_control(Input, 0).

first_bidi_control([], _I) -> none;
first_bidi_control([Cp | Rest], I) ->
    case is_bidi_format_control(Cp) of
        true -> {I, Cp};
        false -> first_bidi_control(Rest, I + 1)
    end.

%% @doc Position and codepoint of the first fullwidth/halfwidth codepoint at or
%% after index `Start', or `none'.
first_fullwidth_from(Input, Start) -> first_fullwidth_from(Input, Start, 0).

first_fullwidth_from([], _Start, _I) -> none;
first_fullwidth_from([Cp | Rest], Start, I) ->
    case I >= Start andalso is_fullwidth_halfwidth(Cp) of
        true -> {I, Cp};
        false -> first_fullwidth_from(Rest, Start, I + 1)
    end.

%% @doc Position and codepoint of the first Extend codepoint at or after index
%% `Start', or `none'.
first_extend_from(Input, Start) -> first_extend_from(Input, Start, 0).

first_extend_from([], _Start, _I) -> none;
first_extend_from([Cp | Rest], Start, I) ->
    case I >= Start andalso is_grapheme_extend(Cp) of
        true -> {I, Cp};
        false -> first_extend_from(Rest, Start, I + 1)
    end.

%% @doc Count of fullwidth/halfwidth codepoints at or after index `Start'.
count_fullwidth_from(Input, Start) ->
    length([Cp || {I, Cp} <- with_index(Input), I >= Start, is_fullwidth_halfwidth(Cp)]).

%% @doc Count of Extend codepoints at or after index `Start'.
count_extend_from(Input, Start) ->
    length([Cp || {I, Cp} <- with_index(Input), I >= Start, is_grapheme_extend(Cp)]).

%% @doc Pair each codepoint with its 0-based index.
with_index(Input) -> lists:zip(lists:seq(0, length(Input) - 1), Input).

%% ─────────────────────────────────────────────────────────────────────
%% §4 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The FilenameDisguise detection function.
detect(Input) ->
    Dots = dot_positions(Input),
    LastDot = last_dot(Dots),
    ExtStart = case LastDot of
                   none -> length(Input);
                   P -> P + 1
               end,
    BidiCount = length([Cp || Cp <- Input, is_bidi_format_control(Cp)]),
    FwInExt = count_fullwidth_from(Input, ExtStart),
    ExtInExt = count_extend_from(Input, ExtStart),
    Classification = classify(Input, Dots, ExtStart),
    #{input => Input,
      classify => Classification,
      dot_positions => Dots,
      last_dot_pos => LastDot,
      bidi_control_count => BidiCount,
      fullwidth_in_ext => FwInExt,
      combining_in_ext => ExtInExt}.

%% @doc Index of the last `.' separator, or `none' when there is none.
last_dot([]) -> none;
last_dot(Dots) -> lists:last(Dots).

%% @doc Classification by first trigger in priority order: RloFlip,
%% WidthClassExt, CombiningInExt, MultipleExtensions; `clear' when none fires.
classify(Input, Dots, ExtStart) ->
    case first_bidi_control(Input) of
        {Pos, CtlCp} ->
            {hazard, {rlo_flip, Pos, CtlCp}, [Pos], []};
        none ->
            classify_fullwidth(Input, Dots, ExtStart)
    end.

classify_fullwidth(Input, Dots, ExtStart) ->
    case first_fullwidth_from(Input, ExtStart) of
        {Pos, Cp} ->
            {hazard, {width_class_ext, Pos, Cp}, [Pos], []};
        none ->
            classify_combining(Input, Dots, ExtStart)
    end.

classify_combining(Input, Dots, ExtStart) ->
    case first_extend_from(Input, ExtStart) of
        {Pos, Cp} ->
            {hazard, {combining_in_ext, Pos, Cp}, [Pos], []};
        none ->
            classify_multiple_extensions(Dots)
    end.

classify_multiple_extensions(Dots) ->
    case length(Dots) >= 3 of
        true -> {hazard, {multiple_extensions, length(Dots)}, Dots, []};
        false -> clear
    end.
