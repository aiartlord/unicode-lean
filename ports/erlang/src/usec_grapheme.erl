%% UAX #29 default extended grapheme cluster segmentation.
%%
%% A transcription of the Lean algorithm
%% `Unicode.Segmentation.GraphemeBreak.graphemeBreaks`, mirroring the rust port
%% (ports/rust/src/segmentation/grapheme.rs). The active Lean tree proves
%% `graphemeBreaks_eq_spec`, relating that algorithm to the declarative UAX #29
%% GB1-GB999 specification. The state fields, rule order, and transitions below
%% mirror that reference. Code points are handled as integer lists.
-module(usec_grapheme).

-export([lookup_gcb/1, lookup_incb/1, is_ext_pict/1,
         grapheme_breaks/1, grapheme_clusters/1]).

%% Running scan state, mirroring the Lean `State` and the rust `State`.
%% `prev_class` is the Grapheme_Cluster_Break class of the previous code point,
%% or `none` before the first code point (mirroring rust `Option<Gcb>`; the GCB
%% tables never assign the atom `none`, so it is an unambiguous sentinel).
%% `epic_state` is the GB11 left-context (none | after_ep | after_ep_zwj).
%% `incb_state` is the GB9c left-context (none | consonant | linker).
%% `ri_run` is the length of the current Regional_Indicator run.
-record(gstate, {prev_class = none :: atom(),
                 epic_state = none :: none | after_ep | after_ep_zwj,
                 incb_state = none :: none | consonant | linker,
                 ri_run = 0 :: non_neg_integer()}).

%% Grapheme_Cluster_Break class of `Cp`, `other` when uncovered.
-spec lookup_gcb(non_neg_integer()) -> atom().
lookup_gcb(Cp) ->
    find_range(Cp, usec_grapheme_tables:gcb_ranges(), other).

%% Indic_Conjunct_Break class of `Cp`, `none` when uncovered.
-spec lookup_incb(non_neg_integer()) -> atom().
lookup_incb(Cp) ->
    find_range(Cp, usec_grapheme_tables:incb_ranges(), none).

%% First covering range wins; each class is a partition so at most one covers.
%% Reaching the empty list means no range covers `Cp` — that is the genuine
%% "unassigned" case, returning the property's default value.
find_range(_Cp, [], Default) ->
    Default;
find_range(Cp, [{First, Last, Class} | _Rest], _Default) when Cp >= First, Cp =< Last ->
    Class;
find_range(Cp, [{_First, _Last, _Class} | Rest], Default) ->
    find_range(Cp, Rest, Default).

%% Whether `Cp` has the Extended_Pictographic property.
-spec is_ext_pict(non_neg_integer()) -> boolean().
is_ext_pict(Cp) ->
    any_range(Cp, usec_grapheme_tables:extpict_ranges()).

any_range(_Cp, []) ->
    false;
any_range(Cp, [{First, Last} | _Rest]) when Cp >= First, Cp =< Last ->
    true;
any_range(Cp, [{_First, _Last} | Rest]) ->
    any_range(Cp, Rest).

%% Whether a grapheme cluster break occurs immediately before `Cp` given the
%% running state. Implements UAX #29 GB1-GB999 in canonical order; the first
%% matching rule wins, and the trailing GB999 breaks every otherwise-unmatched
%% pair (Any div Any).
-spec should_break_before(non_neg_integer(), #gstate{}) -> boolean().
should_break_before(_Cp, #gstate{prev_class = none}) ->
    true;                                       % GB1: sot div
should_break_before(Cp, S) ->
    Pc = S#gstate.prev_class,
    Bc = lookup_gcb(Cp),
    Incb = lookup_incb(Cp),
    IsEp = is_ext_pict(Cp),
    if
        Pc =:= cr andalso Bc =:= lf ->
            false;                              % GB3: CR x LF
        Pc =:= control orelse Pc =:= cr orelse Pc =:= lf ->
            true;                               % GB4: (Control | CR | LF) div
        Bc =:= control orelse Bc =:= cr orelse Bc =:= lf ->
            true;                               % GB5: div (Control | CR | LF)
        Pc =:= l andalso (Bc =:= l orelse Bc =:= v orelse Bc =:= lv orelse Bc =:= lvt) ->
            false;                              % GB6: L x (L | V | LV | LVT)
        (Pc =:= lv orelse Pc =:= v) andalso (Bc =:= v orelse Bc =:= t) ->
            false;                              % GB7: (LV | V) x (V | T)
        (Pc =:= lvt orelse Pc =:= t) andalso Bc =:= t ->
            false;                              % GB8: (LVT | T) x T
        Bc =:= extend orelse Bc =:= zwj ->
            false;                              % GB9: x (Extend | ZWJ)
        Bc =:= spacing_mark ->
            false;                              % GB9a: x SpacingMark
        Pc =:= prepend ->
            false;                              % GB9b: Prepend x
        S#gstate.incb_state =:= linker andalso Incb =:= consonant ->
            false;                              % GB9c: Consonant [ Extend Linker ]* x Consonant
        S#gstate.epic_state =:= after_ep_zwj andalso IsEp ->
            false;                              % GB11: ExtPict Extend* ZWJ x ExtPict
        Bc =:= regional_indicator andalso (S#gstate.ri_run rem 2) =:= 1 ->
            false;                              % GB12/GB13: odd-parity RI run extends
        true ->
            true                                % GB999: Any div Any
    end.

%% Update the running state after consuming `Cp`. Mirrors the Lean `advance`.
-spec advance(non_neg_integer(), #gstate{}) -> #gstate{}.
advance(Cp, S) ->
    Bc = lookup_gcb(Cp),
    Incb = lookup_incb(Cp),
    IsEp = is_ext_pict(Cp),
    Epic =
        if
            IsEp ->
                after_ep;
            S#gstate.epic_state =:= after_ep andalso Bc =:= extend ->
                after_ep;
            S#gstate.epic_state =:= after_ep andalso Bc =:= zwj ->
                after_ep_zwj;
            true ->
                none
        end,
    IncbSt =
        if
            Incb =:= consonant ->
                consonant;
            S#gstate.incb_state =:= consonant andalso Incb =:= linker ->
                linker;
            S#gstate.incb_state =:= consonant andalso Incb =:= extend ->
                consonant;
            S#gstate.incb_state =:= linker andalso Incb =:= linker ->
                linker;
            S#gstate.incb_state =:= linker andalso Incb =:= extend ->
                linker;
            true ->
                none
        end,
    RiRun =
        if
            Bc =:= regional_indicator ->
                S#gstate.ri_run + 1;
            true ->
                0
        end,
    #gstate{prev_class = Bc, epic_state = Epic, incb_state = IncbSt, ri_run = RiRun}.

%% Boundary mask of length `length(Cps) + 1`. Entry `i` is `true` when a
%% grapheme cluster break occurs immediately before position `i` — entry `0` is
%% the GB1 start-of-text break, entry `length(Cps)` the GB2 end-of-text break,
%% both always `true`. Mirrors the Lean `graphemeBreaks`.
-spec grapheme_breaks([non_neg_integer()]) -> [boolean()].
grapheme_breaks(Cps) ->
    grapheme_breaks(Cps, #gstate{}, []).

grapheme_breaks([], _S, Acc) ->
    lists:reverse([true | Acc]);                % GB2: eot div
grapheme_breaks([Cp | Rest], S, Acc) ->
    Break = should_break_before(Cp, S),
    grapheme_breaks(Rest, advance(Cp, S), [Break | Acc]).

%% Split `Cps` into grapheme clusters (the code points between consecutive
%% boundaries). Mirrors the rust `grapheme_clusters`.
-spec grapheme_clusters([non_neg_integer()]) -> [[non_neg_integer()]].
grapheme_clusters(Cps) ->
    Breaks = grapheme_breaks(Cps),
    build_clusters(Cps, Breaks, [], []).

%% `Cur` accumulates the current cluster in reverse; `Out` accumulates finished
%% clusters in reverse. A break before a non-empty current cluster closes it.
build_clusters([], _Breaks, [], Out) ->
    lists:reverse(Out);
build_clusters([], _Breaks, Cur, Out) ->
    lists:reverse([lists:reverse(Cur) | Out]);
build_clusters([Cp | Rest], [Break | BRest], Cur, Out) ->
    case Break andalso Cur =/= [] of
        true ->
            build_clusters(Rest, BRest, [Cp], [lists:reverse(Cur) | Out]);
        false ->
            build_clusters(Rest, BRest, [Cp | Cur], Out)
    end.
