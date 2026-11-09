%% UAX #14 default line breaking.
%%
%% A transcription of the Lean algorithm
%% `Unicode.Segmentation.LineBreak.lineBreaks', whose `lineBreaks_length'
%% theorem fixes the output shape: one break-opportunity flag per boundary
%% position. The rule order, rule bodies and snapshot fields below mirror that
%% reference -- LB2 through LB31 in UAX #14 R7's canonical order, first match
%% winning, the trailing LB31 breaking every otherwise-unmatched pair.
%%
%% Where a line may break is a property of a sequence rather than of a code
%% point, so the entry point returns a flag per boundary instead of a
%% predicate over code points.
%%
%% Three mechanisms carry the context the rules read:
%%
%%   * LB1 is applied at lookup time by `resolved_class/1', which folds the
%%     tailorable AI, CJ, SA, SG and XX into the algorithm's working alphabet.
%%     SA needs General_Category to choose between CM and AL.
%%   * LB9 -- treat X CM* / X ZWJ* as X -- is realised through the `lbstate'
%%     record, whose fields hold the most recent class that was not CM or ZWJ.
%%     LB10, treating a leftover CM or ZWJ as AL, is the fallback taken when no
%%     such class exists.
%%   * The rules naming a third character -- LB15b, LB15c, the LB25 bracket and
%%     the fourth LB28a sub-rule -- read the suffix beginning at the position
%%     being decided.
%%
%% Two departures from the Lean. Its positional reads are `lits[i]!' and
%% `cps[i]!', panicking accessors; here every read comes from a suffix the
%% caller already holds, so each one is total. And its `spSinceNoSp' snapshot
%% field is written by its fold and read by no rule, so this port omits it.
%%
%% Code points are handled as integer lists.
-module(usec_line_break).

-export([raw_class/1, resolved_class/1, category_of/1, width_of/1,
         is_ext_pict/1, line_breaks/1, line_runs/1]).

%% U+2010 HYPHEN, which LB20a and LB21a name explicitly because UCD 17.0 moved
%% it from class HY to class HH.
-define(HYPHEN_U2010, 16#2010).

%% U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster base.
-define(DOTTED_CIRCLE, 16#25CC).

%% The left-hand context a boundary decision reads: the classes and code points
%% of the most recent characters LB9 did not absorb, plus the running counters
%% the rules keep. Mirrors the Lean `EffSnapshot'. The atom `none' is the
%% absent-neighbour sentinel; no property table assigns it, so it is
%% unambiguous.
-record(lbstate, {eff_prev = none :: atom(),
                  eff_prev_cp = none :: non_neg_integer() | none,
                  eff_prev_no_sp = none :: atom(),
                  eff_prev_prev = none :: atom(),
                  eff_prev_prev_cp = none :: non_neg_integer() | none,
                  in_pi_quote_window = false :: boolean(),
                  ri_run = 0 :: non_neg_integer(),
                  in_nu_chain = false :: boolean()}).

%% ── property lookups ──────────────────────────────────────────────────────
%%
%% Each table is sorted by first code point and its ranges are disjoint, so the
%% covering range is unique and a bisection finds it. The tables are tuples so
%% element/2 indexes them in constant time.

bisect_class(Table, Cp, Default) ->
    bisect_class(Table, Cp, Default, 1, tuple_size(Table) + 1).

bisect_class(_Table, _Cp, Default, Low, High) when Low >= High ->
    Default;
bisect_class(Table, Cp, Default, Low, High) ->
    Mid = Low + (High - Low) div 2,
    {First, Last, Class} = element(Mid, Table),
    if
        Cp < First ->
            bisect_class(Table, Cp, Default, Low, Mid);
        Cp > Last ->
            bisect_class(Table, Cp, Default, Mid + 1, High);
        true ->
            Class
    end.

bisect_member(Table, Cp) ->
    bisect_member(Table, Cp, 1, tuple_size(Table) + 1).

bisect_member(_Table, _Cp, Low, High) when Low >= High ->
    false;
bisect_member(Table, Cp, Low, High) ->
    Mid = Low + (High - Low) div 2,
    {First, Last} = element(Mid, Table),
    if
        Cp < First ->
            bisect_member(Table, Cp, Low, Mid);
        Cp > Last ->
            bisect_member(Table, Cp, Mid + 1, High);
        true ->
            true
    end.

%% Line_Break class of `Cp' before LB1. A code point no range covers is xx,
%% the default LineBreak.txt declares in its own
%% `@missing: 0000..10FFFF; XX' header.
-spec raw_class(non_neg_integer()) -> atom().
raw_class(Cp) ->
    bisect_class(usec_line_break_tables:lb_ranges(), Cp, xx).

%% General_Category of `Cp', cn when no range covers it -- the default
%% UnicodeData.txt declares for unassigned code points.
-spec category_of(non_neg_integer()) -> atom().
category_of(Cp) ->
    bisect_class(usec_line_break_tables:gc_ranges(), Cp, cn).

%% East_Asian_Width of `Cp', n when the file omits it.
-spec width_of(non_neg_integer()) -> atom().
width_of(Cp) ->
    bisect_class(usec_line_break_tables:eaw_ranges(), Cp, n).

%% Whether `Cp' carries the Extended_Pictographic property, which LB30b reads.
-spec is_ext_pict(non_neg_integer()) -> boolean().
is_ext_pict(Cp) ->
    bisect_member(usec_line_break_tables:extpict_ranges(), Cp).

%% Line_Break class `Cp' carries once LB1 has tailored it.
%%
%% AI, SG and XX resolve to AL; CJ to NS; SA to CM when the code point is a
%% non-spacing or spacing combining mark and to AL otherwise. Every other class
%% is already in the working alphabet.
-spec resolved_class(non_neg_integer()) -> atom().
resolved_class(Cp) ->
    case raw_class(Cp) of
        ai ->
            al;
        sg ->
            al;
        xx ->
            al;
        cj ->
            ns;
        sa ->
            %% LB1 reads only the two combining-mark categories here; an
            %% enclosing mark is not among them.
            case category_of(Cp) of
                mn -> cm;
                mc -> cm;
                _Other -> al
            end;
        Resolved ->
            Resolved
    end.

%% ── class sets the rules name ─────────────────────────────────────────────

%% Whether LB9 absorbs this class into the character before it.
is_cm_zwj(Class) ->
    Class =:= cm orelse Class =:= zwj.

%% Whether a preceding class blocks LB9's absorption, so a following CM or ZWJ
%% stands on its own and LB10 reads it as AL.
blocks_absorb(Class) ->
    lists:member(Class, [bk, cr, lf, nl, sp, zw]).

%% Whether the class is QU and the code point is initial punctuation, the
%% refinement LB15a reads.
is_pi_quote(Cp, Class) ->
    Class =:= qu andalso category_of(Cp) =:= pi.

%% Whether the class is QU and the code point is final punctuation, the
%% refinement LB15b reads.
is_pf_quote(Cp, Class) ->
    Class =:= qu andalso category_of(Cp) =:= pf.

%% Whether `Cp' is East_Asian_Width F, W or H, the set LB25 and LB30 read.
is_east_asian_full_wide(Cp) ->
    lists:member(width_of(Cp), [f, w, h]).

%% Whether `Cp' counts as East Asian for LB19a's tailoring, which treats
%% Ambiguous as East Asian alongside Fullwidth, Wide and Halfwidth. Wider than
%% is_east_asian_full_wide/1.
is_east_asian_or_ambiguous(Cp) ->
    lists:member(width_of(Cp), [f, w, h, a]).

%% Whether the effective class is present and among `Classes'.
eff_in(none, _Classes) ->
    false;
eff_in(Class, Classes) ->
    lists:member(Class, Classes).

%% The class a CM or ZWJ takes from what it attaches to under LB9, or AL under
%% LB10 when nothing absorbs it.
effective_class(Class, EffPrev) ->
    case is_cm_zwj(Class) of
        false ->
            Class;
        true ->
            if
                EffPrev =:= none -> al;
                true ->
                    case blocks_absorb(EffPrev) of
                        true -> al;
                        false -> Class
                    end
            end
    end.

%% One character folded into the context. A character LB9 absorbs leaves the
%% context untouched, which is what makes the neighbours it records effective
%% rather than literal. Mirrors the Lean `buildSnapshots' step.
advance(Cp, Class, S) ->
    Effective = effective_class(Class, S#lbstate.eff_prev),
    case is_cm_zwj(Effective) of
        true ->
            S;
        false ->
            #lbstate{eff_prev = Effective,
                     eff_prev_cp = Cp,
                     eff_prev_no_sp =
                         case Effective of
                             sp -> S#lbstate.eff_prev_no_sp;
                             _Other -> Effective
                         end,
                     eff_prev_prev = S#lbstate.eff_prev,
                     eff_prev_prev_cp = S#lbstate.eff_prev_cp,
                     in_pi_quote_window = quote_window(Cp, Effective, S),
                     ri_run =
                         case Effective of
                             ri -> S#lbstate.ri_run + 1;
                             _Other2 -> 0
                         end,
                     in_nu_chain = numeric_chain(Effective, S)}
    end.

%% LB15a opens its window only where an initial-punctuation quote stands
%% outside a word; a space carries an open window forward.
quote_window(Cp, Effective, S) ->
    LeftContextOpens =
        S#lbstate.eff_prev =:= none orelse
            eff_in(S#lbstate.eff_prev, [bk, cr, lf, nl, op, qu, gl, sp, zw]),
    case is_pi_quote(Cp, Effective) andalso LeftContextOpens of
        true ->
            true;
        false ->
            Effective =:= sp andalso S#lbstate.in_pi_quote_window
    end.

numeric_chain(Effective, S) ->
    if
        Effective =:= nu ->
            true;
        S#lbstate.in_nu_chain ->
            lists:member(Effective, [sy, is, cl, cp, pr]);
        true ->
            false
    end.

%% ── lookahead ─────────────────────────────────────────────────────────────

%% The class at the head of a suffix, or none past its end.
head_class([]) ->
    none;
head_class([{_Cp, Class} | _Rest]) ->
    Class.

%% The code point at the head of a suffix, or none past its end.
head_cp([]) ->
    none;
head_cp([{Cp, _Class} | _Rest]) ->
    Cp.

%% LB15b holds when the final quote is last, or when what follows it cannot
%% itself open a line.
final_quote_closes([]) ->
    true;
final_quote_closes([{_Cp, Class} | _Rest]) ->
    lists:member(Class,
                 [sp, gl, wj, cl, qu, cp, ex, is, sy, bk, cr, lf, nl, zw]).

%% The fourth LB28a sub-rule looks past any CM or ZWJ the cluster absorbs, so
%% the character it tests is the first significant one ahead.
next_significant_vf([]) ->
    false;
next_significant_vf([{_Cp, Class} | Rest]) ->
    case is_cm_zwj(Class) of
        true -> next_significant_vf(Rest);
        false -> Class =:= vf
    end.

%% ── the rule cascade ──────────────────────────────────────────────────────

%% Whether a line break opportunity falls immediately before the head of
%% `Suffix', given the character before it and the context accumulated from
%% everything earlier.
breaks_before(_Prev, [], _S) ->
    true;                                           % LB3
breaks_before({PrevCp, PrevClass}, [{CurrentCp, CurrentClass} | Ahead], S) ->
    Eff = effective_class(CurrentClass, S#lbstate.eff_prev),
    Left =
        case is_cm_zwj(PrevClass) of
            true -> S#lbstate.eff_prev;
            false -> PrevClass
        end,
    %% An `if' clause is a guard, and a guard may not call a function defined
    %% here, so every predicate the cascade tests is bound first and the
    %% cascade itself compares bound values. The order of the rules is
    %% unchanged; only the evaluation of their conditions moves ahead of it.
    HyphenLeftOpens =
        S#lbstate.eff_prev_prev =:= none orelse
            eff_in(S#lbstate.eff_prev_prev, [bk, cr, lf, nl, sp, zw, cb, gl]),
    LeftIsAksaraBase =
        eff_in(Left, [ak, as]) orelse
            (S#lbstate.eff_prev_cp =:= ?DOTTED_CIRCLE andalso
                 S#lbstate.eff_prev =:= al),
    CurrentIsCmZwj = is_cm_zwj(CurrentClass),
    PrevAbsorbs =
        S#lbstate.eff_prev =/= none andalso
            not blocks_absorb(S#lbstate.eff_prev),
    GlueKeepsLeft = not eff_in(Left, [sp, ba, hy, hh]),
    HeadClassAhead = head_class(Ahead),
    PfQuoteCloses =
        is_pf_quote(CurrentCp, Eff) andalso final_quote_closes(Ahead),
    OpenQuoteEastAsian =
        open_quote_east_asian(PrevCp, CurrentCp, Eff, Ahead),
    CloseQuoteEastAsian = close_quote_east_asian(CurrentCp, S),
    HyphenCarriesLeft = hyphen_carries_left(S),
    HyphenHyOr2010 = hyphen_hy_or_2010(S),
    LeftInPrPo = eff_in(Left, [pr, po]),
    LeftInAlHl = eff_in(Left, [al, hl]),
    LeftInIdEbEm = eff_in(Left, [id, eb, em]),
    LeftInNuOpeners = eff_in(Left, [pr, po, hy, op, is]),
    LeftInAlHlNu = eff_in(Left, [al, hl, nu]),
    LeftInJvH2 = eff_in(Left, [jv, h2]),
    LeftInJtH3 = eff_in(Left, [jt, h3]),
    LeftInJamo = eff_in(Left, [jl, jv, jt, h2, h3]),
    PrevPrevInAkAs = eff_in(S#lbstate.eff_prev_prev, [ak, as]),
    CurrentFullWide = is_east_asian_full_wide(CurrentCp),
    PrevFullWide = is_east_asian_full_wide(PrevCp),
    EffPrevFullWide =
        S#lbstate.eff_prev_cp =/= none andalso
            is_east_asian_full_wide(S#lbstate.eff_prev_cp),
    NextSignificantVf = next_significant_vf(Ahead),
    PrevUnassignedPictograph =
        unassigned_pictograph(S#lbstate.eff_prev_cp),
    if
        PrevClass =:= bk ->
            true;                                   % LB4
        PrevClass =:= cr andalso CurrentClass =:= lf ->
            false;                                  % LB5
        PrevClass =:= cr orelse PrevClass =:= lf orelse PrevClass =:= nl ->
            true;                                   % LB5
        CurrentClass =:= bk orelse CurrentClass =:= cr orelse
            CurrentClass =:= lf orelse CurrentClass =:= nl ->
            false;                                  % LB6
        CurrentClass =:= sp orelse CurrentClass =:= zw ->
            false;                                  % LB7
        S#lbstate.eff_prev_no_sp =:= zw ->
            true;                                   % LB8
        PrevClass =:= zwj ->
            false;                                  % LB8a
        CurrentIsCmZwj andalso PrevAbsorbs ->
            false;                                  % LB9
        Eff =:= wj orelse Left =:= wj ->
            false;                                  % LB11
        Left =:= gl ->
            false;                                  % LB12
        Eff =:= gl andalso GlueKeepsLeft ->
            false;                                  % LB12a
        %% LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an
        %% IS that opens a number and follows a space, as in "equals .35".
        PrevClass =:= sp andalso Eff =:= is andalso HeadClassAhead =:= nu ->
            true;
        Eff =:= cl orelse Eff =:= cp orelse Eff =:= ex orelse Eff =:= is
            orelse Eff =:= sy ->
            false;                                  % LB13
        S#lbstate.eff_prev_no_sp =:= op ->
            false;                                  % LB14
        S#lbstate.in_pi_quote_window ->
            false;                                  % LB15a
        PfQuoteCloses ->
            false;                                  % LB15b
        Eff =:= is ->
            false;                                  % LB15d
        Eff =:= ns andalso (S#lbstate.eff_prev_no_sp =:= cl orelse
                            S#lbstate.eff_prev_no_sp =:= cp) ->
            false;                                  % LB16
        Eff =:= b2 andalso S#lbstate.eff_prev_no_sp =:= b2 ->
            false;                                  % LB17
        PrevClass =:= sp ->
            true;                                   % LB18
        %% LB19 and LB19a. A quote neither breaks before nor after, except on
        %% the OUTER side of an initial or final punctuation quote standing in
        %% contiguous East Asian content -- there the default break applies, so
        %% a line may break at the quote boundary. The inner side stays
        %% unbroken, being the boundary inside the quote's own scope.
        Eff =:= qu andalso not OpenQuoteEastAsian ->
            false;
        Left =:= qu andalso not CloseQuoteEastAsian ->
            false;
        Eff =:= cb orelse Left =:= cb ->
            true;                                   % LB20
        %% LB20.1, UCD 17.0: an explicit hyphen joins a following letter only
        %% where its own left context is outside a word. A mid-word HH falls
        %% through to LB31.
        Left =:= hh andalso (Eff =:= al orelse Eff =:= hl) andalso
            HyphenLeftOpens ->
            false;
        (Eff =:= al orelse Eff =:= hl) andalso HyphenCarriesLeft andalso
            HyphenLeftOpens ->
            false;                                  % LB20a
        Eff =:= ba orelse Eff =:= hy orelse Eff =:= hh orelse Eff =:= ns ->
            false;                                  % LB21
        Left =:= bb ->
            false;                                  % LB21
        %% LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what
        %% comes next unless that is itself HL. A BA does not glue here.
        S#lbstate.eff_prev_prev =:= hl andalso Eff =/= hl andalso
            HyphenHyOr2010 ->
            false;
        Eff =:= hl andalso Left =:= sy ->
            false;                                  % LB21b
        Eff =:= in ->
            false;                                  % LB22
        Eff =:= nu andalso LeftInAlHl ->
            false;                                  % LB23
        (Eff =:= al orelse Eff =:= hl) andalso Left =:= nu ->
            false;                                  % LB23
        (Eff =:= id orelse Eff =:= eb orelse Eff =:= em) andalso Left =:= pr ->
            false;                                  % LB23a
        Eff =:= po andalso LeftInIdEbEm ->
            false;                                  % LB23a
        (Eff =:= al orelse Eff =:= hl) andalso LeftInPrPo ->
            false;                                  % LB24
        (Eff =:= pr orelse Eff =:= po) andalso LeftInAlHl ->
            false;                                  % LB24
        %% LB25, closing an open numeric chain with a CL or CP suffix and a
        %% following PO or PR.
        S#lbstate.in_nu_chain andalso
            (Eff =:= cl orelse Eff =:= cp orelse Eff =:= po orelse
                 Eff =:= pr) ->
            false;
        Eff =:= nu andalso LeftInNuOpeners ->
            false;                                  % LB25, opening a chain
        Eff =:= nu andalso Left =:= nu ->
            false;                                  % LB25, chain body
        Eff =:= nu andalso Left =:= sy andalso S#lbstate.in_nu_chain ->
            false;                                  % LB25, across a SY
        %% LB25, bracketed prefix: a PR joins an OP only when the OP itself
        %% opens a number, and neither is East Asian Fullwidth, Wide or
        %% Halfwidth.
        Eff =:= op andalso Left =:= pr andalso
            not CurrentFullWide andalso not EffPrevFullWide andalso
            HeadClassAhead =:= nu ->
            false;
        Left =:= jl andalso (Eff =:= jl orelse Eff =:= jv orelse Eff =:= h2
                             orelse Eff =:= h3) ->
            false;                                  % LB26
        LeftInJvH2 andalso (Eff =:= jv orelse Eff =:= jt) ->
            false;                                  % LB26
        LeftInJtH3 andalso Eff =:= jt ->
            false;                                  % LB26
        LeftInJamo andalso (Eff =:= in orelse Eff =:= po) ->
            false;                                  % LB27
        Left =:= pr andalso (Eff =:= jl orelse Eff =:= jv orelse Eff =:= jt
                             orelse Eff =:= h2 orelse Eff =:= h3) ->
            false;                                  % LB27
        (Eff =:= al orelse Eff =:= hl) andalso LeftInAlHl ->
            false;                                  % LB28
        %% LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class
        %% AL and stands in for a cluster base throughout.
        Left =:= ap andalso (Eff =:= ak orelse Eff =:= as orelse
                             CurrentCp =:= ?DOTTED_CIRCLE) ->
            false;
        LeftIsAksaraBase andalso (Eff =:= vf orelse Eff =:= vi) ->
            false;
        S#lbstate.eff_prev =:= vi andalso
            (PrevPrevInAkAs orelse
                 S#lbstate.eff_prev_prev_cp =:= ?DOTTED_CIRCLE) andalso
            (Eff =:= ak orelse CurrentCp =:= ?DOTTED_CIRCLE) ->
            false;
        LeftIsAksaraBase andalso
            (Eff =:= ak orelse Eff =:= as orelse
                 CurrentCp =:= ?DOTTED_CIRCLE) andalso
            NextSignificantVf ->
            false;
        (Eff =:= al orelse Eff =:= hl) andalso Left =:= is ->
            false;                                  % LB29
        %% LB30, where the bracket must not be East Asian Fullwidth, Wide or
        %% Halfwidth.
        Eff =:= op andalso LeftInAlHlNu andalso not CurrentFullWide ->
            false;
        (Eff =:= al orelse Eff =:= hl orelse Eff =:= nu) andalso
            Left =:= cp andalso not PrevFullWide ->
            false;
        Eff =:= ri andalso (S#lbstate.ri_run rem 2) =:= 1 ->
            false;                                  % LB30a
        Eff =:= em andalso Left =:= eb ->
            false;                                  % LB30b
        Eff =:= em andalso PrevUnassignedPictograph ->
            false;                                  % LB30b
        true ->
            true                                    % LB31
    end.

%% LB19a's outer-side exception on an initial-punctuation quote: the left
%% context, the quote and the right context must all be East Asian.
open_quote_east_asian(PrevCp, CurrentCp, Eff, Ahead) ->
    is_pi_quote(CurrentCp, Eff) andalso
        is_east_asian_or_ambiguous(PrevCp) andalso
        is_east_asian_or_ambiguous(CurrentCp) andalso
        case head_cp(Ahead) of
            none -> false;
            NextCp -> is_east_asian_or_ambiguous(NextCp)
        end.

%% The same exception on a final-punctuation quote, read from the left: the
%% character before the quote, the quote, and the current one.
close_quote_east_asian(CurrentCp, S) ->
    case {S#lbstate.eff_prev_cp, S#lbstate.eff_prev_prev_cp} of
        {none, _Before} ->
            false;
        {_QuoteCp, none} ->
            false;
        {QuoteCp, BeforeQuote} ->
            is_pf_quote(QuoteCp, qu) andalso
                is_east_asian_or_ambiguous(BeforeQuote) andalso
                is_east_asian_or_ambiguous(QuoteCp) andalso
                is_east_asian_or_ambiguous(CurrentCp)
    end.

hyphen_carries_left(S) ->
    eff_in(S#lbstate.eff_prev, [hy, hh]) orelse
        (S#lbstate.eff_prev =/= none andalso
             S#lbstate.eff_prev_cp =:= ?HYPHEN_U2010).

hyphen_hy_or_2010(S) ->
    S#lbstate.eff_prev =:= hy orelse
        (S#lbstate.eff_prev =/= none andalso
             S#lbstate.eff_prev_cp =:= ?HYPHEN_U2010).

unassigned_pictograph(none) ->
    false;
unassigned_pictograph(Cp) ->
    is_ext_pict(Cp) andalso category_of(Cp) =:= cn.

%% ── entry points ──────────────────────────────────────────────────────────

%% One break-opportunity flag per boundary of the code point sequence, so a
%% sequence of n code points yields n + 1 flags -- the shape the Lean
%% `lineBreaks_length' theorem fixes.
%%
%% Entry 0 is false, LB2 forbidding a break at the start of text, and the last
%% entry is true per LB3, which requires one at the end.
-spec line_breaks([non_neg_integer()]) -> [boolean()].
line_breaks(Cps) ->
    Pairs = [{Cp, resolved_class(Cp)} || Cp <- Cps],
    lists:reverse([true | decide(Pairs, none, #lbstate{}, [])]).

%% One decision per position, walking the suffixes so each reads the character
%% before it, the suffix from it onward, and the context accumulated earlier.
%% The suffix is the tail already in hand, so no position is traversed twice.
decide([], _Prev, _S, Acc) ->
    Acc;
decide([{Cp, Class} | Rest] = Suffix, Prev, S, Acc) ->
    Break =
        case Prev of
            none -> false;                          % LB2
            PrevPair -> breaks_before(PrevPair, Suffix, S)
        end,
    decide(Rest, {Cp, Class}, advance(Cp, Class, S), [Break | Acc]).

%% The code point sequence split at every break opportunity -- the runs a
%% renderer may place on separate lines.
-spec line_runs([non_neg_integer()]) -> [[non_neg_integer()]].
line_runs(Cps) ->
    [_First | Breaks] = line_breaks(Cps),
    build_runs(Cps, Breaks, [], []).

build_runs([], _Breaks, [], Out) ->
    lists:reverse(Out);
build_runs([], _Breaks, Cur, Out) ->
    lists:reverse([lists:reverse(Cur) | Out]);
build_runs([Cp | Rest], [Break | BRest], Cur, Out) ->
    case Break of
        true ->
            build_runs(Rest, BRest, [], [lists:reverse([Cp | Cur]) | Out]);
        false ->
            build_runs(Rest, BRest, [Cp | Cur], Out)
    end.
