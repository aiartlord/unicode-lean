%%% UCD-table-backed support for the identity-spoofing detector family —
%%% NFC/NFD/NFKC/NFKD normalization, case folding, script lookup, UTS #39
%%% identifier-status / restriction-level classification.  Mirrors
%%% `unicode_python.security.identity.ucd` / `Unicode.Security.Identity`.
%%%
%%% All data is parsed once on first access from the bundled UCD files under
%%% `priv/data/` and memoised via `usec_data:cached/2`.  There is no
%%% catchall fallback: the spec's `@missing` defaults (CCC = 0 for unlisted
%%% codepoints, Bidi_Class L, script Unknown) are written as explicit
%%% branch returns, not silent defaults.  Normalization does NOT delegate to
%%% any built-in `unicode` module; the algorithm is the UAX #15 pipeline
%%% driven by the pinned tables.
-module(usec_ucd).

-export([ccc/1,
         to_nfc/1, to_nfd/1, to_nfkc/1, to_nfkd/1,
         case_fold/1,
         bidi_strong/1, is_strong_rtl/1, is_strong_ltr/1,
         east_asian_width/1,
         script_of/1, resolve_scripts/1, string_script_union/1,
         is_default_ignorable/1, is_white_space/1, is_id_allowed/1,
         is_default_identifier/1, is_allowed_identifier/1,
         is_highly_restrictive/1, is_covered_cjk/1, restriction_level/1]).

-export_type([restriction_level/0, bidi_strong/0, east_asian_width/0]).

-type restriction_level() ::
        ascii_only | single_script | highly_restrictive
      | moderately_restrictive | minimally_restrictive | unrestricted.

-type bidi_strong() :: r | al | l | other.
-type east_asian_width() :: a | f | h | n | na | w.

%% ─────────────────────────────────────────────────────────────────────
%% Line-parsing helpers
%% ─────────────────────────────────────────────────────────────────────

lines(Bin) ->
    [strip_cr(L) || L <- binary:split(Bin, <<"\n">>, [global])].

strip_cr(Line) ->
    case binary:last(safe(Line)) of
        $\r -> binary:part(Line, 0, byte_size(Line) - 1);
        _ -> Line
    end.

safe(<<>>) -> <<0>>;
safe(B) -> B.

strip_comment_and_trim(Line) ->
    Body = case binary:split(Line, <<"#">>) of
               [Before | _] -> Before
           end,
    string:trim(Body).

parse_hex(B) ->
    binary_to_integer(string:trim(B), 16).

parse_range_field(B) ->
    Trim = string:trim(B),
    case binary:split(Trim, <<"..">>) of
        [Single] -> Cp = parse_hex(Single), {Cp, Cp};
        [Lo, Hi] -> {parse_hex(Lo), parse_hex(Hi)}
    end.

hex_tokens(B) ->
    [parse_hex(T) || T <- binary:split(string:trim(B), <<" ">>, [global]),
                     T =/= <<>>].

%% ─────────────────────────────────────────────────────────────────────
%% UnicodeData.txt — CCC + canonical / compatibility decomposition
%% ─────────────────────────────────────────────────────────────────────

ucd_maps() ->
    usec_data:cached(ucd_maps, fun parse_unicode_data/0).

parse_unicode_data() ->
    Ls = lines(usec_data:read_file("UnicodeData.txt")),
    lists:foldl(fun ucd_line/2, {#{}, #{}, #{}}, Ls).

ucd_line(<<>>, Acc) -> Acc;
ucd_line(<<"#", _/binary>>, Acc) -> Acc;
ucd_line(Line, {CccM, CanonM, CompatM} = Acc) ->
    Fields = binary:split(Line, <<";">>, [global]),
    case length(Fields) >= 6 of
        false -> Acc;
        true ->
            Cp = parse_hex(lists:nth(1, Fields)),
            Ccc = binary_to_integer(string:trim(lists:nth(4, Fields))),
            DecompField = string:trim(lists:nth(6, Fields)),
            {Canon, Compat} = parse_decomp(DecompField),
            CccM1 = maps:put(Cp, Ccc, CccM),
            CanonM1 = case Canon of
                          none -> CanonM;
                          _ -> maps:put(Cp, Canon, CanonM)
                      end,
            CompatM1 = case Compat of
                           none -> CompatM;
                           _ -> maps:put(Cp, Compat, CompatM)
                       end,
            {CccM1, CanonM1, CompatM1}
    end.

parse_decomp(<<>>) ->
    {none, none};
parse_decomp(<<"<", _/binary>> = Field) ->
    AfterTag = case binary:split(Field, <<">">>) of
                   [_Tag, Rest] -> Rest;
                   [Only] -> Only
               end,
    case hex_tokens(AfterTag) of
        [] -> {none, none};
        Parts -> {none, Parts}
    end;
parse_decomp(Field) ->
    case hex_tokens(Field) of
        [] -> {none, none};
        Parts -> {Parts, none}
    end.

%% @doc Canonical Combining Class; UAX #44 §5.7.4 default 0 for unlisted.
-spec ccc(non_neg_integer()) -> non_neg_integer().
ccc(Cp) ->
    {CccM, _, _} = ucd_maps(),
    maps:get(Cp, CccM, 0).

canonical_decomp(Cp) ->
    {_, CanonM, _} = ucd_maps(),
    maps:get(Cp, CanonM, none).

compat_decomp(Cp) ->
    {_, _, CompatM} = ucd_maps(),
    maps:get(Cp, CompatM, none).

%% ─────────────────────────────────────────────────────────────────────
%% CompositionExclusions.txt + composition table
%% ─────────────────────────────────────────────────────────────────────

composition_exclusions() ->
    usec_data:cached(exclusions, fun parse_composition_exclusions/0).

parse_composition_exclusions() ->
    Ls = lines(usec_data:read_file("CompositionExclusions.txt")),
    lists:foldl(
      fun(Line, Acc) ->
              case strip_comment_and_trim(Line) of
                  <<>> -> Acc;
                  Stripped -> maps:put(parse_hex(Stripped), true, Acc)
              end
      end, #{}, Ls).

composition_table() ->
    usec_data:cached(comp_table, fun build_composition_table/0).

build_composition_table() ->
    {_, CanonM, _} = ucd_maps(),
    Excl = composition_exclusions(),
    maps:fold(
      fun(Cp, Decomp, Acc) ->
              case Decomp of
                  [A, B] ->
                      case maps:is_key(Cp, Excl) of
                          true -> Acc;
                          false ->
                              case ccc(A) of
                                  0 -> maps:put({A, B}, Cp, Acc);
                                  _ -> Acc
                              end
                      end;
                  _ -> Acc
              end
      end, #{}, CanonM).

comp_lookup(A, B) ->
    maps:get({A, B}, composition_table(), none).

%% ─────────────────────────────────────────────────────────────────────
%% Hangul algorithmic decomposition + composition (UAX #15 §1.3)
%% ─────────────────────────────────────────────────────────────────────

-define(S_BASE, 16#AC00).
-define(L_BASE, 16#1100).
-define(V_BASE, 16#1161).
-define(T_BASE, 16#11A7).
-define(L_COUNT, 19).
-define(V_COUNT, 21).
-define(T_COUNT, 28).
-define(N_COUNT, (?V_COUNT * ?T_COUNT)).
-define(S_COUNT, (?L_COUNT * ?N_COUNT)).

hangul_decompose(Cp) when Cp >= ?S_BASE, Cp < ?S_BASE + ?S_COUNT ->
    SIndex = Cp - ?S_BASE,
    L = ?L_BASE + SIndex div ?N_COUNT,
    V = ?V_BASE + (SIndex rem ?N_COUNT) div ?T_COUNT,
    TIndex = SIndex rem ?T_COUNT,
    case TIndex of
        0 -> [L, V];
        _ -> [L, V, ?T_BASE + TIndex]
    end;
hangul_decompose(_) ->
    none.

hangul_compose(A, B)
  when A >= ?L_BASE, A < ?L_BASE + ?L_COUNT,
       B >= ?V_BASE, B < ?V_BASE + ?V_COUNT ->
    LIndex = A - ?L_BASE,
    VIndex = B - ?V_BASE,
    ?S_BASE + (LIndex * ?V_COUNT + VIndex) * ?T_COUNT;
hangul_compose(A, B)
  when A >= ?S_BASE, A < ?S_BASE + ?S_COUNT,
       (A - ?S_BASE) rem ?T_COUNT =:= 0,
       B >= ?T_BASE + 1, B < ?T_BASE + ?T_COUNT ->
    A + (B - ?T_BASE);
hangul_compose(_, _) ->
    none.

%% ─────────────────────────────────────────────────────────────────────
%% Decomposition, canonical reordering, composition
%% ─────────────────────────────────────────────────────────────────────

decompose_one(Cp) ->
    case hangul_decompose(Cp) of
        none ->
            case canonical_decomp(Cp) of
                none -> [Cp];
                Children -> lists:append([decompose_one(C) || C <- Children])
            end;
        Hangul -> Hangul
    end.

canonical_decompose(Cps) ->
    lists:append([decompose_one(Cp) || Cp <- Cps]).

compat_decompose_one(Cp) ->
    case hangul_decompose(Cp) of
        none ->
            case compat_decomp(Cp) of
                none ->
                    case canonical_decomp(Cp) of
                        none -> [Cp];
                        Children ->
                            lists:append([compat_decompose_one(C) || C <- Children])
                    end;
                Children ->
                    lists:append([compat_decompose_one(C) || C <- Children])
            end;
        Hangul -> Hangul
    end.

compat_decompose(Cps) ->
    lists:append([compat_decompose_one(Cp) || Cp <- Cps]).

canonical_reorder(Seq) ->
    reorder_walk(Seq, []).

reorder_walk([], Acc) ->
    lists:reverse(Acc);
reorder_walk([Cp | Rest], Acc) ->
    case ccc(Cp) of
        0 -> reorder_walk(Rest, [Cp | Acc]);
        _ ->
            {Run, Rest2} = take_nonstarters([Cp | Rest], []),
            Sorted = stable_sort_run(Run),
            reorder_walk(Rest2, lists:reverse(Sorted, Acc))
    end.

take_nonstarters([Cp | Rest] = All, Acc) ->
    case ccc(Cp) of
        0 -> {lists:reverse(Acc), All};
        _ -> take_nonstarters(Rest, [Cp | Acc])
    end;
take_nonstarters([], Acc) ->
    {lists:reverse(Acc), []}.

stable_sort_run(Cps) ->
    Tagged = lists:zip(lists:seq(1, length(Cps)), Cps),
    Sorted = lists:sort(
               fun({I1, C1}, {I2, C2}) ->
                       {ccc(C1), I1} =< {ccc(C2), I2}
               end, Tagged),
    [Cp || {_I, Cp} <- Sorted].

canonical_compose(Seq) ->
    compose(Seq, [], none, -1).

compose([], Out, _StarterIdx, _LastCcc) ->
    Out;
compose([Cp | Rest], Out, none, LastCcc) ->
    append_step(Cp, ccc(Cp), Rest, Out, none, LastCcc);
compose([Cp | Rest], Out, StarterIdx, LastCcc) ->
    CpCcc = ccc(Cp),
    Starter = lists:nth(StarterIdx + 1, Out),
    Composed = case hangul_compose(Starter, Cp) of
                   none -> comp_lookup(Starter, Cp);
                   H -> H
               end,
    Blocked = LastCcc =/= 0 andalso (CpCcc =:= 0 orelse LastCcc >= CpCcc),
    case (not Blocked) andalso Composed =/= none of
        true ->
            Out2 = set_nth(StarterIdx + 1, Composed, Out),
            compose(Rest, Out2, StarterIdx, LastCcc);
        false ->
            append_step(Cp, CpCcc, Rest, Out, StarterIdx, LastCcc)
    end.

append_step(Cp, 0, Rest, Out, _StarterIdx, _LastCcc) ->
    Out2 = Out ++ [Cp],
    compose(Rest, Out2, length(Out2) - 1, 0);
append_step(Cp, CpCcc, Rest, Out, StarterIdx, _LastCcc) ->
    Out2 = Out ++ [Cp],
    compose(Rest, Out2, StarterIdx, CpCcc).

set_nth(N, Value, List) ->
    set_nth(N, Value, List, []).
set_nth(1, Value, [_ | T], Acc) ->
    lists:reverse(Acc, [Value | T]);
set_nth(N, Value, [H | T], Acc) when N > 1 ->
    set_nth(N - 1, Value, T, [H | Acc]).

-spec to_nfc([non_neg_integer()]) -> [non_neg_integer()].
to_nfc(Cps) ->
    canonical_compose(canonical_reorder(canonical_decompose(Cps))).

-spec to_nfd([non_neg_integer()]) -> [non_neg_integer()].
to_nfd(Cps) ->
    canonical_reorder(canonical_decompose(Cps)).

-spec to_nfkd([non_neg_integer()]) -> [non_neg_integer()].
to_nfkd(Cps) ->
    canonical_reorder(compat_decompose(Cps)).

-spec to_nfkc([non_neg_integer()]) -> [non_neg_integer()].
to_nfkc(Cps) ->
    canonical_compose(to_nfkd(Cps)).

%% ─────────────────────────────────────────────────────────────────────
%% CaseFolding.txt — default full case folding (status C ∪ F)
%% ─────────────────────────────────────────────────────────────────────

case_folding_table() ->
    usec_data:cached(case_folding, fun parse_case_folding/0).

parse_case_folding() ->
    Ls = lines(usec_data:read_file("CaseFolding.txt")),
    lists:foldl(fun case_folding_line/2, #{}, Ls).

case_folding_line(Line, Acc) ->
    case strip_comment_and_trim(Line) of
        <<>> -> Acc;
        Stripped ->
            Parts = [string:trim(P) || P <- binary:split(Stripped, <<";">>, [global])],
            case Parts of
                [SrcB, Status, TgtB | _] when Status =:= <<"C">>; Status =:= <<"F">> ->
                    case hex_tokens(TgtB) of
                        [] -> Acc;
                        Tgt -> maps:put(parse_hex(SrcB), Tgt, Acc)
                    end;
                _ -> Acc
            end
    end.

-spec case_fold([non_neg_integer()]) -> [non_neg_integer()].
case_fold(Cps) ->
    Table = case_folding_table(),
    lists:append([maps:get(Cp, Table, [Cp]) || Cp <- Cps]).

%% ─────────────────────────────────────────────────────────────────────
%% DerivedBidiClass.txt — strong Bidi_Class lookup
%% ─────────────────────────────────────────────────────────────────────

bidi_table() ->
    usec_data:cached(bidi_table, fun parse_derived_bidi/0).

parse_derived_bidi() ->
    Ls = lines(usec_data:read_file("DerivedBidiClass.txt")),
    {Explicit, Defaults} = lists:foldl(fun bidi_line/2, {[], []}, Ls),
    Sorted = lists:sort(fun({Lo1, _, _}, {Lo2, _, _}) -> Lo1 =< Lo2 end,
                        lists:reverse(Explicit)),
    {Sorted, lists:reverse(Defaults)}.

bidi_line(<<"# @missing:", Rest/binary>>, {Explicit, Defaults}) ->
    case binary:split(Rest, <<";">>) of
        [RangeB, ClassB] ->
            {Lo, Hi} = parse_range_field(RangeB),
            {Explicit, [{Lo, Hi, strong_of_long(string:trim(ClassB))} | Defaults]};
        _ -> {Explicit, Defaults}
    end;
bidi_line(Line, {Explicit, Defaults} = Acc) ->
    case strip_comment_and_trim(Line) of
        <<>> -> Acc;
        Body ->
            case binary:split(Body, <<";">>) of
                [RangeB, ClassB] ->
                    {Lo, Hi} = parse_range_field(RangeB),
                    {[{Lo, Hi, strong_of_short(string:trim(ClassB))} | Explicit],
                     Defaults};
                _ -> Acc
            end
    end.

strong_of_short(<<"R">>) -> r;
strong_of_short(<<"AL">>) -> al;
strong_of_short(<<"L">>) -> l;
strong_of_short(_) -> other.

strong_of_long(<<"Right_To_Left">>) -> r;
strong_of_long(<<"Arabic_Letter">>) -> al;
strong_of_long(<<"Left_To_Right">>) -> l;
strong_of_long(_) -> other.

%% ─────────────────────────────────────────────────────────────────────
%% EastAsianWidth.txt — UAX #11 East_Asian_Width lookup
%% ─────────────────────────────────────────────────────────────────────

eaw_table() ->
    usec_data:cached(east_asian_width_table, fun parse_east_asian_width/0).

parse_east_asian_width() ->
    Ls = lines(usec_data:read_file("EastAsianWidth.txt")),
    Rows = lists:foldl(fun eaw_line/2, [], Ls),
    lists:sort(fun({Lo1, _, _}, {Lo2, _, _}) -> Lo1 =< Lo2 end, lists:reverse(Rows)).

eaw_line(Line, Acc) ->
    case strip_comment_and_trim(Line) of
        <<>> -> Acc;
        Body ->
            case binary:split(Body, <<";">>) of
                [RangeB, ClassB] ->
                    {Lo, Hi} = parse_range_field(RangeB),
                    [{Lo, Hi, eaw_of_token(string:trim(ClassB))} | Acc];
                _ -> Acc
            end
    end.

eaw_of_token(<<"A">>) -> a;
eaw_of_token(<<"F">>) -> f;
eaw_of_token(<<"H">>) -> h;
eaw_of_token(<<"Na">>) -> na;
eaw_of_token(<<"W">>) -> w;
eaw_of_token(_) -> n.

%% East_Asian_Width for one codepoint. The file's @missing line declares N over
%% the whole space, so an unlisted codepoint is Neutral.
-spec east_asian_width(non_neg_integer()) -> east_asian_width().
east_asian_width(Cp) ->
    find_eaw(eaw_table(), Cp).

find_eaw([], _Cp) -> n;
find_eaw([{Lo, Hi, Class} | _], Cp) when Cp >= Lo, Cp =< Hi -> Class;
find_eaw([_ | T], Cp) -> find_eaw(T, Cp).

-spec bidi_strong(non_neg_integer()) -> bidi_strong().
bidi_strong(Cp) ->
    {Explicit, Defaults} = bidi_table(),
    case find_explicit_bidi(Explicit, Cp) of
        {ok, Class} -> Class;
        none -> last_default_bidi(Defaults, Cp, l)
    end.

find_explicit_bidi([], _Cp) -> none;
find_explicit_bidi([{Lo, Hi, Class} | _], Cp) when Cp >= Lo, Cp =< Hi -> {ok, Class};
find_explicit_bidi([_ | T], Cp) -> find_explicit_bidi(T, Cp).

last_default_bidi([], _Cp, Result) -> Result;
last_default_bidi([{Lo, Hi, Class} | T], Cp, _Result) when Cp >= Lo, Cp =< Hi ->
    last_default_bidi(T, Cp, Class);
last_default_bidi([_ | T], Cp, Result) ->
    last_default_bidi(T, Cp, Result).

-spec is_strong_rtl(non_neg_integer()) -> boolean().
is_strong_rtl(Cp) ->
    case bidi_strong(Cp) of
        r -> true;
        al -> true;
        _ -> false
    end.

-spec is_strong_ltr(non_neg_integer()) -> boolean().
is_strong_ltr(Cp) ->
    bidi_strong(Cp) =:= l.

%% ─────────────────────────────────────────────────────────────────────
%% PropertyValueAliases.txt — Script long-name → 4-letter abbreviation
%% ─────────────────────────────────────────────────────────────────────

script_name_to_abbrev() ->
    usec_data:cached(script_alias, fun parse_script_name_to_abbrev/0).

parse_script_name_to_abbrev() ->
    Ls = lines(usec_data:read_file("PropertyValueAliases.txt")),
    lists:foldl(
      fun(Line, Acc) ->
              case strip_comment_and_trim(Line) of
                  <<>> -> Acc;
                  Stripped ->
                      Parts = [string:trim(P)
                               || P <- binary:split(Stripped, <<";">>, [global])],
                      case Parts of
                          [<<"sc">>, Short, Long | _] ->
                              maps:put(Long, Short, Acc);
                          _ -> Acc
                      end
              end
      end, #{}, Ls).

script_long_to_abbrev(Name) ->
    Table = script_name_to_abbrev(),
    case maps:find(Name, Table) of
        {ok, Short} -> Short;
        error -> error({script_long_to_abbrev_missing, Name})
    end.

%% ─────────────────────────────────────────────────────────────────────
%% Scripts.txt — codepoint → primary script (long name)
%% ─────────────────────────────────────────────────────────────────────

scripts_table() ->
    usec_data:cached(scripts, fun parse_scripts/0).

parse_scripts() ->
    Ls = lines(usec_data:read_file("Scripts.txt")),
    Ranges = lists:foldl(
               fun(Line, Acc) ->
                       case strip_comment_and_trim(Line) of
                           <<>> -> Acc;
                           Stripped ->
                               case binary:split(Stripped, <<";">>) of
                                   [RangeB, ValueB] ->
                                       {Lo, Hi} = parse_range_field(RangeB),
                                       [{Lo, Hi, string:trim(ValueB)} | Acc];
                                   _ -> Acc
                               end
                       end
               end, [], Ls),
    lists:sort(fun({Lo1, _, _}, {Lo2, _, _}) -> Lo1 =< Lo2 end, Ranges).

-spec script_of(non_neg_integer()) -> binary().
script_of(Cp) ->
    find_range_value(scripts_table(), Cp, <<"Unknown">>).

find_range_value([], _Cp, Default) -> Default;
find_range_value([{Lo, Hi, Value} | _], Cp, _Default) when Cp >= Lo, Cp =< Hi -> Value;
find_range_value([_ | T], Cp, Default) -> find_range_value(T, Cp, Default).

%% ─────────────────────────────────────────────────────────────────────
%% ScriptExtensions.txt — codepoint → multi-script abbreviation list
%% ─────────────────────────────────────────────────────────────────────

script_extensions_table() ->
    usec_data:cached(script_ext, fun parse_script_extensions/0).

parse_script_extensions() ->
    Ls = lines(usec_data:read_file("ScriptExtensions.txt")),
    Ranges = lists:foldl(
               fun(Line, Acc) ->
                       case strip_comment_and_trim(Line) of
                           <<>> -> Acc;
                           Stripped ->
                               case binary:split(Stripped, <<";">>) of
                                   [RangeB, ValueB] ->
                                       {Lo, Hi} = parse_range_field(RangeB),
                                       Scripts = [S || S <- binary:split(
                                                              string:trim(ValueB),
                                                              <<" ">>, [global]),
                                                       S =/= <<>>],
                                       case Scripts of
                                           [] -> Acc;
                                           _ -> [{Lo, Hi, Scripts} | Acc]
                                       end;
                                   _ -> Acc
                               end
                       end
               end, [], Ls),
    lists:sort(fun({Lo1, _, _}, {Lo2, _, _}) -> Lo1 =< Lo2 end, Ranges).

-spec resolve_scripts(non_neg_integer()) -> [binary()].
resolve_scripts(Cp) ->
    case find_range_value(script_extensions_table(), Cp, none) of
        none -> fallback_scripts(script_long_to_abbrev(script_of(Cp)));
        Scripts -> Scripts
    end.

%% The abbreviations the resolver can name are those occurring in
%% ScriptExtensions.txt. Unicode/ResolvedScripts.lean models the same set as its
%% ScriptAbbrev enum, which is why its scriptToAbbrev is partial over Script. A
%% codepoint whose primary script falls outside this set resolves to no
%% abbreviation on both sides; returning a singleton instead would make every
%% unknown-script codepoint look Single-Script, putting restriction_level one
%% rung too strict and hiding RestrictionLow.
-spec fallback_scripts(binary()) -> [binary()].
fallback_scripts(Abbrev) ->
    case lists:member(Abbrev, script_extension_abbrevs()) of
        true -> [Abbrev];
        false -> []
    end.

-spec script_extension_abbrevs() -> [binary()].
script_extension_abbrevs() ->
    lists:usort(
      lists:flatmap(fun({_Lo, _Hi, Scripts}) -> Scripts end,
                    script_extensions_table())).

is_common_script(Cp) -> script_of(Cp) =:= <<"Common">>.
is_inherited_script(Cp) -> script_of(Cp) =:= <<"Inherited">>.

is_ignored_for_intersection(Cp) ->
    is_common_script(Cp) orelse is_inherited_script(Cp).

-spec string_script_union([non_neg_integer()]) -> [binary()].
string_script_union(Cps) ->
    lists:foldl(
      fun(Cp, Acc) ->
              case is_ignored_for_intersection(Cp) of
                  true -> Acc;
                  false ->
                      lists:foldl(
                        fun(S, A) ->
                                case lists:member(S, A) of
                                    true -> A;
                                    false -> A ++ [S]
                                end
                        end, Acc, resolve_scripts(Cp))
              end
      end, [], Cps).

%% ─────────────────────────────────────────────────────────────────────
%% IdentifierStatus.txt — UTS #39 General-Security-Profile Allowed set
%% ─────────────────────────────────────────────────────────────────────

id_allowed_ranges() ->
    usec_data:cached(id_allowed, fun parse_identifier_status/0).

parse_identifier_status() ->
    Ls = lines(usec_data:read_file("IdentifierStatus.txt")),
    Ranges = lists:foldl(
               fun(Line, Acc) ->
                       case strip_comment_and_trim(Line) of
                           <<>> -> Acc;
                           Stripped ->
                               case binary:split(Stripped, <<";">>) of
                                   [RangeB, StatusB] ->
                                       case string:trim(StatusB) of
                                           <<"Allowed">> ->
                                               [parse_range_field(RangeB) | Acc];
                                           _ -> Acc
                                       end;
                                   _ -> Acc
                               end
                       end
               end, [], Ls),
    lists:sort(fun({Lo1, _}, {Lo2, _}) -> Lo1 =< Lo2 end, Ranges).

-spec is_id_allowed(non_neg_integer()) -> boolean().
is_id_allowed(Cp) ->
    in_ranges(id_allowed_ranges(), Cp).

in_ranges([], _Cp) -> false;
in_ranges([{Lo, Hi} | _], Cp) when Cp >= Lo, Cp =< Hi -> true;
in_ranges([_ | T], Cp) -> in_ranges(T, Cp).

%% ─────────────────────────────────────────────────────────────────────
%% DerivedCoreProperties.txt — Default_Ignorable_Code_Point ranges
%% ─────────────────────────────────────────────────────────────────────

default_ignorable_ranges() ->
    usec_data:cached(default_ignorable, fun parse_default_ignorable/0).

parse_default_ignorable() ->
    Ls = lines(usec_data:read_file("DerivedCoreProperties.txt")),
    Ranges = lists:foldl(
               fun(Line, Acc) ->
                       case strip_comment_and_trim(Line) of
                           <<>> -> Acc;
                           Stripped ->
                               case binary:split(Stripped, <<";">>) of
                                   [RangeB, PropB] ->
                                       case string:trim(PropB) of
                                           <<"Default_Ignorable_Code_Point">> ->
                                               [parse_range_field(RangeB) | Acc];
                                           _ -> Acc
                                       end;
                                   _ -> Acc
                               end
                       end
               end, [], Ls),
    lists:sort(fun({Lo1, _}, {Lo2, _}) -> Lo1 =< Lo2 end, Ranges).

-spec is_default_ignorable(non_neg_integer()) -> boolean().
is_default_ignorable(Cp) ->
    in_ranges(default_ignorable_ranges(), Cp).

%% ─────────────────────────────────────────────────────────────────────
%% DerivedCoreProperties.txt — XID_Start / XID_Continue ranges
%%
%% UAX #31 default-identifier machinery + UTS #39 whole-string admissibility,
%% mirroring `Unicode.Identifier'. XID_Start / XID_Continue are parsed from the
%% same bundled DerivedCoreProperties.txt the Default_Ignorable ranges come
%% from, using the same range-per-property extraction; `is_id_allowed/1' (above)
%% supplies the per-codepoint UTS #39 Identifier_Status = Allowed test.
%% ─────────────────────────────────────────────────────────────────────

%% @doc Ranges of every codepoint carrying derived-core property `Name' in
%% DerivedCoreProperties.txt, sorted by lower bound. `Name' is the exact
%% property token as it appears in field 2 (e.g. `<<"XID_Start">>').
parse_derived_core_ranges(Name) ->
    Ls = lines(usec_data:read_file("DerivedCoreProperties.txt")),
    Ranges = lists:foldl(
               fun(Line, Acc) ->
                       case strip_comment_and_trim(Line) of
                           <<>> -> Acc;
                           Stripped ->
                               case binary:split(Stripped, <<";">>) of
                                   [RangeB, PropB] ->
                                       case string:trim(PropB) of
                                           Name -> [parse_range_field(RangeB) | Acc];
                                           _ -> Acc
                                       end;
                                   _ -> Acc
                               end
                       end
               end, [], Ls),
    lists:sort(fun({Lo1, _}, {Lo2, _}) -> Lo1 =< Lo2 end, Ranges).

xid_start_ranges() ->
    usec_data:cached(xid_start, fun() -> parse_derived_core_ranges(<<"XID_Start">>) end).

xid_continue_ranges() ->
    usec_data:cached(xid_continue, fun() -> parse_derived_core_ranges(<<"XID_Continue">>) end).

is_xid_start(Cp) -> in_ranges(xid_start_ranges(), Cp).

is_xid_continue(Cp) -> in_ranges(xid_continue_ranges(), Cp).

%% @doc UAX #31 default identifier start: `XID_Start' or `U+005F LOW LINE'.
is_default_id_start(Cp) -> is_xid_start(Cp) orelse Cp =:= 16#005F.

%% @doc UAX #31 default identifier continue: `XID_Continue'.
is_default_id_continue(Cp) -> is_xid_continue(Cp).

%% @doc True iff `Cps' is a well-formed UAX #31 default identifier: a non-empty
%% sequence whose first codepoint is a default-id start and whose remaining
%% codepoints are default-id continues. The empty sequence is not an identifier.
-spec is_default_identifier([non_neg_integer()]) -> boolean().
is_default_identifier([]) -> false;
is_default_identifier([First | Rest]) ->
    is_default_id_start(First)
        andalso lists:all(fun(Cp) -> is_default_id_continue(Cp) end, Rest).

%% @doc True iff `Cps' is a well-formed default identifier AND every codepoint
%% has `Identifier_Status = Allowed' per UTS #39 — the whole-string
%% admissibility predicate `isAllowedIdentifier'. Reuses `is_id_allowed/1'.
-spec is_allowed_identifier([non_neg_integer()]) -> boolean().
is_allowed_identifier(Cps) ->
    is_default_identifier(Cps)
        andalso lists:all(fun(Cp) -> is_id_allowed(Cp) end, Cps).

-spec is_white_space(non_neg_integer()) -> boolean().
is_white_space(Cp) ->
    (Cp >= 16#0009 andalso Cp =< 16#000D)
        orelse Cp =:= 16#0020
        orelse Cp =:= 16#0085
        orelse Cp =:= 16#00A0
        orelse Cp =:= 16#1680
        orelse (Cp >= 16#2000 andalso Cp =< 16#200A)
        orelse (Cp >= 16#2028 andalso Cp =< 16#2029)
        orelse Cp =:= 16#202F
        orelse Cp =:= 16#205F
        orelse Cp =:= 16#3000.

%% ─────────────────────────────────────────────────────────────────────
%% UTS #39 §5.1 Restriction-level classification
%% ─────────────────────────────────────────────────────────────────────

is_ascii_only(Cps) ->
    lists:all(fun(Cp) -> Cp < 16#80 end, Cps).

intersect_many([]) -> [];
intersect_many([First | Rest]) ->
    lists:foldl(
      fun(S, Acc) -> [X || X <- Acc, lists:member(X, S)] end, First, Rest).

string_resolved_scripts(Cps) ->
    NonIgnored = [Cp || Cp <- Cps, not is_ignored_for_intersection(Cp)],
    case NonIgnored of
        [] -> [];
        _ -> intersect_many([resolve_scripts(Cp) || Cp <- NonIgnored])
    end.

is_single_script(Cps) ->
    (not is_ascii_only(Cps)) andalso length(string_resolved_scripts(Cps)) > 0.

covered_japanese() -> [<<"Latn">>, <<"Hani">>, <<"Hira">>, <<"Kana">>].
covered_chinese() -> [<<"Latn">>, <<"Hani">>, <<"Bopo">>].
covered_korean() -> [<<"Latn">>, <<"Hani">>, <<"Hang">>].

intersects(A, B) ->
    lists:any(fun(X) -> lists:member(X, B) end, A).

all_within_covered(Cps, Covered) ->
    lists:all(
      fun(Cp) ->
              case is_ignored_for_intersection(Cp) of
                  true -> true;
                  false ->
                      R = resolve_scripts(Cp),
                      R =/= [] andalso intersects(R, Covered)
              end
      end, Cps).

is_covered_cjk(Cps) ->
    all_within_covered(Cps, covered_japanese())
        orelse all_within_covered(Cps, covered_chinese())
        orelse all_within_covered(Cps, covered_korean()).

-spec is_highly_restrictive([non_neg_integer()]) -> boolean().
is_highly_restrictive(Cps) ->
    is_single_script(Cps) orelse is_covered_cjk(Cps).

is_moderately_restrictive_shape(Cps) ->
    mod_shape(Cps, none).

mod_shape([], Other) ->
    Other =/= none;
mod_shape([Cp | Rest], Other) ->
    case is_ignored_for_intersection(Cp) of
        true -> mod_shape(Rest, Other);
        false ->
            case resolve_scripts(Cp) of
                [] -> false;
                R ->
                    case lists:member(<<"Latn">>, R) of
                        true -> mod_shape(Rest, Other);
                        false ->
                            S = hd(R),
                            case S of
                                <<"Cyrl">> -> false;
                                <<"Grek">> -> false;
                                _ ->
                                    case Other of
                                        none -> mod_shape(Rest, S);
                                        S -> mod_shape(Rest, Other);
                                        _ -> false
                                    end
                            end
                    end
            end
    end.

is_minimally_restrictive(Cps) ->
    lists:all(fun(Cp) -> is_id_allowed(Cp) end, Cps).

-spec restriction_level([non_neg_integer()]) -> restriction_level().
restriction_level(Cps) ->
    case is_ascii_only(Cps) of
        true -> ascii_only;
        false ->
            case is_single_script(Cps) of
                true -> single_script;
                false ->
                    case is_highly_restrictive(Cps) of
                        true -> highly_restrictive;
                        false ->
                            case is_moderately_restrictive_shape(Cps) of
                                true -> moderately_restrictive;
                                false ->
                                    case is_minimally_restrictive(Cps) of
                                        true -> minimally_restrictive;
                                        false -> unrestricted
                                    end
                            end
                    end
            end
    end.
