-module(usec_detectors).

-export([tag_block_detect/1, variation_selector_detect/1, zero_width_detect/1,
         surrogate_reassembly_detect/1, looks_like_byte_stream/1,
         bidi_control_detect/1, is_bidi_format_control/1, opens_embedding/1,
         is_pdf/1, opens_isolate/1, is_pdi/1,
         homoglyph_detect/1, confusable_source/1, mixed_script_admissibility/1, mixed_script_verdict/2,
         mixed_script_subthreat/1, rtl_injection_detect/1,
         rtl_injection_detect_with_context/2,
         confusable_bidi_detect/1, covert_display_detect/1,
         locale_case_detect/1, nfc_witness_detect/1, normalization_bomb_detect/1,
         bip39_detect/1, bip39_canonical/1, sub_tag/1, is_vs/1]).

%% Covert: tag block
tag_block_detect(Input) ->
    Pos = positions(Input, fun(Cp) -> Cp >= 16#E0000 andalso Cp =< 16#E007F end),
    case Pos of
        [] -> #{kind => clear, sub => none, positions => []};
        _ ->
            Decoded = tag_decode(Input, Pos),
            First = hd(Pos),
            FirstCp = lists:nth(First + 1, Input),
            Sub =
                if
                    FirstCp =:= 16#E0001 andalso length(Pos) >= 2 ->
                        Tail = [P || P <- Pos, P =/= First],
                        {language_tag_revival, First, tag_decode(Input, Tail)};
                    length(Input) =:= length(Pos), Decoded =/= <<>> ->
                        {direct_ascii, Decoded};
                    length(Input) > length(Pos) ->
                        {mixed_block, length(Pos), length(Input)};
                    true ->
                        {bare_tag_present, FirstCp}
                end,
            #{kind => hazard, sub => Sub, positions => Pos}
    end.

tag_decode(Input, Pos) ->
    list_to_binary([Cp - 16#E0000 || P <- Pos,
                                      Cp <- [lists:nth(P + 1, Input)],
                                      Cp >= 16#E0020, Cp =< 16#E007E]).

%% Covert: variation selectors
is_vs(Cp) ->
    (Cp >= 16#FE00 andalso Cp =< 16#FE0F)
        orelse (Cp >= 16#E0100 andalso Cp =< 16#E01EF)
        orelse (Cp >= 16#180B andalso Cp =< 16#180D).

vs_nibble(Cp) when Cp >= 16#FE00, Cp =< 16#FE0F -> Cp - 16#FE00;
vs_nibble(Cp) when Cp >= 16#E0100, Cp =< 16#E01EF -> Cp - 16#E0100 + 16;
vs_nibble(_) -> none.

variation_selector_detect(Input) ->
    Pos = positions(Input, fun is_vs/1),
    case Pos of
        [] -> #{kind => clear, sub => none, positions => []};
        [P] ->
            case P > 0 andalso registered_variation_pair(lists:nth(P, Input), lists:nth(P + 1, Input)) of
                true -> #{kind => clear, sub => none, positions => Pos};
                false -> variation_hazard(Input, Pos)
            end;
        _ -> variation_hazard(Input, Pos)
    end.

variation_hazard(Input, Pos) ->
    Bytes = decode_vs(Input, Pos),
    Vals = [lists:nth(P + 1, Input) || P <- Pos],
    Sub =
        case length(Pos) >= 4 andalso length(lists:usort(Vals)) =:= 1 of
            true ->
                P0 = hd(Pos),
                Base = case P0 of 0 -> 0; _ -> lists:nth(P0, Input) end,
                {repeated_base, Base, length(Pos)};
            false ->
                case Bytes of
                    [] ->
                        P = hd(Pos),
                        Target = case P of 0 -> 0; _ -> lists:nth(P, Input) end,
                        {illegal_target, Target, lists:nth(P + 1, Input)};
                    _ ->
                        {direct_payload, lossy_ascii(Bytes)}
                end
        end,
    #{kind => hazard, sub => Sub, positions => Pos}.

decode_vs(Input, Pos) ->
    {BytesRev, _High} =
        lists:foldl(
          fun(P, {Bytes, High}) ->
                  case vs_nibble(lists:nth(P + 1, Input)) of
                      none -> {Bytes, High};
                      N when High =:= none -> {Bytes, N};
                      N -> {[(High bsl 4 bor N) band 16#FF | Bytes], none}
                  end
          end, {[], none}, Pos),
    lists:reverse(BytesRev).

lossy_ascii(Bytes) ->
    list_to_binary([case (B >= 16#20 andalso B =< 16#7E) orelse lists:member(B, [9, 10, 13]) of
                        true -> B;
                        false -> $?
                    end || B <- Bytes]).

registered_variation_pair(Base, Vs) ->
    sets:is_element({Base, Vs}, legal_pairs()).

legal_pairs() ->
    usec_data:cached(variation_legal_pairs, fun parse_legal_pairs/0).

parse_legal_pairs() ->
    lists:foldl(fun(File, Set0) ->
                        lists:foldl(fun(Line, Set) ->
                                            Body = string:trim(hd(binary:split(Line, <<"#">>))),
                                            case Body of
                                                <<>> -> Set;
                                                _ ->
                                                    Pair = hd(binary:split(Body, <<";">>)),
                                                    case [T || T <- binary:split(string:trim(Pair), <<" ">>, [global]), T =/= <<>>] of
                                                        [B, V | _] -> sets:add_element({binary_to_integer(B, 16), binary_to_integer(V, 16)}, Set);
                                                        _ -> Set
                                                    end
                                            end
                                    end, Set0, lines(usec_data:read_file(File)))
                end, sets:new(), ["StandardizedVariants.txt", "emoji-variation-sequences.txt"]).

%% Covert: zero-width
zero_width_detect(Input) ->
    Pos = positions(Input, fun zero_width/1),
    %% The sanctioning model: a ZWJ inside a registered emoji sequence and a
    %% ZWNJ in an RFC 5892 CONTEXTJ-valid position both carry meaning a reader
    %% depends on, so they are recorded as present but not treated as
    %% suspicious.
    Susp = [P || P <- Pos, not sanctioned_zero_width(Input, P)],
    case {Pos, Susp} of
        {[], _} -> #{kind => clear, sub => none, positions => []};
        {_, []} -> #{kind => clear, sub => none, positions => Pos};
        _ ->
            Cps = [lists:nth(P + 1, Input) || P <- Pos],
            SuspCps = [lists:nth(P + 1, Input) || P <- Susp],
            Ann = count(Cps, fun(Cp) -> Cp >= 16#FFF9 andalso Cp =< 16#FFFB end),
            Wj = count(Cps, fun(Cp) -> Cp =:= 16#2060 end),
            Nnbsp = count(Cps, fun(Cp) -> Cp =:= 16#202F end),
            Zw = count(Cps, fun(Cp) -> Cp =:= 16#200B orelse Cp =:= 16#200D end),
            Sub = if
                      Ann > 0 -> {annotation_misuse, Ann};
                      Wj > 0 -> {word_joiner_injection, Wj};
                      Nnbsp >= 2 -> {ai_watermark_nnbsp, Nnbsp};
                      Zw >= 2 -> {binary_payload, Zw div 2};
                      true -> {bare_zero_width, hd(SuspCps)}
                  end,
            #{kind => hazard, sub => Sub, positions => Pos}
    end.

%% True iff the zero-width codepoint at index P carries meaning a reader depends
%% on: a ZWJ inside a registered RGI emoji sequence, or a ZWNJ in an RFC 5892
%% Appendix A.1 CONTEXTJ-valid position.
sanctioned_zero_width(Input, P) ->
    case lists:nth(P + 1, Input) of
        16#200D -> legitimate_zwj_context(Input, P);
        16#200C -> legitimate_zwnj_context(Input, P);
        _ -> false
    end.

%% A ZWJ is legitimate only when flanked by two codepoints that both participate
%% in some registered RGI emoji ZWJ sequence. Strictly narrower than "is an
%% emoji": a codepoint carrying the Emoji property but appearing in no
%% registered sequence does not sanction a ZWJ beside it. A ZWJ in head or tail
%% position is never legitimate.
legitimate_zwj_context(Input, P) ->
    case P > 0 andalso P + 1 < length(Input) of
        false -> false;
        true ->
            usec_emoji_zwj_integrity:is_emoji_target(lists:nth(P, Input))
                andalso usec_emoji_zwj_integrity:is_emoji_target(lists:nth(P + 2, Input))
    end.

%% RFC 5892 Appendix A.1: a ZWNJ is orthographically required when it follows a
%% Virama, which is how a Devanagari conjunct is suppressed, or when it sits
%% between a left- or dual-joining character and a right- or dual-joining one,
%% skipping Transparent characters on both sides, which is how a Persian word
%% boundary is written inside a cursive run. A ZWNJ outside such a position
%% carries no orthographic duty and stays reportable.
legitimate_zwnj_context(Input, P) ->
    case P > 0 andalso usec_ucd:is_virama(lists:nth(P, Input)) of
        true -> true;
        false ->
            Left = joining_type_before(Input, P),
            Right = joining_type_after(Input, P),
            lists:member(Left, [l, d]) andalso lists:member(Right, [r, d])
    end.

%% The Joining_Type of the first non-Transparent codepoint before index P.
joining_type_before(Input, P) ->
    Before = lists:reverse(lists:sublist(Input, P)),
    first_non_transparent(Before).

%% The Joining_Type of the first non-Transparent codepoint after index P.
joining_type_after(Input, P) ->
    After = lists:nthtail(min(P + 1, length(Input)), Input),
    first_non_transparent(After).

first_non_transparent([]) -> none;
first_non_transparent([Cp | T]) ->
    case usec_ucd:joining_type(Cp) of
        t -> first_non_transparent(T);
        Other -> Other
    end.

zero_width(Cp) ->
    Explicit = (Cp >= 16#200B andalso Cp =< 16#200F)
        orelse (Cp >= 16#2060 andalso Cp =< 16#2064)
        orelse Cp =:= 16#202F
        orelse Cp =:= 16#FEFF
        orelse (Cp >= 16#FFF9 andalso Cp =< 16#FFFB),
    Explicit orelse (usec_ucd:is_default_ignorable(Cp) andalso not sibling_handled(Cp)).

sibling_handled(Cp) ->
    (Cp >= 16#FE00 andalso Cp =< 16#FE0F)
        orelse (Cp >= 16#E0100 andalso Cp =< 16#E01EF)
        orelse (Cp >= 16#E0000 andalso Cp =< 16#E007F)
        orelse (Cp >= 16#202A andalso Cp =< 16#202E)
        orelse (Cp >= 16#2066 andalso Cp =< 16#2069).

%% Surrogate reassembly
looks_like_byte_stream(Input) ->
    lists:all(fun(Cp) -> Cp < 16#100 end, Input).

surrogate_reassembly_detect(Input) ->
    Bytes = [case Cp > 16#FF of true -> 16#FF; false -> Cp end || Cp <- Input],
    case usec_utf8:first_invalid_utf8_offset(Bytes) of
        none -> #{sub => none, positions => []};
        {Offset, Kind} -> #{sub => surrogate_sub(Kind), positions => [Offset]}
    end.

surrogate_sub(overlong_encoding) -> <<"Overlong">>;
surrogate_sub(surrogate_codepoint) -> <<"Cesu8">>;
surrogate_sub(truncated_sequence) -> <<"Truncated">>;
surrogate_sub(invalid_start_byte) -> <<"InvalidStartByte">>;
surrogate_sub(invalid_continuation_byte) -> <<"InvalidContinuation">>;
surrogate_sub(codepoint_beyond_max) -> <<"CodepointBeyondMax">>.

%% Bidi balance
opens_embedding(Cp) -> lists:member(Cp, [16#202A, 16#202B, 16#202D, 16#202E]).
is_pdf(Cp) -> Cp =:= 16#202C.
opens_isolate(Cp) -> lists:member(Cp, [16#2066, 16#2067, 16#2068]).
is_pdi(Cp) -> Cp =:= 16#2069.
is_bidi_format_control(Cp) -> opens_embedding(Cp) orelse is_pdf(Cp) orelse opens_isolate(Cp) orelse is_pdi(Cp).

bidi_control_detect(Input) ->
    Init = #{kind => clear, sub => none, positions => [], emb_open => 0, emb_pop => 0, iso_open => 0, iso_pop => 0, max_depth => 0},
    {V, Emb, Iso, Orphans} =
        lists:foldl(fun({Cp, I}, {Acc, Emb0, Iso0, Orph}) ->
                            case is_bidi_format_control(Cp) of
                                false -> {Acc, Emb0, Iso0, Orph};
                                true ->
                                    Acc1 = Acc#{positions := maps:get(positions, Acc) ++ [I]},
                                    bidi_step(Cp, I, Acc1, Emb0, Iso0, Orph)
                            end
                    end, {Init, 0, 0, []}, with_index(Input)),
    Positions = maps:get(positions, V),
    MaxDepth = maps:get(max_depth, V),
    case Positions of
        [] -> V;
        _ when MaxDepth > 125 -> V#{kind := hazard, sub := #{tag => <<"DepthExceeded">>}};
        _ when Orphans =/= [] -> V#{kind := hazard, sub := #{tag => <<"OrphanPop">>, positions => Orphans}};
        _ when Emb > 0 -> V#{kind := hazard, sub := #{tag => <<"UnbalancedEmbedding">>}};
        _ when Iso > 0 -> V#{kind := hazard, sub := #{tag => <<"UnbalancedIsolate">>}};
        _ -> V
    end.

bidi_step(Cp, I, Acc, Emb, Iso, Orph) ->
    case true of
        _ when Cp =:= 16#202A; Cp =:= 16#202B; Cp =:= 16#202D; Cp =:= 16#202E ->
            E = Emb + 1,
            {Acc#{emb_open := maps:get(emb_open, Acc) + 1, max_depth := max(maps:get(max_depth, Acc), E + Iso)}, E, Iso, Orph};
        _ when Cp =:= 16#202C ->
            Acc1 = Acc#{emb_pop := maps:get(emb_pop, Acc) + 1},
            case Emb > 0 of true -> {Acc1, Emb - 1, Iso, Orph}; false -> {Acc1, Emb, Iso, Orph ++ [I]} end;
        _ when Cp =:= 16#2066; Cp =:= 16#2067; Cp =:= 16#2068 ->
            S = Iso + 1,
            {Acc#{iso_open := maps:get(iso_open, Acc) + 1, max_depth := max(maps:get(max_depth, Acc), Emb + S)}, Emb, S, Orph};
        _ when Cp =:= 16#2069 ->
            Acc1 = Acc#{iso_pop := maps:get(iso_pop, Acc) + 1},
            case Iso > 0 of true -> {Acc1, Emb, Iso - 1, Orph}; false -> {Acc1, Emb, Iso, Orph ++ [I]} end
    end.

%% Identity
homoglyph_detect(Input) ->
    Skel = skeleton(Input),
    ISkel = iterated_skeleton(Input),
    Rl = usec_ucd:restriction_level(Input),
    Base = #{kind => clear, sub => none, skeleton => Skel, iterated_skeleton => ISkel, restriction_level => Rl},
    case find_target_match(Input, ISkel) of
        Target when Target =/= none ->
            Base#{kind := hazard, sub := #{tag => <<"TargetMatch">>, target => Target}};
        none ->
            case lists:any(fun math_alnum/1, Input) of
                true -> Base#{kind := hazard, sub := #{tag => <<"MathAlpha">>}};
                false ->
                    case lists:any(fun fullwidth_halfwidth/1, Input) of
                        true -> Base#{kind := hazard, sub := #{tag => <<"WidthClass">>}};
                        false ->
                            case usec_ucd:to_nfc(Input) =/= Input of
                                true -> Base#{kind := hazard, sub := #{tag => <<"DecompositionSwap">>}};
                                false ->
                                    %% Priority 5: CrossScriptMix asks the script question only;
                                    %% the Restricted-status rung belongs to the mixed-script family.
                                    case length(usec_ucd:string_script_union(Input)) >= 2 andalso not usec_ucd:is_highly_restrictive(Input) of
                                        true -> Base#{kind := hazard, sub := #{tag => <<"CrossScriptMix">>}};
                                        false ->
                                            case lists:member(Rl, [minimally_restrictive, unrestricted]) of
                                                true -> Base#{kind := hazard, sub := #{tag => <<"RestrictionLow">>}};
                                                false -> Base
                                            end
                                    end
                            end
                    end
            end
    end.

confusable_source(Cp) -> maps:is_key(Cp, confusables()).

skeleton(Input) ->
    usec_ucd:to_nfd(usec_ucd:case_fold(substitute(usec_ucd:case_fold(usec_ucd:to_nfd(Input))))).

iterated_skeleton(Input) ->
    Next = skeleton(Input),
    case Next =:= Input of true -> Input; false -> iterated_skeleton(Next) end.

substitute(Input) ->
    M = confusables(),
    lists:flatmap(fun(Cp) -> maps:get(Cp, M, [Cp]) end, Input).

confusables() ->
    usec_data:cached(confusables_map, fun parse_confusables/0).

parse_confusables() ->
    lists:foldl(fun(Line, Acc) ->
                        Body = string:trim(hd(binary:split(Line, <<"#">>))),
                        case Body of
                            <<>> -> Acc;
                            _ ->
                                Parts = [string:trim(P) || P <- binary:split(Body, <<";">>, [global])],
                                case Parts of
                                    [Src, Tgt | _] ->
                                        maps:put(binary_to_integer(Src, 16),
                                                 [binary_to_integer(T, 16) || T <- binary:split(Tgt, <<" ">>, [global]), T =/= <<>>],
                                                 Acc);
                                    _ -> Acc
                                end
                        end
                end, #{}, lines(usec_data:read_file("confusables.txt"))).

known_targets() ->
    usec_data:cached(known_targets, fun parse_targets/0).

parse_targets() ->
    lists:filtermap(
      fun(Line0) ->
              Line = string:trim(Line0),
              case Line =:= <<>> orelse binary:first(Line) =:= $# of
                  true -> false;
                  false ->
                      Cps = usec_utf8:decode_to_codepoints(Line),
                      {true, #{name => Line, cps => Cps, letters => letter_skeleton(iterated_skeleton(Cps))}}
              end
      end, lines(usec_data:read_file("KnownAttackTargets.txt"))).

letter_skeleton(Cps) ->
    [Cp || Cp <- Cps,
           usec_ucd:ccc(Cp) =:= 0,
           not usec_ucd:is_default_ignorable(Cp),
           not usec_ucd:is_white_space(Cp)].

find_target_match(Input, ISkel) ->
    Letters = letter_skeleton(ISkel),
    case [maps:get(name, T) || T <- known_targets(),
                            maps:get(cps, T) =/= Input,
                            maps:get(letters, T) =:= Letters] of
        [Name | _] -> Name;
        [] -> none
    end.

math_alnum(Cp) -> Cp >= 16#1D400 andalso Cp =< 16#1D7FF.
fullwidth_halfwidth(Cp) -> Cp >= 16#FF01 andalso Cp =< 16#FFEF.

mixed_script_admissibility(Input) ->
    mixed_script_verdict(Input, true) =/= none.

%% The mixed-script sub-threat for Input, or none when admissible.
%%
%% The rung order is MixedScriptAdmissibility.lean's: a Restricted-status
%% codepoint outranks every script question, then the two named Latin pairs,
%% then a multi-script mix split by whether it stays inside a CJK covered set,
%% and finally an Unrestricted level with no script mix.
%%
%% IdentifierField carries what the caller knows about the field, mirroring
%% that module's Context. Phase 1 is sound for an identifier, which cannot
%% contain a space, and unsound for a document, where every space and every
%% punctuation mark is Restricted.
mixed_script_verdict(Input, IdentifierField) ->
    HasRestricted = IdentifierField andalso
        lists:any(fun(Cp) -> not usec_ucd:is_id_allowed(Cp) end, Input),
    case HasRestricted of
        true -> <<"RestrictedStatusCp">>;
        false ->
            U = usec_ucd:string_script_union(Input),
            HasLatn = lists:member(<<"Latn">>, U),
            case HasLatn andalso lists:member(<<"Cyrl">>, U) of
                true -> <<"LatinCyrillic">>;
                false ->
                    case HasLatn andalso lists:member(<<"Grek">>, U) of
                        true -> <<"LatinGreek">>;
                        false ->
                            case length(U) >= 2 andalso not usec_ucd:is_highly_restrictive(Input) of
                                true ->
                                    case usec_ucd:is_covered_cjk(Input) of
                                        true -> <<"CjkMix">>;
                                        false -> <<"ScriptMixOther">>
                                    end;
                                false ->
                                    case IdentifierField andalso
                                         usec_ucd:restriction_level(Input) =:= unrestricted of
                                        true -> <<"UnrestrictedLevel">>;
                                        false -> none
                                    end
                            end
                    end
            end
    end.

mixed_script_subthreat(Input) ->
    U = usec_ucd:string_script_union(Input),
    case lists:member(<<"Latn">>, U) andalso lists:member(<<"Cyrl">>, U) of
        true -> <<"LatinCyrillic">>;
        false ->
            case lists:member(<<"Latn">>, U) andalso lists:member(<<"Grek">>, U) of
                true -> <<"LatinGreek">>;
                false -> <<"ScriptMixOther">>
            end
    end.

%% Display and boundary
%% The declared display direction of the field holding an input, ltr | rtl.
%% A caller handling Hebrew, Arabic or Persian UI text declares its field
%% right-to-left; every other reading treats the input as a declared-LTR string,
%% under which right-to-left content is itself the hazard. Mirrors
%% FieldDirection in Unicode/Security/Display/RtlInjection.lean, that spec's
%% alias for the UAX #9 paragraph-direction vocabulary.
%%
%% A bidi format control reorders what a reviewer sees whichever way the field
%% runs, so Phase 1 holds unconditionally and trumps all. Phases 2 and 3 ask
%% whether right-to-left text has taken over or been spliced into a
%% left-to-right field, which has no premise in a right-to-left field where
%% right-to-left text is the content. The mirror-image hazard, strong-LTR
%% injection into a right-to-left field, belongs to the separate detector the
%% scope note assigns it to.
rtl_injection_detect_with_context(Direction, Input) ->
    StrongRtl = count(Input, fun usec_ucd:is_strong_rtl/1),
    {RunLen, RunStart} = longest_rtl_run(Input),
    case first_pos(Input, fun is_bidi_format_control/1) of
        P when P =/= none -> #{sub => <<"BidiControlInLTRField">>, positions => [P]};
        none when Direction =:= rtl ->
            %% A right-to-left field carrying right-to-left text carries its
            %% content.
            #{sub => none, positions => []};
        none ->
            case first_strong_char(Input) of
                {P, rtl} -> #{sub => <<"FieldTakeover">>, positions => [P]};
                _ ->
                    if
                        StrongRtl =:= 0 -> #{sub => none, positions => []};
                        RunLen >= 4 -> #{sub => <<"MixedOverflow">>, positions => [RunStart]};
                        true ->
                            case first_pos(Input, fun usec_ucd:is_strong_rtl/1) of
                                none -> #{sub => none, positions => []};
                                Pos -> #{sub => <<"StrongRTLInLTR">>, positions => [Pos]}
                            end
                    end
            end
    end.

%% Detection in a field declared left-to-right, the reading the module scope
%% note fixes for an undeclared field.
rtl_injection_detect(Input) ->
    rtl_injection_detect_with_context(ltr, Input).

first_strong_char(Input) ->
    case [{I, Cp} || {Cp, I} <- with_index(Input),
                     usec_ucd:is_strong_rtl(Cp) orelse usec_ucd:is_strong_ltr(Cp)] of
        [{I, Cp} | _] -> {I, case usec_ucd:is_strong_rtl(Cp) of true -> rtl; false -> ltr end};
        [] -> none
    end.

longest_rtl_run(Input) ->
    {Best, BestStart, _Cur, _CurStart} =
        lists:foldl(fun({Cp, I}, {B, BS, C, CS}) ->
                            case usec_ucd:is_strong_rtl(Cp) of
                                true ->
                                    Start = case C of 0 -> I; _ -> CS end,
                                    C1 = C + 1,
                                    case C1 > B of true -> {C1, Start, C1, Start}; false -> {B, BS, C1, Start} end;
                                false -> {B, BS, 0, 0}
                            end
                    end, {0, 0, 0, 0}, with_index(Input)),
    {Best, BestStart}.

confusable_bidi_detect(Input) ->
    case first_pos(Input, fun confusable_source/1) of
        none -> #{sub => none, positions => []};
        CPos ->
            case first_pos(Input, fun(Cp) -> opens_embedding(Cp) orelse is_pdf(Cp) end) of
                P when P =/= none -> #{sub => <<"ConfusableInOverride">>, positions => [CPos, P]};
                none ->
                    case first_pos(Input, fun(Cp) -> opens_isolate(Cp) orelse is_pdi(Cp) end) of
                        P2 when P2 =/= none -> #{sub => <<"ConfusableInIsolate">>, positions => [CPos, P2]};
                        none -> #{sub => none, positions => []}
                    end
            end
    end.

covert_display_detect(Input) ->
    case first_pos(Input, fun is_bidi_format_control/1) of
        none -> #{sub => none, positions => []};
        BidiPos ->
            case first_suspicious_vs(Input) of
                P when P =/= none -> #{sub => <<"BidiPlusUnregisteredVs">>, positions => [BidiPos, P]};
                none ->
                    case first_pos(Input, fun(Cp) -> Cp >= 16#E0000 andalso Cp =< 16#E007F end) of
                        T when T =/= none -> #{sub => <<"BidiPlusTagBlock">>, positions => [BidiPos, T]};
                        none -> #{sub => none, positions => []}
                    end
            end
    end.

first_suspicious_vs(Input) ->
    first_pos(with_prev(Input), fun({Cp, Prev}) ->
                                       is_vs(Cp) andalso not (Prev =/= none andalso registered_variation_pair(Prev, Cp))
                               end).

%% Form and crypto
locale_case_detect(Input) ->
    case first_locale_divergence(turkish, Input) of
        P when P =/= none -> #{sub => <<"TurkishCaseDivergence">>, positions => [P]};
        none ->
            case first_locale_divergence(lithuanian, Input) of
                P2 when P2 =/= none -> #{sub => <<"LithuanianCaseDivergence">>, positions => [P2]};
                none -> #{sub => none, positions => []}
            end
    end.

first_locale_divergence(Loc, Input) ->
    first_locale_divergence(Loc, Input, [], 0).
first_locale_divergence(_Loc, [], _Rev, _I) -> none;
first_locale_divergence(Loc, [Cp | Rest], Rev, I) ->
    D = usec_casing:lower_codepoint(default, Rev, Rest, Cp),
    L = usec_casing:lower_codepoint(Loc, Rev, Rest, Cp),
    case D =/= L of true -> I; false -> first_locale_divergence(Loc, Rest, [Cp | Rev], I + 1) end.

nfc_witness_detect(Input) ->
    case first_divergence(Input, usec_ucd:to_nfc(Input)) of
        P when P =/= none -> #{sub => <<"NonNfcForm">>, positions => [P]};
        none ->
            case first_divergence(Input, usec_ucd:to_nfkc(Input)) of
                P2 when P2 =/= none -> #{sub => <<"NonNfkcCompatForm">>, positions => [P2]};
                none -> #{sub => none, positions => []}
            end
    end.

normalization_bomb_detect(Input) ->
    case first_blowup(Input) of
        P when P =/= none -> #{sub => <<"SingleCpBlowup">>, positions => [P]};
        none ->
            NfkdRatio = ratio(Input, fun usec_ucd:to_nfkd/1),
            NfdRatio = ratio(Input, fun usec_ucd:to_nfd/1),
            case true of
                _ when NfkdRatio > 400 -> #{sub => <<"NfkdHighExpansion">>, positions => []};
                _ when NfdRatio > 300 -> #{sub => <<"NfdHighExpansion">>, positions => []};
                _ -> #{sub => none, positions => []}
            end
    end.

first_blowup(Input) ->
    first_pos(Input, fun(Cp) -> length(usec_ucd:to_nfkd([Cp])) > 8 end).

ratio([], _F) -> 0;
ratio(Input, F) -> (length(F(Input)) * 100) div length(Input).

bip39_canonical(Cps) ->
    trim_spaces(collapse_ws(usec_casing:to_lower(default, usec_ucd:to_nfkd(Cps)))).

bip39_detect(Input) ->
    Canon = bip39_canonical(Input),
    Words = split_words(Canon),
    WordCount = length(Words),
    Trailing = length(lists:takewhile(fun bip39_ws/1, lists:reverse(Input))),
    Upper = first_pos(Input, fun(Cp) -> Cp >= $A andalso Cp =< $Z end),
    Ws = first_ws_run(Input),
    Nfkd = usec_ucd:to_nfkd(Input),
    NonNfkd = case Input =:= Nfkd of true -> none; false -> first_divergence(Input, Nfkd) end,
    Unknown = first_pos(Words, fun(W) -> wordlists_containing(W) =:= [] end),
    Lang = unique_language(Words),
    if
        Trailing > 0 -> #{sub => <<"TrailingWhitespace">>, positions => [length(Input) - Trailing], language => null, canonical => Canon, word_count => WordCount};
        Upper =/= none -> #{sub => <<"MixedCase">>, positions => [Upper], language => null, canonical => Canon, word_count => WordCount};
        Ws =/= none -> #{sub => <<"WhitespaceAnomaly">>, positions => [Ws], language => null, canonical => Canon, word_count => WordCount};
        NonNfkd =/= none -> #{sub => <<"NonNFKD">>, positions => [NonNfkd], language => null, canonical => Canon, word_count => WordCount};
        Unknown =/= none -> #{sub => <<"WordlistMismatch">>, positions => [Unknown], language => null, canonical => Canon, word_count => WordCount};
        Lang =:= none -> #{sub => <<"LanguageAmbiguous">>, positions => [], language => null, canonical => Canon, word_count => WordCount};
        true -> #{sub => none, positions => [], language => Lang, canonical => Canon, word_count => WordCount}
    end.

wordlists() ->
    usec_data:cached(bip39_wordlists, fun parse_wordlists/0).

parse_wordlists() ->
    Files = [{<<"english">>, "english.txt"}, {<<"japanese">>, "japanese.txt"}, {<<"korean">>, "korean.txt"},
             {<<"spanish">>, "spanish.txt"}, {<<"chinese_simplified">>, "chinese_simplified.txt"},
             {<<"chinese_traditional">>, "chinese_traditional.txt"}, {<<"french">>, "french.txt"},
             {<<"italian">>, "italian.txt"}, {<<"czech">>, "czech.txt"}, {<<"portuguese">>, "portuguese.txt"}],
    [#{name => Name,
       set => sets:from_list([key(usec_utf8:decode_to_codepoints(Line)) || Line <- lines(usec_data:read_file(filename:join("bip39", File))), Line =/= <<>>])}
     || {Name, File} <- Files].

key(Cps) -> list_to_binary(string:join([integer_to_list(C) || C <- Cps], ",")).

wordlists_containing(Word) ->
    K = key(Word),
    [maps:get(name, Wl) || Wl <- wordlists(), sets:is_element(K, maps:get(set, Wl))].

unique_language(Words) ->
    case [maps:get(name, Wl) || Wl <- wordlists(), lists:all(fun(W) -> sets:is_element(key(W), maps:get(set, Wl)) end, Words)] of
        [L | _] -> L;
        [] -> none
    end.

split_words(Canon) ->
    [W || W <- split_words(Canon, [], []), W =/= []].
split_words([], Cur, Acc) -> lists:reverse([lists:reverse(Cur) | Acc]);
split_words([16#20 | Rest], Cur, Acc) -> split_words(Rest, [], [lists:reverse(Cur) | Acc]);
split_words([Cp | Rest], Cur, Acc) -> split_words(Rest, [Cp | Cur], Acc).

collapse_ws(Cps) -> collapse_ws(Cps, false, []).
collapse_ws([], _InWs, Acc) -> lists:reverse(Acc);
collapse_ws([Cp | Rest], InWs, Acc) ->
    case bip39_ws(Cp) of
        true -> case InWs of true -> collapse_ws(Rest, true, Acc); false -> collapse_ws(Rest, true, [16#20 | Acc]) end;
        false -> collapse_ws(Rest, false, [Cp | Acc])
    end.

trim_spaces(Cps) -> lists:reverse(drop_spaces(lists:reverse(drop_spaces(Cps)))).
drop_spaces([16#20 | T]) -> drop_spaces(T);
drop_spaces(L) -> L.
bip39_ws(Cp) -> Cp =:= 16#20 orelse Cp =:= 16#3000.

first_ws_run(Input) ->
    first_ws_run(Input, 0).
first_ws_run([], _I) -> none;
first_ws_run([Cp], I) -> case bip39_ws(Cp) andalso I =:= 0 of true -> 0; false -> none end;
first_ws_run([Cp, Next | Rest], I) when Cp =:= 16#20; Cp =:= 16#3000 ->
    case I =:= 0 orelse bip39_ws(Next) of true -> I; false -> first_ws_run([Next | Rest], I + 1) end;
first_ws_run([_ | Rest], I) -> first_ws_run(Rest, I + 1).

%% Helpers
sub_tag(none) -> none;
sub_tag(B) when is_binary(B) -> B;
sub_tag(#{tag := T}) -> T;
sub_tag({direct_ascii, _}) -> <<"DirectAscii">>;
sub_tag({language_tag_revival, _, _}) -> <<"LanguageTagRevival">>;
sub_tag({mixed_block, _, _}) -> <<"MixedBlock">>;
sub_tag({bare_tag_present, _}) -> <<"BareTagPresent">>;
sub_tag({direct_payload, _}) -> <<"DirectPayload">>;
sub_tag({illegal_target, _, _}) -> <<"IllegalTarget">>;
sub_tag({repeated_base, _, _}) -> <<"RepeatedBase">>;
sub_tag({annotation_misuse, _}) -> <<"AnnotationMisuse">>;
sub_tag({word_joiner_injection, _}) -> <<"WordJoinerInjection">>;
sub_tag({ai_watermark_nnbsp, _}) -> <<"AiWatermarkNNBSP">>;
sub_tag({binary_payload, _}) -> <<"BinaryPayload">>;
sub_tag({bare_zero_width, _}) -> <<"BareZeroWidth">>.

positions(Input, Pred) -> [I || {Cp, I} <- with_index(Input), Pred(Cp)].
first_pos(Input, Pred) ->
    case [I || {Cp, I} <- with_index(Input), Pred(Cp)] of [I | _] -> I; [] -> none end.
count(Input, Pred) -> length([Cp || Cp <- Input, Pred(Cp)]).
with_index([]) -> [];
with_index(Input) -> lists:zip(Input, lists:seq(0, length(Input) - 1)).
with_prev(Input) -> with_prev(Input, none, []).
with_prev([], _Prev, Acc) -> lists:reverse(Acc);
with_prev([Cp | Rest], Prev, Acc) -> with_prev(Rest, Cp, [{Cp, Prev} | Acc]).

first_divergence(A, B) -> first_divergence(A, B, 0).
first_divergence([], [], _I) -> none;
first_divergence([], _B, I) -> I;
first_divergence(_A, [], I) -> I;
first_divergence([H | T1], [H | T2], I) -> first_divergence(T1, T2, I + 1);
first_divergence(_, _, I) -> I.

lines(Bin) ->
    [case L of
         <<>> -> <<>>;
         _ -> case binary:last(L) of $\r -> binary:part(L, 0, byte_size(L) - 1); _ -> L end
     end || L <- binary:split(Bin, <<"\n">>, [global])].
