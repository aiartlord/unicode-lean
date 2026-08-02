-module(usec_casing).

-export([lower_codepoint/4, upper_codepoint/4, to_lower/2]).

strip(Line) ->
    string:trim(hd(binary:split(Line, <<"#">>))).

parse_hex(B) ->
    binary_to_integer(string:trim(B), 16).

hex_tokens(B) ->
    [parse_hex(T) || T <- binary:split(string:trim(B), <<" ">>, [global]), T =/= <<>>].

lines(Bin) ->
    [case L of
         <<>> -> <<>>;
         _ ->
             case binary:last(L) of
                 $\r -> binary:part(L, 0, byte_size(L) - 1);
                 _ -> L
             end
     end || L <- binary:split(Bin, <<"\n">>, [global])].

special_rows() ->
    usec_data:cached(special_casing_rows, fun parse_special_casing/0).

parse_special_casing() ->
    lists:foldl(
      fun(Raw, Acc) ->
              Line = strip(Raw),
              case Line of
                  <<>> -> Acc;
                  _ ->
                      Fields = [string:trim(F) || F <- binary:split(Line, <<";">>, [global])],
                      case length(Fields) >= 4 of
                          false -> Acc;
                          true ->
                              Cp = parse_hex(lists:nth(1, Fields)),
                              Lower = hex_tokens(lists:nth(2, Fields)),
                              %% Field 3 (0-based) — the SpecialCasing full uppercase
                              %% column — is nth(4) 1-based, sitting between the
                              %% title (nth 3) and conditions (nth 5).
                              Upper = hex_tokens(lists:nth(4, Fields)),
                              Conds = case length(Fields) >= 5 of
                                          true -> [C || C <- binary:split(lists:nth(5, Fields), <<" ">>, [global]), C =/= <<>>];
                                          false -> []
                                      end,
                              Row = {Lower, Upper, Conds},
                              maps:update_with(Cp, fun(Old) -> Old ++ [Row] end, [Row], Acc)
                      end
              end
      end, #{}, lines(usec_data:read_file("SpecialCasing.txt"))).

simple_lower() ->
    usec_data:cached(simple_lower, fun parse_simple_lower/0).

parse_simple_lower() ->
    lists:foldl(
      fun(Line, Acc) ->
              case Line of
                  <<>> -> Acc;
                  <<"#", _/binary>> -> Acc;
                  _ ->
                      Fields = binary:split(Line, <<";">>, [global]),
                      case length(Fields) >= 14 of
                          false -> Acc;
                          true ->
                              Cp = parse_hex(lists:nth(1, Fields)),
                              Lower = string:trim(lists:nth(14, Fields)),
                              case Lower of
                                  <<>> -> Acc;
                                  _ -> maps:put(Cp, parse_hex(Lower), Acc)
                              end
                      end
              end
      end, #{}, lines(usec_data:read_file("UnicodeData.txt"))).

simple_upper() ->
    usec_data:cached(simple_upper, fun parse_simple_upper/0).

parse_simple_upper() ->
    lists:foldl(
      fun(Line, Acc) ->
              case Line of
                  <<>> -> Acc;
                  <<"#", _/binary>> -> Acc;
                  _ ->
                      Fields = binary:split(Line, <<";">>, [global]),
                      case length(Fields) >= 13 of
                          false -> Acc;
                          true ->
                              Cp = parse_hex(lists:nth(1, Fields)),
                              %% Field 12 (0-based) — the UnicodeData simple
                              %% uppercase mapping — is nth(13) 1-based, one column
                              %% before the simple lowercase mapping (nth 14).
                              Upper = string:trim(lists:nth(13, Fields)),
                              case Upper of
                                  <<>> -> Acc;
                                  _ -> maps:put(Cp, parse_hex(Upper), Acc)
                              end
                      end
              end
      end, #{}, lines(usec_data:read_file("UnicodeData.txt"))).

ranges(Name) ->
    usec_data:cached({derived_property, Name}, fun() -> parse_derived_property(Name) end).

parse_range(B) ->
    case binary:split(string:trim(B), <<"..">>) of
        [One] -> Cp = parse_hex(One), {Cp, Cp};
        [Lo, Hi] -> {parse_hex(Lo), parse_hex(Hi)}
    end.

parse_derived_property(Name) ->
    lists:sort(
      lists:foldl(
        fun(Raw, Acc) ->
                Line = strip(Raw),
                case Line of
                    <<>> -> Acc;
                    _ ->
                        case binary:split(Line, <<";">>) of
                            [Range, Prop | _] ->
                                case string:trim(Prop) =:= Name of
                                    true -> [parse_range(Range) | Acc];
                                    false -> Acc
                                end;
                            _ -> Acc
                        end
                end
        end, [], lines(usec_data:read_file("DerivedCoreProperties.txt")))).

in_ranges(Cp, Ranges) ->
    lists:any(fun({Lo, Hi}) -> Cp >= Lo andalso Cp =< Hi end, Ranges).

cased(Cp) -> in_ranges(Cp, ranges(<<"Cased">>)).
soft_dotted(Cp) -> in_ranges(Cp, ranges(<<"Soft_Dotted">>)).

more_above_after([]) -> false;
more_above_after([Cp | Rest]) ->
    case usec_ucd:ccc(Cp) of
        230 -> true;
        0 -> false;
        _ -> more_above_after(Rest)
    end.

after_soft_dotted([]) -> false;
after_soft_dotted([Cp | Rest]) ->
    case soft_dotted(Cp) of
        true -> true;
        false ->
            case usec_ucd:ccc(Cp) of
                C when C =:= 0; C =:= 230 -> false;
                _ -> after_soft_dotted(Rest)
            end
    end.

after_i([]) -> false;
after_i([Cp | Rest]) ->
    case Cp of
        16#0049 -> true;
        _ ->
            case usec_ucd:ccc(Cp) of
                C when C =:= 0; C =:= 230 -> false;
                _ -> after_i(Rest)
            end
    end.

before_dot([]) -> false;
before_dot([Cp | Rest]) ->
    case Cp of
        16#0307 -> true;
        _ ->
            case usec_ucd:ccc(Cp) of
                0 -> false;
                _ -> before_dot(Rest)
            end
    end.

has_cased_before([]) -> false;
has_cased_before([Cp | Rest]) ->
    case cased(Cp) of
        true -> true;
        false ->
            case usec_ucd:ccc(Cp) of
                0 -> false;
                _ -> has_cased_before(Rest)
            end
    end.

has_cased_after([]) -> false;
has_cased_after([Cp | Rest]) ->
    case cased(Cp) of
        true -> true;
        false ->
            case usec_ucd:ccc(Cp) of
                0 -> false;
                _ -> has_cased_after(Rest)
            end
    end.

final_sigma(RevPrefix, Suffix) ->
    has_cased_before(RevPrefix) andalso not has_cased_after(Suffix).

locale_matches(Loc, Conds) ->
    HasLocale = lists:any(fun(C) -> lists:member(C, [<<"tr">>, <<"az">>, <<"lt">>]) end, Conds),
    (not HasLocale) orelse
        lists:any(fun(C) ->
                          (C =:= <<"tr">> andalso Loc =:= turkish)
                              orelse (C =:= <<"az">> andalso Loc =:= azeri)
                              orelse (C =:= <<"lt">> andalso Loc =:= lithuanian)
                  end, Conds).

conditions_hold(Loc, RevPrefix, Suffix, Conds) ->
    locale_matches(Loc, Conds) andalso
        lists:all(
          fun(C) ->
                  case C of
                      <<"tr">> -> true;
                      <<"az">> -> true;
                      <<"lt">> -> true;
                      <<"Final_Sigma">> -> final_sigma(RevPrefix, Suffix);
                      <<"Not_Final_Sigma">> -> not final_sigma(RevPrefix, Suffix);
                      <<"After_Soft_Dotted">> -> after_soft_dotted(RevPrefix);
                      <<"More_Above">> -> more_above_after(Suffix);
                      <<"Not_Before_Dot">> -> not before_dot(Suffix);
                      <<"After_I">> -> after_i(RevPrefix);
                      _ -> false
                  end
          end, Conds).

find_special_row(Loc, RevPrefix, Suffix, Cp) ->
    case maps:get(Cp, special_rows(), none) of
        none -> none;
        Rows ->
            case lists:dropwhile(fun({_Lower, _Upper, Conds}) ->
                                         Conds =:= [] orelse not conditions_hold(Loc, RevPrefix, Suffix, Conds)
                                 end, Rows) of
                [Row | _] -> Row;
                [] ->
                    case lists:dropwhile(fun({_Lower, _Upper, Conds}) -> Conds =/= [] end, Rows) of
                        [Row | _] -> Row;
                        [] -> none
                    end
            end
    end.

lower_codepoint(Loc, RevPrefix, Suffix, Cp) ->
    case find_special_row(Loc, RevPrefix, Suffix, Cp) of
        {Lower, _Upper, _Conds} -> Lower;
        none -> [maps:get(Cp, simple_lower(), Cp)]
    end.

upper_codepoint(Loc, RevPrefix, Suffix, Cp) ->
    case find_special_row(Loc, RevPrefix, Suffix, Cp) of
        {_Lower, Upper, _Conds} -> Upper;
        none -> [maps:get(Cp, simple_upper(), Cp)]
    end.

to_lower(Loc, Cps) ->
    {OutRev, _RevPrefix} =
        lists:foldl(
          fun({Cp, Suffix}, {Out, RevPrefix}) ->
                  Mapped = lower_codepoint(Loc, RevPrefix, Suffix, Cp),
                  {lists:reverse(Mapped) ++ Out, [Cp | RevPrefix]}
          end, {[], []}, suffixes(Cps)),
    lists:reverse(OutRev).

suffixes(Cps) ->
    suffixes(Cps, []).

suffixes([], Acc) -> lists:reverse(Acc);
suffixes([Cp | Rest], Acc) -> suffixes(Rest, [{Cp, Rest} | Acc]).
