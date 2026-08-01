-module(usec_test).

-export([run/0]).

run() ->
    detector_fixtures(),
    policy_contract(),
    verdict_contract(),
    decode_contract(),
    multiencoding_contract(),
    form_and_bip39(),
    opaque_blob_tests(),
    grapheme_tests(),
    io:format("ok: erlang unicode security tests pass~n").

grapheme_tests() ->
    %% Core UAX #29 vectors mirroring the rust segmentation tests.
    assert_eq([true, true, true, true],
              usec_grapheme:grapheme_breaks([16#61, 16#62, 16#63]), gb_ascii),
    assert_eq(3, length(usec_grapheme:grapheme_clusters([16#61, 16#62, 16#63])), gb_ascii_clusters),
    assert_eq([true, false, true],
              usec_grapheme:grapheme_breaks([16#65, 16#0301]), gb_combining),
    assert_eq(1, length(usec_grapheme:grapheme_clusters([16#65, 16#0301])), gb_combining_clusters),
    assert_eq([true, false, true],
              usec_grapheme:grapheme_breaks([16#0D, 16#0A]), gb_crlf),
    assert_eq([true, false, true],
              usec_grapheme:grapheme_breaks([16#1F1EF, 16#1F1F5]), gb_flag),
    assert_eq(1, length(usec_grapheme:grapheme_clusters([16#1F1EF, 16#1F1F5])), gb_flag_clusters),
    assert_eq(2, length(usec_grapheme:grapheme_clusters([16#1F1EF, 16#1F1F5, 16#1F1FA, 16#1F1F8])),
              gb_four_flags_clusters),
    assert_eq(1, length(usec_grapheme:grapheme_clusters([16#1F468, 16#200D, 16#1F469, 16#200D, 16#1F467])),
              gb_zwj_family_clusters),
    %% Full GraphemeBreakTest.txt conformance: every div/x boundary must match.
    {ok, Bin} = file:read_file(filename:join(["test", "fixtures", "GraphemeBreakTest.txt"])),
    Lines = binary:split(Bin, <<"\n">>, [global]),
    Count = lists:foldl(fun run_gbt_line/2, 0, Lines),
    assert_eq(766, Count, grapheme_break_test_row_count),
    io:format("  grapheme: validated ~p GraphemeBreakTest.txt rows~n", [Count]).

%% Parse one GraphemeBreakTest.txt line and assert grapheme_breaks matches its
%% div/x markers. Non-data lines (comments, blanks) contribute nothing.
run_gbt_line(Line, Acc) ->
    Pattern = case binary:split(Line, <<"#">>) of
                  [P | _Comment] -> P;
                  [] -> <<>>
              end,
    Tokens = [T || T <- binary:split(Pattern, [<<" ">>, <<"\t">>, <<"\r">>], [global]), T =/= <<>>],
    case Tokens of
        [] ->
            Acc;
        _ ->
            {Cps, Breaks} = parse_gbt_tokens(Tokens, [], []),
            Got = usec_grapheme:grapheme_breaks(Cps),
            assert_eq(Breaks, Got, {gbt_row, Line}),
            Acc + 1
    end.

%% Tokens alternate boundary-marker, code point, marker, ..., marker. Markers
%% become the expected boundary mask; hex tokens become the code point list.
parse_gbt_tokens([], Cps, Breaks) ->
    {lists:reverse(Cps), lists:reverse(Breaks)};
parse_gbt_tokens([Tok | Rest], Cps, Breaks) ->
    case gbt_marker(Tok) of
        {boundary, B} -> parse_gbt_tokens(Rest, Cps, [B | Breaks]);
        codepoint -> parse_gbt_tokens(Rest, [binary_to_integer(Tok, 16) | Cps], Breaks)
    end.

%% U+00F7 DIVISION SIGN (div, C3 B7) marks a break; U+00D7 MULTIPLICATION SIGN
%% (x, C3 97) marks no break. Anything else is a hex code point token.
gbt_marker(<<16#C3, 16#B7>>) -> {boundary, true};
gbt_marker(<<16#C3, 16#97>>) -> {boundary, false};
gbt_marker(_Other) -> codepoint.

opaque_blob_tests() ->
    assert(usec_opaque_blob:is_utf8_blob([16#48, 16#69]), blob_ascii),
    assert(usec_opaque_blob:is_utf8_blob([16#C3, 16#A9]), blob_2byte),
    assert(usec_opaque_blob:is_utf8_blob([16#F0, 16#9F, 16#98, 16#80]), blob_4byte),
    assert(not usec_opaque_blob:is_utf8_blob([16#C0, 16#80]), blob_overlong),
    assert(not usec_opaque_blob:is_utf8_blob([16#ED, 16#A0, 16#80]), blob_surrogate),
    #{value := [16#48, 16#69], max_bytes := 16} = usec_opaque_blob:make([16#48, 16#69], 16),
    assert_eq(none, usec_opaque_blob:make([16#48, 16#69, 16#21], 2), blob_over_bound),
    assert_eq(none, usec_opaque_blob:make([16#C0, 16#80], 16), blob_malformed),
    #{} = usec_opaque_blob:make([], 32),
    {validated_utf8, [16#C3, 16#A9]} = usec_validated_utf8:validate([16#C3, 16#A9]),
    assert_eq([16#C3, 16#A9],
              usec_validated_utf8:as_bytes(usec_validated_utf8:validate([16#C3, 16#A9])),
              validated_as_bytes),
    assert_eq([16#C3, 16#A9],
              usec_validated_utf8:unwrap(usec_validated_utf8:validate([16#C3, 16#A9])),
              validated_unwrap),
    assert_eq(none, usec_validated_utf8:validate([16#ED, 16#A0, 16#80]), validated_malformed),
    ok.

fixture(Rel) ->
    {ok, Bin} = file:read_file(filename:join(["test", "fixtures", "security", Rel])),
    usec_json:decode(Bin).

assert(true, _Label) -> ok;
assert(false, Label) -> error({assertion_failed, Label}).

assert_eq(Expected, Actual, Label) ->
    case Expected =:= Actual of
        true -> ok;
        false -> error({assert_eq_failed, Label, Expected, Actual})
    end.

codes(Verdict) ->
    [maps:get(code, F) || F <- maps:get(findings, Verdict)].

detector_fixtures() ->
    Files = ["tag_block_payload.json", "variation_selector_payload.json",
             "zero_width_payload.json", "surrogate_reassembly.json",
             "bidi_control_balance.json", "noncharacter_control.json",
             "homoglyph_confusable.json", "mixed_script_admissibility.json",
             "rtl_injection.json", "covert_display_compound.json",
             "confusable_bidi_compound.json"],
    lists:foreach(fun(Name) ->
                          F = fixture(filename:join("detectors", Name)),
                          Family = maps:get(<<"family">>, F),
                          lists:foreach(fun(Case) ->
                                                V = usec_policy:scan(<<"gateway-header">>, <<"observe">>, maps:get(<<"input">>, Case)),
                                                Cs = codes(V),
                                                Label = {Name, maps:get(<<"name">>, Case)},
                                                lists:foreach(fun(Req) -> assert(lists:member(Req, Cs), Label) end,
                                                              maps:get(<<"required_findings">>, Case)),
                                                case maps:get(<<"required_findings">>, Case) of
                                                    [] ->
                                                        Needle = <<".", Family/binary, ".">>,
                                                        lists:foreach(fun(C) -> assert(binary:match(C, Needle) =:= nomatch, Label) end, Cs);
                                                    _ -> ok
                                                end
                                        end, maps:get(<<"cases">>, F))
                  end, Files).

policy_contract() ->
    P = fixture("policy_contract.json"),
    assert_eq(<<"unicode-security-policy-v0">>, maps:get(<<"contract">>, P), policy_contract),
    lists:foreach(fun(Case) ->
                          V = usec_policy:scan(maps:get(<<"profile">>, Case), maps:get(<<"mode">>, Case), maps:get(<<"input">>, Case)),
                          assert_eq(maps:get(<<"action">>, Case), maps:get(action, V), maps:get(<<"name">>, Case)),
                          Cs = codes(V),
                          lists:foreach(fun(Req) -> assert(lists:member(Req, Cs), maps:get(<<"name">>, Case)) end,
                                        maps:get(<<"required_findings">>, Case))
                  end, maps:get(<<"cases">>, P)).

verdict_contract() ->
    P = fixture("verdict_contract.json"),
    assert_eq(<<"unicode-security-verdict-v0">>, maps:get(<<"contract">>, P), verdict_contract),
    lists:foreach(fun(Case) ->
                          V = usec_policy:scan(maps:get(<<"profile">>, Case), maps:get(<<"mode">>, Case), maps:get(<<"input">>, Case)),
                          Wire = usec_policy:verdict_to_wire(V),
                          assert_eq(maps:get(<<"verdict">>, Case), Wire, maps:get(<<"name">>, Case)),
                          assert_eq(maps:get(<<"verdict">>, Case), usec_json:decode(usec_policy:verdict_to_json(V)), {json, maps:get(<<"name">>, Case)})
                  end, maps:get(<<"cases">>, P)).

decode_contract() ->
    P = fixture("decode_contract.json"),
    assert_eq(<<"unicode-security-decode-v0">>, maps:get(<<"contract">>, P), decode_contract),
    lists:foreach(fun(Case) ->
                          V = usec_policy:scan_utf8(maps:get(<<"profile">>, Case), maps:get(<<"mode">>, Case), maps:get(<<"input_bytes">>, Case)),
                          assert_eq(maps:get(<<"action">>, Case), maps:get(action, V), maps:get(<<"name">>, Case)),
                          assert_eq(maps:get(<<"input">>, Case), maps:get(input, V), maps:get(<<"name">>, Case)),
                          required_positions(Case, V)
                  end, maps:get(<<"cases">>, P)).

multiencoding_contract() ->
    P = fixture("decode_multiencoding_contract.json"),
    assert_eq(<<"unicode-security-multiencoding-decode-v0">>, maps:get(<<"contract">>, P), multiencoding_contract),
    lists:foreach(fun(Case) ->
                          V = scan_encoded(Case),
                          assert_eq(maps:get(<<"action">>, Case), maps:get(action, V), maps:get(<<"name">>, Case)),
                          assert_eq(maps:get(<<"input">>, Case), maps:get(input, V), maps:get(<<"name">>, Case)),
                          required_positions(Case, V)
                  end, maps:get(<<"cases">>, P)).

scan_encoded(Case) ->
    Profile = maps:get(<<"profile">>, Case),
    Mode = maps:get(<<"mode">>, Case),
    Bytes = maps:get(<<"input_bytes">>, Case),
    case maps:get(<<"encoding">>, Case) of
        <<"utf-8">> -> usec_policy:scan_utf8(Profile, Mode, Bytes);
        <<"utf-16be">> -> usec_policy:scan_utf16be(Profile, Mode, Bytes);
        <<"utf-16le">> -> usec_policy:scan_utf16le(Profile, Mode, Bytes);
        <<"utf-32be">> -> usec_policy:scan_utf32be(Profile, Mode, Bytes);
        <<"utf-32le">> -> usec_policy:scan_utf32le(Profile, Mode, Bytes)
    end.

required_positions(Case, V) ->
    Cs = codes(V),
    lists:foreach(fun(Req) -> assert(lists:member(Req, Cs), maps:get(<<"name">>, Case)) end,
                  maps:get(<<"required_findings">>, Case)),
    PosByCode = maps:from_list([{maps:get(code, F), maps:get(positions, F)} || F <- maps:get(findings, V)]),
    lists:foreach(fun(Expected) ->
                          Code = maps:get(<<"code">>, Expected),
                          assert_eq(maps:get(<<"positions">>, Expected), maps:get(Code, PosByCode), maps:get(<<"name">>, Case))
                  end, maps:get(<<"required_positions">>, Case)).

form_and_bip39() ->
    assert_eq(none, maps:get(sub, usec_detectors:locale_case_detect([])), locale_empty),
    assert_eq(none, maps:get(sub, usec_detectors:locale_case_detect("Hello")), locale_ascii),
    assert_eq(<<"TurkishCaseDivergence">>, maps:get(sub, usec_detectors:locale_case_detect([16#0049])), locale_i),
    assert_eq([0], maps:get(positions, usec_detectors:locale_case_detect([16#0049])), locale_i_pos),
    assert_eq(<<"TurkishCaseDivergence">>, maps:get(sub, usec_detectors:locale_case_detect([16#0130])), locale_dotted_i),
    assert_eq(<<"TurkishCaseDivergence">>, maps:get(sub, usec_detectors:locale_case_detect([16#0049, 16#0300])), locale_priority),
    assert_eq(<<"LithuanianCaseDivergence">>, maps:get(sub, usec_detectors:locale_case_detect([16#004A, 16#0300])), locale_lt),

    assert_eq(none, maps:get(sub, usec_detectors:nfc_witness_detect([])), nfc_empty),
    assert_eq(none, maps:get(sub, usec_detectors:nfc_witness_detect("Hello")), nfc_ascii),
    assert_eq(none, maps:get(sub, usec_detectors:nfc_witness_detect([16#00E9])), nfc_composed),
    assert_eq(<<"NonNfcForm">>, maps:get(sub, usec_detectors:nfc_witness_detect([16#0065, 16#0301])), nfc_decomp),
    assert_eq([0], maps:get(positions, usec_detectors:nfc_witness_detect([16#0065, 16#0301])), nfc_pos),
    assert_eq(<<"NonNfkcCompatForm">>, maps:get(sub, usec_detectors:nfc_witness_detect([16#FB01])), nfkc_ligature),

    assert_eq(none, maps:get(sub, usec_detectors:normalization_bomb_detect([])), bomb_empty),
    assert_eq(none, maps:get(sub, usec_detectors:normalization_bomb_detect("Hello")), bomb_ascii),
    assert_eq(none, maps:get(sub, usec_detectors:normalization_bomb_detect([16#D55C])), bomb_korean),
    assert_eq(none, maps:get(sub, usec_detectors:normalization_bomb_detect([16#2460])), bomb_circled),
    assert_eq(<<"SingleCpBlowup">>, maps:get(sub, usec_detectors:normalization_bomb_detect([16#FDFA])), bomb_blowup),
    assert_eq([0], maps:get(positions, usec_detectors:normalization_bomb_detect([16#FDFA])), bomb_blowup_pos),
    assert_eq(<<"NfkdHighExpansion">>, maps:get(sub, usec_detectors:normalization_bomb_detect([16#FDFB])), bomb_nfkd),
    assert_eq(<<"NfdHighExpansion">>, maps:get(sub, usec_detectors:normalization_bomb_detect([16#1F82])), bomb_nfd),

    Abandon = "abandon",
    About = "about",
    assert_eq("a b", usec_detectors:bip39_canonical("a  b"), bip39_collapse),
    assert_eq("a", usec_detectors:bip39_canonical("A"), bip39_lower),
    assert_eq(<<"TrailingWhitespace">>, maps:get(sub, usec_detectors:bip39_detect(Abandon ++ [16#20])), bip39_trailing),
    assert_eq(<<"MixedCase">>, maps:get(sub, usec_detectors:bip39_detect("Abandon")), bip39_case),
    assert_eq(<<"WhitespaceAnomaly">>, maps:get(sub, usec_detectors:bip39_detect(Abandon ++ [16#20, 16#20] ++ About)), bip39_ws),
    assert_eq(<<"NonNFKD">>, maps:get(sub, usec_detectors:bip39_detect([16#FB00])), bip39_nfkd),
    assert_eq(<<"WordlistMismatch">>, maps:get(sub, usec_detectors:bip39_detect("qzqz")), bip39_word),
    Mnemonic = lists:flatten(lists:duplicate(11, Abandon ++ [16#20])) ++ About,
    B = usec_detectors:bip39_detect(Mnemonic),
    assert_eq(none, maps:get(sub, B), bip39_clear),
    assert_eq(<<"english">>, maps:get(language, B), bip39_lang),
    assert_eq(12, maps:get(word_count, B), bip39_count).
