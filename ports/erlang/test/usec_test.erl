-module(usec_test).

-export([run/0]).

run() ->
    detector_fixtures(),
    policy_contract(),
    verdict_contract(),
    decode_contract(),
    multiencoding_contract(),
    form_and_bip39(),
    hash_input_stability_tests(),
    stream_safe_tests(),
    ai_watermark_tests(),
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

%% Reason code the detect verdict would emit for a given input, or `none' when
%% the input is clear. Mirrors how usec_policy:scan_hash_input_stability wires
%% the classification tag into a finding code.
his_code(Input) ->
    C = maps:get(classify, usec_hash_input_stability:detect(Input)),
    case usec_hash_input_stability:classify_tag(C) of
        none -> none;
        Tag -> usec_policy:reason_code(hash_input_stability, Tag)
    end.

%% Context-bearing detect: the classification tag under a given Context map.
his_ctx_tag(Ctx, Input) ->
    C = maps:get(classify, usec_hash_input_stability:detect_with_context(Ctx, Input)),
    usec_hash_input_stability:classify_tag(C).

%% Context-bearing detect: the implicated positions under a given Context map.
his_ctx_positions(Ctx, Input) ->
    C = maps:get(classify, usec_hash_input_stability:detect_with_context(Ctx, Input)),
    usec_hash_input_stability:classify_positions(C).

hash_input_stability_tests() ->
    %% ── Shared context-free fixture, run through detect. ────────────────
    F = fixture(filename:join("detectors", "hash_input_stability.json")),
    assert_eq(<<"hash-input-stability">>, maps:get(<<"family">>, F), his_fixture_family),
    lists:foreach(fun(Case) ->
                          Input = maps:get(<<"input">>, Case),
                          Label = {his_fixture, maps:get(<<"name">>, Case)},
                          Required = maps:get(<<"required_findings">>, Case),
                          Codes = case his_code(Input) of
                                      none -> [];
                                      Code -> [Code]
                                  end,
                          lists:foreach(fun(Req) -> assert(lists:member(Req, Codes), Label) end, Required),
                          case Required of
                              [] -> assert(Codes =:= [], Label);
                              _ -> ok
                          end
                  end, maps:get(<<"cases">>, F)),

    %% ── Context vectors transcribed verbatim from the rust #[test] comment
    %%    block (ports/rust/src/security/crypto/hash_input_stability.rs). ──

    %% declared_encoding = Some("utf-16"), [0x61,0x62,0x63] → EncodingMismatch, [0]
    assert_eq(<<"EncodingMismatch">>, his_ctx_tag(#{declared_encoding => <<"utf-16">>}, [16#61, 16#62, 16#63]), his_enc_utf16),
    assert_eq([0], his_ctx_positions(#{declared_encoding => <<"utf-16">>}, [16#61, 16#62, 16#63]), his_enc_utf16_pos),

    %% declared_encoding = Some("utf-8"), [0x61,0xD800,0x62] → EncodingMismatch, [1] (invalid surrogate)
    assert_eq(<<"EncodingMismatch">>, his_ctx_tag(#{declared_encoding => <<"utf-8">>}, [16#61, 16#D800, 16#62]), his_enc_surrogate),
    assert_eq([1], his_ctx_positions(#{declared_encoding => <<"utf-8">>}, [16#61, 16#D800, 16#62]), his_enc_surrogate_pos),

    %% declared_encoding = Some("utf-8"), [0x61,0x110000,0x62] → EncodingMismatch, [1] (out of range)
    assert_eq(<<"EncodingMismatch">>, his_ctx_tag(#{declared_encoding => <<"utf-8">>}, [16#61, 16#110000, 16#62]), his_enc_oor),
    assert_eq([1], his_ctx_positions(#{declared_encoding => <<"utf-8">>}, [16#61, 16#110000, 16#62]), his_enc_oor_pos),

    %% declared_encoding = Some("UTF-8"|"utf-8"|"UTF8"|"utf8"), [0x61,0x62,0x63] → clear
    lists:foreach(fun(Lbl) ->
                          assert_eq(none, his_ctx_tag(#{declared_encoding => Lbl}, [16#61, 16#62, 16#63]), {his_enc_utf8_clear, Lbl})
                  end, [<<"UTF-8">>, <<"utf-8">>, <<"UTF8">>, <<"utf8">>]),

    %% rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule, [1]
    assert_eq(<<"SignedMessageRule">>, his_ctx_tag(#{rfc_rule => pgp4880_trailing_whitespace}, [16#61, 16#20]), his_pgp4880),
    assert_eq([1], his_ctx_positions(#{rfc_rule => pgp4880_trailing_whitespace}, [16#61, 16#20]), his_pgp4880_pos),

    %% rfc_rule = Pgp9580LineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1] (bare LF)
    assert_eq(<<"SignedMessageRule">>, his_ctx_tag(#{rfc_rule => pgp9580_line_ending}, [16#61, 16#0A, 16#62]), his_pgp9580_lf),
    assert_eq([1], his_ctx_positions(#{rfc_rule => pgp9580_line_ending}, [16#61, 16#0A, 16#62]), his_pgp9580_lf_pos),

    %% rfc_rule = Pgp9580LineEnding, [0x61,0x62,0x63,0x0D,0x0A,0x64,0x65,0x66] → clear (CRLF)
    assert_eq(none, his_ctx_tag(#{rfc_rule => pgp9580_line_ending}, [16#61, 16#62, 16#63, 16#0D, 16#0A, 16#64, 16#65, 16#66]), his_pgp9580_crlf),

    %% rfc_rule = Rfc8785NfcRequirement, [0x0065,0x0301] → SignedMessageRule, [0]
    assert_eq(<<"SignedMessageRule">>, his_ctx_tag(#{rfc_rule => rfc8785_nfc_requirement}, [16#0065, 16#0301]), his_rfc8785),
    assert_eq([0], his_ctx_positions(#{rfc_rule => rfc8785_nfc_requirement}, [16#0065, 16#0301]), his_rfc8785_pos),

    %% rfc_rule = Rfc8259ControlChar, [0x61,0x01,0x62] → SignedMessageRule, [1]
    assert_eq(<<"SignedMessageRule">>, his_ctx_tag(#{rfc_rule => rfc8259_control_char}, [16#61, 16#01, 16#62]), his_rfc8259),
    assert_eq([1], his_ctx_positions(#{rfc_rule => rfc8259_control_char}, [16#61, 16#01, 16#62]), his_rfc8259_pos),

    %% rfc_rule = Rfc7515JwsBase64Url, [0x41,0x2B,0x42] → SignedMessageRule, [1] ('+')
    assert_eq(<<"SignedMessageRule">>, his_ctx_tag(#{rfc_rule => rfc7515_jws_base64_url}, [16#41, 16#2B, 16#42]), his_rfc7515),
    assert_eq([1], his_ctx_positions(#{rfc_rule => rfc7515_jws_base64_url}, [16#41, 16#2B, 16#42]), his_rfc7515_pos),

    %% rfc_rule = Rfc7515JwsBase64Url, [0x41,0x61,0x30,0x2D,0x5F,0x7A,0x5A,0x39] → clear
    assert_eq(none, his_ctx_tag(#{rfc_rule => rfc7515_jws_base64_url}, [16#41, 16#61, 16#30, 16#2D, 16#5F, 16#7A, 16#5A, 16#39]), his_rfc7515_clear),

    %% rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x20,0x62] → SignedMessageRule, [2]
    assert_eq(<<"SignedMessageRule">>, his_ctx_tag(#{rfc_rule => rfc6376_dkim_relaxed}, [16#61, 16#20, 16#20, 16#62]), his_rfc6376),
    assert_eq([2], his_ctx_positions(#{rfc_rule => rfc6376_dkim_relaxed}, [16#61, 16#20, 16#20, 16#62]), his_rfc6376_pos),

    %% rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x62] → clear (single space)
    assert_eq(none, his_ctx_tag(#{rfc_rule => rfc6376_dkim_relaxed}, [16#61, 16#20, 16#62]), his_rfc6376_clear),

    %% rfc_rule = Rfc5751SmimeLineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1] (bare LF)
    assert_eq(<<"SignedMessageRule">>, his_ctx_tag(#{rfc_rule => rfc5751_smime_line_ending}, [16#61, 16#0A, 16#62]), his_rfc5751),
    assert_eq([1], his_ctx_positions(#{rfc_rule => rfc5751_smime_line_ending}, [16#61, 16#0A, 16#62]), his_rfc5751_pos),

    %% as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x64] → AuditLogReinterpretation, [2]
    assert_eq(<<"AuditLogReinterpretation">>, his_ctx_tag(#{as_written => [16#61, 16#62, 16#63]}, [16#61, 16#62, 16#64]), his_audit),
    assert_eq([2], his_ctx_positions(#{as_written => [16#61, 16#62, 16#63]}, [16#61, 16#62, 16#64]), his_audit_pos),

    %% as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
    assert_eq(none, his_ctx_tag(#{as_written => [16#61, 16#62, 16#63]}, [16#61, 16#62, 16#63]), his_audit_clear),

    %% server_bytes = Some([0x61,0x62,0x64]), input [0x61,0x62,0x63] → WebhookSignatureDrift, [2]
    assert_eq(<<"WebhookSignatureDrift">>, his_ctx_tag(#{server_bytes => [16#61, 16#62, 16#64]}, [16#61, 16#62, 16#63]), his_webhook),
    assert_eq([2], his_ctx_positions(#{server_bytes => [16#61, 16#62, 16#64]}, [16#61, 16#62, 16#63]), his_webhook_pos),

    %% server_bytes = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
    assert_eq(none, his_ctx_tag(#{server_bytes => [16#61, 16#62, 16#63]}, [16#61, 16#62, 16#63]), his_webhook_clear),

    %% declared_encoding = Some("utf-16") + rfc_rule = Pgp9580LineEnding,
    %%   [0x0065,0x0301,0x0A] → EncodingMismatch (priority over rfc)
    assert_eq(<<"EncodingMismatch">>,
              his_ctx_tag(#{declared_encoding => <<"utf-16">>, rfc_rule => pgp9580_line_ending}, [16#0065, 16#0301, 16#0A]),
              his_priority_enc_over_rfc),

    %% server_bytes = Some([0x61,0x62,0x65]) + as_written = Some([0x61,0x62,0x66]),
    %%   input [0x61,0x62,0x63] → WebhookSignatureDrift (priority over audit)
    assert_eq(<<"WebhookSignatureDrift">>,
              his_ctx_tag(#{server_bytes => [16#61, 16#62, 16#65], as_written => [16#61, 16#62, 16#66]}, [16#61, 16#62, 16#63]),
              his_priority_webhook_over_audit),

    %% rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule (priority over trailing)
    assert_eq(<<"SignedMessageRule">>, his_ctx_tag(#{rfc_rule => pgp4880_trailing_whitespace}, [16#61, 16#20]), his_priority_rfc_over_trailing),

    %% ── Empty context equals bare detect. ───────────────────────────────
    assert_eq(his_ctx_tag(#{}, [16#61, 16#62, 16#63]), classify_tag_of(usec_hash_input_stability:detect([16#61, 16#62, 16#63])), his_default_matches_detect),

    %% ── RfcRule tag round-trip. ─────────────────────────────────────────
    lists:foreach(fun(Rule) ->
                          assert_eq(Rule, usec_hash_input_stability:from_tag(usec_hash_input_stability:tag(Rule)), {his_tag_roundtrip, Rule})
                  end, [pgp4880_trailing_whitespace, pgp9580_line_ending, rfc8785_nfc_requirement,
                        rfc8259_control_char, rfc7515_jws_base64_url, rfc6376_dkim_relaxed,
                        rfc5751_smime_line_ending]),
    assert_eq(none, usec_hash_input_stability:from_tag(<<"nope">>), his_tag_roundtrip_none),

    io:format("  hash-input-stability: fixture + 21 context vectors pass~n").

classify_tag_of(Verdict) ->
    usec_hash_input_stability:classify_tag(maps:get(classify, Verdict)).

%% Reason code the detect verdict would emit for a given input, or `none' when
%% the input is clear. Mirrors how usec_policy:scan_stream_safe_violation wires
%% the classification tag into a finding code.
ss_code(Input) ->
    C = maps:get(classify, usec_stream_safe_violation:detect(Input)),
    case usec_stream_safe_violation:classify_tag(C) of
        none -> none;
        Tag -> usec_policy:reason_code(stream_safe_violation, Tag)
    end.

%% "a" followed by N combining acute accents (U+0301, CCC 230 — a non-starter).
a_plus_marks(N) ->
    [16#61 | lists:duplicate(N, 16#0301)].

stream_safe_tests() ->
    %% ── Shared context-free fixture, run through detect. ────────────────
    F = fixture(filename:join("detectors", "stream_safe_violation.json")),
    assert_eq(<<"stream-safe-violation">>, maps:get(<<"family">>, F), ss_fixture_family),
    lists:foreach(fun(Case) ->
                          Input = maps:get(<<"input">>, Case),
                          Label = {ss_fixture, maps:get(<<"name">>, Case)},
                          Required = maps:get(<<"required_findings">>, Case),
                          Codes = case ss_code(Input) of
                                      none -> [];
                                      Code -> [Code]
                                  end,
                          lists:foreach(fun(Req) -> assert(lists:member(Req, Codes), Label) end, Required),
                          case Required of
                              [] -> assert(Codes =:= [], Label);
                              _ -> ok
                          end
                  end, maps:get(<<"cases">>, F)),

    %% ── 30-mark boundary: clear under strict `>'. ───────────────────────
    Marks30 = a_plus_marks(30),
    V30 = usec_stream_safe_violation:detect(Marks30),
    assert(usec_stream_safe_violation:is_clear(maps:get(classify, V30)), ss_thirty_clear),
    assert_eq(none, ss_code(Marks30), ss_thirty_code),
    assert_eq(30, maps:get(max_run_len, V30), ss_thirty_max),
    assert_eq(0, maps:get(overrun_count, V30), ss_thirty_overrun),
    assert_eq(30, maps:get(total_non_starters, V30), ss_thirty_total),

    %% ── 31-mark: fires StreamSafeOverrun at base_pos 1, run_len 31. ──────
    Marks31 = a_plus_marks(31),
    V31 = usec_stream_safe_violation:detect(Marks31),
    C31 = maps:get(classify, V31),
    assert(not usec_stream_safe_violation:is_clear(C31), ss_thirtyone_hazard),
    assert_eq(<<"StreamSafeOverrun">>, usec_stream_safe_violation:classify_tag(C31), ss_thirtyone_tag),
    assert_eq([1], usec_stream_safe_violation:classify_positions(C31), ss_thirtyone_pos),
    assert_eq(<<"unicode.security.F.stream-safe-violation.StreamSafeOverrun">>, ss_code(Marks31), ss_thirtyone_code),
    assert_eq(31, maps:get(max_run_len, V31), ss_thirtyone_max),
    assert_eq(1, maps:get(overrun_count, V31), ss_thirtyone_overrun),
    assert_eq(31, maps:get(total_non_starters, V31), ss_thirtyone_total),

    io:format("  stream-safe-violation: fixture + 30/31 boundary pass~n").

%% Reason code the detect verdict would emit for a given input, or `none' when
%% clear. Mirrors usec_policy:scan_ai_watermark_detectability's finding wiring.
aw_code(Input) ->
    C = maps:get(classify, usec_ai_watermark_detectability:detect(Input)),
    case usec_ai_watermark_detectability:classify_tag(C) of
        none -> none;
        Tag -> usec_policy:reason_code(ai_watermark_detectability, Tag)
    end.

%% Context-bearing detect: the classification tag under a given Context map.
aw_ctx_tag(Ctx, Input) ->
    C = maps:get(classify, usec_ai_watermark_detectability:detect_with_context(Ctx, Input)),
    usec_ai_watermark_detectability:classify_tag(C).

ai_watermark_tests() ->
    %% ── Shared context-free fixture, run through detect. ────────────────
    F = fixture(filename:join("detectors", "ai_watermark_detectability.json")),
    assert_eq(<<"ai-watermark-detectability">>, maps:get(<<"family">>, F), aw_fixture_family),
    lists:foreach(fun(Case) ->
                          Input = maps:get(<<"input">>, Case),
                          Label = {aw_fixture, maps:get(<<"name">>, Case)},
                          Required = maps:get(<<"required_findings">>, Case),
                          Codes = case aw_code(Input) of
                                      none -> [];
                                      Code -> [Code]
                                  end,
                          lists:foreach(fun(Req) -> assert(lists:member(Req, Codes), Label) end, Required),
                          case Required of
                              [] -> assert(Codes =:= [], Label);
                              _ -> ok
                          end
                  end, maps:get(<<"cases">>, F)),

    %% ── The two Context-tolerance vectors transcribed from the rust #[test]
    %%    module (detect_zwsp_jittered_*). ZWSPs at positions 1, 3, 6
    %%    (gaps 2, 3). Bare detect (tolerance 0) falls through to
    %%    defaultIgnorableCarrier; tolerance 1 fires gpt5ZwspModulo. ──
    Jittered = [16#61, 16#200B, 16#62, 16#200B, 16#63, 16#64, 16#200B, 16#65],
    assert_eq(<<"DefaultIgnorableCarrier">>, aw_ctx_tag(#{}, Jittered), aw_zwsp_jittered_strict),
    assert_eq(<<"Gpt5ZwspModulo">>, aw_ctx_tag(#{zwsp_modulo_tolerance => 1}, Jittered), aw_zwsp_jittered_tolerant),

    %% ── Cue-class coverage (rust every_cue_class_is_probed /
    %%    unknown_has_no_cue_class). ─────────────────────────────────────
    Classes = [green_list_bias, pseudorandom_seq, semantic_drift],
    SubThreats = [{nnbsp_boundary, 0}, {variation_selector_carrier, 0}, {zwj_non_emoji, 0},
                  {default_ignorable_carrier, 0}, {gpt5_zwsp_modulo, 0}, {em_dash_pattern, 0},
                  {smart_quote_alternation, 0}, {statistical_token_choice, 0},
                  {adversarial, <<>>, 0}],
    lists:foreach(fun(Cls) ->
                          assert(lists:any(fun(St) -> usec_ai_watermark_detectability:cue_class(St) =:= Cls end, SubThreats),
                                 {aw_cue_class, Cls})
                  end, Classes),
    assert_eq(none, usec_ai_watermark_detectability:cue_class({unknown, 0}), aw_unknown_no_cue_class),

    io:format("  ai-watermark-detectability: fixture + 2 tolerance vectors pass~n").

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
