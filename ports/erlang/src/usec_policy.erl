-module(usec_policy).

-export([reason_code/1, reason_code/2, scan/3, scan_utf8/3,
         scan_utf16be/3, scan_utf16le/3, scan_utf32be/3, scan_utf32le/3,
         scan_default/2, scan_forms/3, scan_bip39/3, scan_hash_input_stability/3,
         scan_stream_safe_violation/3,
         scan_ai_watermark_detectability/3,
         scan_emoji_zwj_integrity/3,
         scan_renderer_divergence/3,
         verdict_to_wire/1, verdict_to_json/1, finding_to_wire/1]).

policy_of_profile(<<"gateway-header">>) -> #{level => restrictive, crypto => non_crypto, quarantine => false};
policy_of_profile(<<"domain-name">>) -> #{level => restrictive, crypto => non_crypto, quarantine => false};
policy_of_profile(<<"dns-label">>) -> #{level => restrictive, crypto => non_crypto, quarantine => false};
policy_of_profile(<<"source-code">>) -> #{level => restrictive, crypto => non_crypto, quarantine => false};
policy_of_profile(<<"url">>) -> #{level => moderate, crypto => non_crypto, quarantine => false};
policy_of_profile(<<"username">>) -> #{level => moderate, crypto => non_crypto, quarantine => true};
policy_of_profile(<<"display-name">>) -> #{level => minimal, crypto => non_crypto, quarantine => true};
policy_of_profile(<<"chat-message">>) -> #{level => minimal, crypto => non_crypto, quarantine => true};
policy_of_profile(<<"opaque-secret">>) -> #{level => minimal, crypto => hash_input, quarantine => false};
policy_of_profile(<<"binary-blob">>) -> #{level => minimal, crypto => non_crypto, quarantine => false}.

rejection_set(restrictive) ->
    [malformed_utf8, malformed_utf16, malformed_utf32, tag_block_payload,
     variation_selector_payload, zero_width_payload, surrogate_reassembly,
     bidi_control_balance, noncharacter_control, homoglyph_confusable,
     mixed_script_admissibility, emoji_zwj_integrity, skin_tone_variation_forgery,
     source_display_divergence, filename_disguise, rtl_injection, renderer_divergence,
     normalization_bomb, stream_safe_violation, locale_case_inversion,
     case_expansion_mismatch, width_class_confusion, nfc_idempotence_witness,
     identifier_form_drift, covert_display_compound, confusable_bidi_compound,
     admissibility_form_drift];
rejection_set(moderate) ->
    [malformed_utf8, malformed_utf16, malformed_utf32, tag_block_payload,
     variation_selector_payload, zero_width_payload, surrogate_reassembly,
     bidi_control_balance, noncharacter_control, homoglyph_confusable,
     mixed_script_admissibility, skin_tone_variation_forgery,
     source_display_divergence, filename_disguise, stream_safe_violation,
     locale_case_inversion, case_expansion_mismatch, width_class_confusion,
     nfc_idempotence_witness, identifier_form_drift, covert_display_compound,
     confusable_bidi_compound, admissibility_form_drift];
rejection_set(minimal) ->
    [malformed_utf8, malformed_utf16, malformed_utf32, surrogate_reassembly,
     bidi_control_balance, noncharacter_control, stream_safe_violation].

family_slug(F) ->
    list_to_binary(string:replace(atom_to_list(F), "_", "-", all)).

family_layer_code(F) ->
    case lists:member(F, [malformed_utf8, malformed_utf16, malformed_utf32, tag_block_payload,
                          variation_selector_payload, zero_width_payload, surrogate_reassembly,
                          bidi_control_balance, noncharacter_control]) of
        true -> <<"C">>;
        false ->
            case lists:member(F, [homoglyph_confusable, mixed_script_admissibility,
                                  emoji_zwj_integrity, skin_tone_variation_forgery]) of
                true -> <<"I">>;
                false ->
                    case lists:member(F, [source_display_divergence, filename_disguise,
                                          rtl_injection, renderer_divergence]) of
                        true -> <<"D">>;
                        false ->
                            case lists:member(F, [normalization_bomb, stream_safe_violation,
                                                  locale_case_inversion, case_expansion_mismatch,
                                                  width_class_confusion, nfc_idempotence_witness]) of
                                true -> <<"F">>;
                                false ->
                                    case lists:member(F, [identifier_form_drift, covert_display_compound,
                                                          confusable_bidi_compound, admissibility_form_drift]) of
                                        true -> <<"X">>;
                                        false -> <<"K">>
                                    end
                            end
                    end
            end
    end.

reason_code(Family) -> reason_code(Family, none).
reason_code(Family, none) -> reason_code(Family, <<"hazard">>);
reason_code(Family, Sub) ->
    <<(<<"unicode.security.">>)/binary, (family_layer_code(Family))/binary, <<".">>/binary,
      (family_slug(Family))/binary, <<".">>/binary, Sub/binary>>.

family_blocks(Profile, Family) ->
    P = policy_of_profile(Profile),
    lists:member(Family, rejection_set(maps:get(level, P))).

select_action(Profile, Mode, Findings) ->
    HasFindings = Findings =/= [],
    HasBlocking = lists:any(fun(F) -> family_blocks(Profile, maps:get(family, F)) end, Findings),
    case Mode of
        <<"observe">> -> case HasFindings of true -> <<"observe">>; false -> <<"allow">> end;
        <<"warn">> -> case HasFindings of true -> <<"observe">>; false -> <<"allow">> end;
        <<"enforce">> ->
            case HasBlocking of
                false -> <<"allow">>;
                true ->
                    case maps:get(quarantine, policy_of_profile(Profile)) of
                        true -> <<"quarantine">>;
                        false -> <<"reject">>
                    end
            end;
        <<"strict">> -> case HasFindings of true -> <<"reject">>; false -> <<"allow">> end
    end.

scan(Profile, Mode, Input) ->
    F0 = [],
    F1 = push_detector(F0, tag_block_payload, usec_detectors:tag_block_detect(Input)),
    F2 = push_detector(F1, variation_selector_payload, usec_detectors:variation_selector_detect(Input)),
    F3 = push_detector(F2, zero_width_payload, usec_detectors:zero_width_detect(Input)),
    F4 = case usec_detectors:looks_like_byte_stream(Input) of
             true ->
                 Sr = usec_detectors:surrogate_reassembly_detect(Input),
                 case maps:get(sub, Sr) of
                     none -> F3;
                     Sub -> push_finding(F3, surrogate_reassembly, hazard, Sub, maps:get(positions, Sr))
                 end;
             false -> F3
         end,
    Bidi = usec_detectors:bidi_control_detect(Input),
    F5 = push_finding(F4, bidi_control_balance, maps:get(kind, Bidi), maps:get(sub, Bidi), maps:get(positions, Bidi)),
    F6 = push_positional(F5, noncharacter_control, <<"Noncharacter">>, positions(Input, fun usec_noncharacters/1)),
    F7 = push_positional(F6, noncharacter_control, <<"C0Control">>, positions(Input, fun c0_control/1)),
    F8 = push_positional(F7, noncharacter_control, <<"C1Control">>, positions(Input, fun c1_control/1)),
    H = usec_detectors:homoglyph_detect(Input),
    F9 = case usec_detectors:sub_tag(maps:get(sub, H)) of
             <<"CrossScriptMix">> -> F8;
             _ -> push_finding(F8, homoglyph_confusable, maps:get(kind, H), maps:get(sub, H), case maps:get(kind, H) of clear -> []; _ -> positions_all(Input) end)
         end,
    F10 = case usec_detectors:mixed_script_admissibility(Input) of
              true -> push_finding(F9, mixed_script_admissibility, hazard, usec_detectors:mixed_script_subthreat(Input), positions_all(Input));
              false -> F9
          end,
    F11 = push_optional(F10, rtl_injection, usec_detectors:rtl_injection_detect(Input)),
    F12 = push_optional(F11, confusable_bidi_compound, usec_detectors:confusable_bidi_detect(Input)),
    F13 = push_optional(F12, covert_display_compound, usec_detectors:covert_display_detect(Input)),
    F14 = push_classified(F13, emoji_zwj_integrity, usec_emoji_zwj_integrity, Input),
    F15 = push_classified(F14, skin_tone_variation_forgery, usec_skin_tone_variation_forgery, Input),
    F16 = push_classified(F15, filename_disguise, usec_filename_disguise, Input),
    F17 = push_classified(F16, renderer_divergence, usec_renderer_divergence, Input),
    F18 = push_classified(F17, stream_safe_violation, usec_stream_safe_violation, Input),
    F19 = push_classified(F18, case_expansion_mismatch, usec_case_expansion_mismatch, Input),
    F20 = push_classified(F19, identifier_form_drift, usec_identifier_form_drift, Input),
    F21 = push_classified(F20, admissibility_form_drift, usec_admissibility_form_drift, Input),
    F22 = push_optional(F21, normalization_bomb, usec_detectors:normalization_bomb_detect(Input)),
    F23 = push_optional(F22, locale_case_inversion, usec_detectors:locale_case_detect(Input)),
    F24 = push_optional(F23, nfc_idempotence_witness, usec_detectors:nfc_witness_detect(Input)),
    F25 = push_classified(F24, width_class_confusion, usec_width_class_confusion, Input),
    F26 = push_classified(F25, source_display_divergence, usec_source_display_divergence, Input),
    verdict(Profile, Mode, Input, F26, null).

scan_utf8(Profile, Mode, Bytes) ->
    case usec_utf8:first_invalid_utf8_offset(Bytes) of
        none -> scan(Profile, Mode, usec_utf8:decode_to_codepoints(Bytes));
        {Offset, Kind} -> malformed(Profile, Mode, malformed_utf8, usec_utf8:reject_tag(Kind), Offset)
    end.

scan_utf16be(Profile, Mode, Bytes) -> scan_utf16(Profile, Mode, Bytes, big).
scan_utf16le(Profile, Mode, Bytes) -> scan_utf16(Profile, Mode, Bytes, little).
scan_utf32be(Profile, Mode, Bytes) -> scan_utf32(Profile, Mode, Bytes, big).
scan_utf32le(Profile, Mode, Bytes) -> scan_utf32(Profile, Mode, Bytes, little).
scan_default(Profile, Input) -> scan(Profile, <<"enforce">>, Input).

scan_forms(Profile, Mode, Input) ->
    F0 = [],
    F1 = push_optional(F0, locale_case_inversion, usec_detectors:locale_case_detect(Input)),
    F2 = push_optional(F1, nfc_idempotence_witness, usec_detectors:nfc_witness_detect(Input)),
    F3 = push_optional(F2, normalization_bomb, usec_detectors:normalization_bomb_detect(Input)),
    verdict(Profile, Mode, Input, F3, null).

scan_bip39(Profile, Mode, Input) ->
    B = usec_detectors:bip39_detect(Input),
    F = case maps:get(sub, B) of
            none -> [];
            Sub -> push_finding([], bip39_canonical, hazard, Sub, maps:get(positions, B))
        end,
    verdict(Profile, Mode, Input, F, maps:get(canonical, B)).

scan_hash_input_stability(Profile, Mode, Input) ->
    V = usec_hash_input_stability:detect(Input),
    C = maps:get(classify, V),
    F = case usec_hash_input_stability:classify_tag(C) of
            none -> [];
            Sub -> push_finding([], hash_input_stability, hazard, Sub, usec_hash_input_stability:classify_positions(C))
        end,
    verdict(Profile, Mode, Input, F, null).

scan_stream_safe_violation(Profile, Mode, Input) ->
    V = usec_stream_safe_violation:detect(Input),
    C = maps:get(classify, V),
    F = case usec_stream_safe_violation:classify_tag(C) of
            none -> [];
            Sub -> push_finding([], stream_safe_violation, hazard, Sub, usec_stream_safe_violation:classify_positions(C))
        end,
    verdict(Profile, Mode, Input, F, null).

scan_ai_watermark_detectability(Profile, Mode, Input) ->
    V = usec_ai_watermark_detectability:detect(Input),
    C = maps:get(classify, V),
    F = case usec_ai_watermark_detectability:classify_tag(C) of
            none -> [];
            Sub -> push_finding([], ai_watermark_detectability, hazard, Sub, usec_ai_watermark_detectability:classify_positions(C))
        end,
    verdict(Profile, Mode, Input, F, null).

scan_emoji_zwj_integrity(Profile, Mode, Input) ->
    V = usec_emoji_zwj_integrity:detect(Input),
    C = maps:get(classify, V),
    F = case usec_emoji_zwj_integrity:classify_tag(C) of
            none -> [];
            Sub -> push_finding([], emoji_zwj_integrity, hazard, Sub, usec_emoji_zwj_integrity:classify_positions(C))
        end,
    verdict(Profile, Mode, Input, F, null).

scan_renderer_divergence(Profile, Mode, Input) ->
    V = usec_renderer_divergence:detect(Input),
    C = maps:get(classify, V),
    F = case usec_renderer_divergence:classify_tag(C) of
            none -> [];
            Sub -> push_finding([], renderer_divergence, hazard, Sub, usec_renderer_divergence:classify_positions(C))
        end,
    verdict(Profile, Mode, Input, F, null).

push_detector(Findings, Family, D) ->
    push_finding(Findings, Family, maps:get(kind, D), maps:get(sub, D), maps:get(positions, D)).

push_optional(Findings, Family, D) ->
    case maps:get(sub, D) of
        none -> Findings;
        Sub -> push_finding(Findings, Family, hazard, Sub, maps:get(positions, D))
    end.

push_positional(Findings, _Family, _Sub, []) -> Findings;
push_positional(Findings, Family, Sub, Positions) -> push_finding(Findings, Family, hazard, Sub, Positions).

%% Build a finding from a detector module that carries a classification. Every
%% such module exports the same three functions over the verdict's classify map,
%% so the shape is written once here rather than per family.
push_classified(Findings, Family, Mod, Input) ->
    V = Mod:detect(Input),
    C = maps:get(classify, V),
    %% Guard on the module's own is_clear rather than on the tag: the clear
    %% sentinel is not uniform -- width_class_confusion answers undefined where
    %% the others answer none -- and matching one of them treats the other as a
    %% sub-threat, which reaches sub_tag with a sentinel it has no clause for.
    case Mod:is_clear(C) of
        true -> Findings;
        false -> push_finding(Findings, Family, hazard, Mod:classify_tag(C), Mod:classify_positions(C))
    end.

push_finding(Findings, _Family, clear, _Sub, _Positions) -> Findings;
push_finding(Findings, Family, Kind, Sub0, Positions) ->
    Sub = usec_detectors:sub_tag(Sub0),
    [#{code => reason_code(Family, Sub),
       family => Family,
       severity => severity(Kind),
       positions => Positions,
       sub_threat => Sub,
       detail => family_slug(Family)} | Findings].

severity(hazard) -> moderate;
severity(compound) -> high;
severity(_) -> informational.

verdict(Profile, Mode, Input, FindingsRev, Normalized) ->
    Findings = lists:reverse(FindingsRev),
    #{input => Input,
      profile => Profile,
      mode => Mode,
      action => select_action(Profile, Mode, Findings),
      findings => Findings,
      normalized => Normalized}.

finding_to_wire(F) ->
    #{<<"code">> => maps:get(code, F),
      <<"family">> => family_slug(maps:get(family, F)),
      <<"severity">> => usec_calculus:severity_value(maps:get(severity, F)),
      <<"positions">> => maps:get(positions, F),
      <<"sub_threat">> => maps:get(sub_threat, F),
      <<"detail">> => maps:get(detail, F)}.

verdict_to_wire(V) ->
    #{<<"action">> => maps:get(action, V),
      <<"profile">> => maps:get(profile, V),
      <<"mode">> => maps:get(mode, V),
      <<"input">> => maps:get(input, V),
      <<"findings">> => [finding_to_wire(F) || F <- maps:get(findings, V)],
      <<"normalized">> => maps:get(normalized, V)}.

verdict_to_json(V) ->
    usec_json:encode(verdict_to_wire(V)).

malformed(Profile, Mode, Family, Sub, Offset) ->
    F = [#{code => reason_code(Family, Sub),
           family => Family,
           severity => moderate,
           positions => [Offset],
           sub_threat => Sub,
           detail => family_slug(Family)}],
    verdict(Profile, Mode, [], F, null).

scan_utf16(Profile, Mode, Bytes, Endian) ->
    case decode_utf16(Bytes, Endian) of
        {ok, Input} -> scan(Profile, Mode, Input);
        {error, Sub, Offset} -> malformed(Profile, Mode, malformed_utf16, Sub, Offset)
    end.

decode_utf16(Bytes, Endian) -> decode_utf16(Bytes, Endian, 0, []).
decode_utf16([], _Endian, _Offset, Acc) -> {ok, lists:reverse(Acc)};
decode_utf16([_], _Endian, Offset, _Acc) -> {error, <<"TruncatedCodeUnit">>, Offset + 1};
decode_utf16([A, B | Rest], Endian, Offset, Acc) ->
    Unit = read_u16(A, B, Endian),
    if
        Unit >= 16#D800, Unit =< 16#DBFF ->
            case Rest of
                [C, D | Tail] ->
                    Low = read_u16(C, D, Endian),
                    case Low >= 16#DC00 andalso Low =< 16#DFFF of
                        true -> decode_utf16(Tail, Endian, Offset + 4, [16#10000 + (Unit - 16#D800) * 16#400 + (Low - 16#DC00) | Acc]);
                        false -> {error, <<"InvalidSurrogatePair">>, Offset + 2}
                    end;
                _ -> {error, <<"TruncatedSurrogatePair">>, Offset + length(Rest) + 2}
            end;
        Unit >= 16#DC00, Unit =< 16#DFFF ->
            {error, <<"LoneSurrogate">>, Offset};
        true ->
            decode_utf16(Rest, Endian, Offset + 2, [Unit | Acc])
    end.

scan_utf32(Profile, Mode, Bytes, Endian) ->
    case decode_utf32(Bytes, Endian) of
        {ok, Input} -> scan(Profile, Mode, Input);
        {error, Sub, Offset} -> malformed(Profile, Mode, malformed_utf32, Sub, Offset)
    end.

decode_utf32(Bytes, _Endian) when length(Bytes) rem 4 =/= 0 ->
    {error, <<"TruncatedCodeUnit">>, length(Bytes)};
decode_utf32(Bytes, Endian) ->
    decode_utf32(Bytes, Endian, 0, []).
decode_utf32([], _Endian, _Offset, Acc) -> {ok, lists:reverse(Acc)};
decode_utf32([A, B, C, D | Rest], Endian, Offset, Acc) ->
    Cp = read_u32(A, B, C, D, Endian),
    if
        Cp >= 16#D800, Cp =< 16#DFFF -> {error, <<"SurrogateCodepoint">>, Offset};
        Cp > 16#10FFFF -> {error, <<"CodepointBeyondMax">>, Offset};
        true -> decode_utf32(Rest, Endian, Offset + 4, [Cp | Acc])
    end.

read_u16(A, B, big) -> A * 16#100 + B;
read_u16(A, B, little) -> A + B * 16#100.
read_u32(A, B, C, D, big) -> A * 16#1000000 + B * 16#10000 + C * 16#100 + D;
read_u32(A, B, C, D, little) -> A + B * 16#100 + C * 16#10000 + D * 16#1000000.

positions([], _Pred) -> [];
positions(Input, Pred) -> [I || {Cp, I} <- lists:zip(Input, lists:seq(0, length(Input) - 1)), Pred(Cp)].
positions_all([]) -> [];
positions_all(Input) -> lists:seq(0, length(Input) - 1).
usec_noncharacters(Cp) ->
    (Cp >= 16#FDD0 andalso Cp =< 16#FDEF)
        orelse (Cp =< 16#10FFFF andalso ((Cp band 16#FFFF) =:= 16#FFFE orelse (Cp band 16#FFFF) =:= 16#FFFF)).
c0_control(Cp) -> (Cp >= 0 andalso Cp =< 16#1F andalso not lists:member(Cp, [9, 10, 13])) orelse Cp =:= 16#7F.
c1_control(Cp) -> Cp >= 16#80 andalso Cp =< 16#9F.
