%% hash-input-stability — detection of inputs that are not in canonical
%% hash-input form. Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an input
%% hashed by a signer must be byte-identical to the input hashed by the
%% verifier; if the two ends pick different canonical forms (NFC vs NFD, trim
%% policy, line-ending convention) the resulting hashes diverge silently while
%% both sides believe they signed the same content.
%%
%% Direct port of `ports/rust/src/security/crypto/hash_input_stability.rs`. The
%% canonical (hash-stable) form is `trim_trailing(to_nfc(input))`, where
%% `trim_trailing` strips only ASCII whitespace {U+0020, U+0009, U+000A,
%% U+000D}; Unicode whitespace (U+00A0, U+2000..U+200A, U+3000) is content and
%% is not stripped. NFC is the port's `usec_ucd:to_nfc`, never a host
%% normalizer.
%%
%% Six probes run in strict priority order (first hit wins): encodingMismatch,
%% webhookSignatureDrift, auditLogReinterpretation, signedMessageRule,
%% trailingWhitespace, normalizationDrift, then clear. Context-specific probes
%% fire first because they carry more precise threat information than the
%% generic probes. `detect` is the convenience wrapper over the empty context
%% that leaves the four context-bearing probes silent.

-module(usec_hash_input_stability).

-export([tag/1, from_tag/1,
         hash_stable/1, detect/1, detect_with_context/2,
         sub_threat_tag/1, classify_tag/1, classify_positions/1, is_clear/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 RfcRule tags
%% ─────────────────────────────────────────────────────────────────────

%% @doc Fixture-string identifier for an `RfcRule' atom — used by the
%% conformance harness's attribution parser to round-trip rule selections.
tag(pgp4880_trailing_whitespace) -> <<"pgp4880TrailingWhitespace">>;
tag(pgp9580_line_ending) -> <<"pgp9580LineEnding">>;
tag(rfc8785_nfc_requirement) -> <<"rfc8785NfcRequirement">>;
tag(rfc8259_control_char) -> <<"rfc8259ControlChar">>;
tag(rfc7515_jws_base64_url) -> <<"rfc7515JwsBase64Url">>;
tag(rfc6376_dkim_relaxed) -> <<"rfc6376DkimRelaxed">>;
tag(rfc5751_smime_line_ending) -> <<"rfc5751SmimeLineEnding">>.

%% @doc Inverse of `tag/1'. Returns `none' for unrecognised strings.
from_tag(<<"pgp4880TrailingWhitespace">>) -> pgp4880_trailing_whitespace;
from_tag(<<"pgp9580LineEnding">>) -> pgp9580_line_ending;
from_tag(<<"rfc8785NfcRequirement">>) -> rfc8785_nfc_requirement;
from_tag(<<"rfc8259ControlChar">>) -> rfc8259_control_char;
from_tag(<<"rfc7515JwsBase64Url">>) -> rfc7515_jws_base64_url;
from_tag(<<"rfc6376DkimRelaxed">>) -> rfc6376_dkim_relaxed;
from_tag(<<"rfc5751SmimeLineEnding">>) -> rfc5751_smime_line_ending;
from_tag(_Unrecognised) -> none.

%% ─────────────────────────────────────────────────────────────────────
%% §2 Sub-threat tags
%% ─────────────────────────────────────────────────────────────────────

%% @doc Human-facing classification tag for a sub-threat tuple.
sub_threat_tag({normalization_drift, _FirstDivergentPos}) -> <<"NormalizationDrift">>;
sub_threat_tag({trailing_whitespace, _Count}) -> <<"TrailingWhitespace">>;
sub_threat_tag({encoding_mismatch, _DeclaredEnc, _DetectedEnc}) -> <<"EncodingMismatch">>;
sub_threat_tag({signed_message_rule, _RfcRuleTag, _FirstPos}) -> <<"SignedMessageRule">>;
sub_threat_tag({audit_log_reinterpretation, _FirstDivergentPos}) -> <<"AuditLogReinterpretation">>;
sub_threat_tag({webhook_signature_drift, _FirstPos}) -> <<"WebhookSignatureDrift">>.

%% @doc Human-facing tag for a classification, or `none' when clear.
classify_tag(clear) -> none;
classify_tag({hazard, Sub, _Positions}) -> sub_threat_tag(Sub).

%% @doc Implicated positions (empty when clear).
classify_positions(clear) -> [];
classify_positions({hazard, _Sub, Positions}) -> Positions.

%% @doc True iff the classification is clear.
is_clear(clear) -> true;
is_clear({hazard, _Sub, _Positions}) -> false.

%% ─────────────────────────────────────────────────────────────────────
%% §3 Canonicalisation pipeline
%% ─────────────────────────────────────────────────────────────────────

%% @doc True iff `Cp' is an ASCII whitespace codepoint that line-oriented
%% hash-input protocols treat as framing rather than content: U+0020 SPACE,
%% U+0009 TAB, U+000A LF, U+000D CR.
is_ascii_whitespace(Cp) ->
    Cp =:= 16#0020 orelse Cp =:= 16#0009 orelse Cp =:= 16#000A orelse Cp =:= 16#000D.

%% @doc Count of trailing ASCII whitespace codepoints in `Input'.
count_trailing_whitespace(Input) ->
    length(lists:takewhile(fun is_ascii_whitespace/1, lists:reverse(Input))).

%% @doc Strip trailing ASCII whitespace.
trim_trailing(Input) ->
    lists:sublist(Input, length(Input) - count_trailing_whitespace(Input)).

%% @doc The hash-stable form of an input: NFC then trim, in spec order.
hash_stable(Input) ->
    trim_trailing(usec_ucd:to_nfc(Input)).

%% ─────────────────────────────────────────────────────────────────────
%% §4 Priority position-finder
%% ─────────────────────────────────────────────────────────────────────

%% @doc First position at which `A' and `B' diverge, or the length of the
%% shared prefix when one strictly extends the other. `none' when identical.
first_array_divergence(A, B) -> first_array_divergence(A, B, 0).
first_array_divergence([], [], _I) -> none;
first_array_divergence([], _B, I) -> I;
first_array_divergence(_A, [], I) -> I;
first_array_divergence([H | T1], [H | T2], I) -> first_array_divergence(T1, T2, I + 1);
first_array_divergence([_A | _T1], [_B | _T2], I) -> I.

%% @doc First position in `Input' satisfying `Pred', or `none'.
first_pos(Input, Pred) -> first_pos(Input, Pred, 0).
first_pos([], _Pred, _I) -> none;
first_pos([Cp | Rest], Pred, I) ->
    case Pred(Cp) of
        true -> I;
        false -> first_pos(Rest, Pred, I + 1)
    end.

%% ─────────────────────────────────────────────────────────────────────
%% §5 Context-bearing probes
%% ─────────────────────────────────────────────────────────────────────

%% @doc Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A).
ascii_lower(Cp) when Cp >= 16#41, Cp =< 16#5A -> Cp + 16#20;
ascii_lower(Cp) -> Cp.

%% @doc True iff `Label' (after ASCII case-fold) names UTF-8: accepts "utf-8",
%% "UTF-8", "UTF8", "utf8". Non-ASCII bytes pass through unchanged.
is_utf8_label(Label) ->
    Normalised = << <<(ascii_lower(B))>> || <<B>> <= Label >>,
    Normalised =:= <<"utf-8">> orelse Normalised =:= <<"utf8">>.

%% @doc True iff `Cp' is a valid Unicode scalar value: in [0, 0x10FFFF] and not
%% a surrogate [0xD800, 0xDFFF].
is_valid_scalar(Cp) ->
    Cp =< 16#10FFFF andalso not (Cp >= 16#D800 andalso Cp =< 16#DFFF).

%% @doc First position holding a codepoint that is not a valid Unicode scalar,
%% or `none' if every codepoint is valid.
first_invalid_scalar(Input) ->
    first_pos(Input, fun(Cp) -> not is_valid_scalar(Cp) end).

%% @doc Probe: encodingMismatch. Validity is dispatched first — an invalid
%% scalar fires with detected "invalid" regardless of the declared label;
%% otherwise a non-UTF-8 label fires with detected "utf-8" at position 0.
encoding_mismatch_probe(Declared, Input) ->
    case first_invalid_scalar(Input) of
        none ->
            case is_utf8_label(Declared) of
                true -> none;
                false -> {Declared, <<"utf-8">>, 0}
            end;
        Pos -> {Declared, <<"invalid">>, Pos}
    end.

%% @doc Probe: signedMessageRule for pgp4880TrailingWhitespace. Same condition
%% as trailingWhitespace; returns the first position of the trailing run.
pgp4880_violation(Input) ->
    Trailing = count_trailing_whitespace(Input),
    case Trailing > 0 of
        true -> length(Input) - Trailing;
        false -> none
    end.

%% @doc Probe: signedMessageRule for pgp9580LineEnding. First bare LF (U+000A
%% not preceded by CR) or bare CR (U+000D not followed by LF).
pgp9580_violation(Input) -> pgp9580_violation(Input, none, 0).
pgp9580_violation([], _Prev, _I) -> none;
pgp9580_violation([16#000A | _Rest], Prev, I) when Prev =/= 16#000D -> I;
pgp9580_violation([16#000A | Rest], _Prev, I) -> pgp9580_violation(Rest, 16#000A, I + 1);
pgp9580_violation([16#000D | Rest], _Prev, I) ->
    case Rest of
        [16#000A | _Tail] -> pgp9580_violation(Rest, 16#000D, I + 1);
        _NotLf -> I
    end;
pgp9580_violation([Cp | Rest], _Prev, I) -> pgp9580_violation(Rest, Cp, I + 1).

%% @doc Probe: signedMessageRule for rfc8785NfcRequirement. Same condition as
%% normalizationDrift; returns the first NFC divergence position.
rfc8785_violation(Input) ->
    Nfc = usec_ucd:to_nfc(Input),
    case Input =:= Nfc of
        true -> none;
        false -> first_array_divergence(Input, Nfc)
    end.

%% @doc Probe: signedMessageRule for rfc8259ControlChar. First C0 control
%% (U+0000..U+001F).
rfc8259_violation(Input) ->
    first_pos(Input, fun(Cp) -> Cp =< 16#1F end).

%% @doc True iff `Cp' is in the JWS Base64URL alphabet [A-Za-z0-9_-].
is_base64_url(Cp) ->
    (Cp >= 16#41 andalso Cp =< 16#5A)
        orelse (Cp >= 16#61 andalso Cp =< 16#7A)
        orelse (Cp >= 16#30 andalso Cp =< 16#39)
        orelse Cp =:= 16#2D
        orelse Cp =:= 16#5F.

%% @doc Probe: signedMessageRule for rfc7515JwsBase64Url. First codepoint
%% outside [A-Za-z0-9_-].
rfc7515_violation(Input) ->
    first_pos(Input, fun(Cp) -> not is_base64_url(Cp) end).

%% @doc True iff `Cp' is DKIM whitespace: U+0020 SPACE or U+0009 HTAB.
is_dkim_whitespace(Cp) ->
    Cp =:= 16#20 orelse Cp =:= 16#09.

%% @doc Probe: signedMessageRule for rfc6376DkimRelaxed. Position of the second
%% whitespace codepoint in the first internal whitespace run longer than one.
rfc6376_violation(Input) -> rfc6376_violation(Input, none, 0).
rfc6376_violation([], _Prev, _I) -> none;
rfc6376_violation([Cp | Rest], Prev, I) ->
    case is_dkim_whitespace(Cp) andalso I > 0 andalso is_dkim_whitespace(Prev) of
        true -> I;
        false -> rfc6376_violation(Rest, Cp, I + 1)
    end.

%% @doc Probe: signedMessageRule for rfc5751SmimeLineEnding. Reuses the PGP 9580
%% bare-line-ending rule.
rfc5751_violation(Input) ->
    pgp9580_violation(Input).

%% @doc Dispatch the RFC-rule probe. First violation position, or `none'.
rfc_rule_violation(pgp4880_trailing_whitespace, Input) -> pgp4880_violation(Input);
rfc_rule_violation(pgp9580_line_ending, Input) -> pgp9580_violation(Input);
rfc_rule_violation(rfc8785_nfc_requirement, Input) -> rfc8785_violation(Input);
rfc_rule_violation(rfc8259_control_char, Input) -> rfc8259_violation(Input);
rfc_rule_violation(rfc7515_jws_base64_url, Input) -> rfc7515_violation(Input);
rfc_rule_violation(rfc6376_dkim_relaxed, Input) -> rfc6376_violation(Input);
rfc_rule_violation(rfc5751_smime_line_ending, Input) -> rfc5751_violation(Input).

%% ─────────────────────────────────────────────────────────────────────
%% §6 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The full detection function. Runs all six probes in priority order,
%% with the context-bearing probes ahead of the generic ones. `Ctx' is a map
%% with any of the optional keys `declared_encoding' (binary label), `rfc_rule'
%% (an RfcRule atom), `as_written' (codepoint list), `server_bytes' (codepoint
%% list). Absent keys leave the corresponding probe silent.
detect_with_context(Ctx, Input) ->
    Stable = hash_stable(Input),

    EncodingHit = case maps:get(declared_encoding, Ctx, none) of
                      none -> none;
                      Label -> encoding_mismatch_probe(Label, Input)
                  end,

    WebhookHit = case maps:get(server_bytes, Ctx, none) of
                     none -> none;
                     Server -> first_array_divergence(Input, Server)
                 end,

    AuditHit = case maps:get(as_written, Ctx, none) of
                   none -> none;
                   Written -> first_array_divergence(Written, Input)
               end,

    RfcHit = case maps:get(rfc_rule, Ctx, none) of
                 none -> none;
                 Rule ->
                     case rfc_rule_violation(Rule, Input) of
                         none -> none;
                         Pos -> {Rule, Pos}
                     end
             end,

    TrailingCount = count_trailing_whitespace(Input),

    Nfc = usec_ucd:to_nfc(Input),
    NonNfcPos = case Input =:= Nfc of
                    true -> none;
                    false -> first_array_divergence(Input, Nfc)
                end,

    Classification = classify(EncodingHit, WebhookHit, AuditHit, RfcHit,
                              TrailingCount, length(Input), NonNfcPos),

    #{input => Input,
      classify => Classification,
      stable_form => Stable,
      stable_size => length(Stable)}.

%% @doc The priority resolver: first hit wins, in the spec's fixed order.
classify({Declared, Detected, Pos}, _WebhookHit, _AuditHit, _RfcHit,
         _TrailingCount, _InputLen, _NonNfcPos) ->
    {hazard, {encoding_mismatch, Declared, Detected}, [Pos]};
classify(none, WebhookHit, _AuditHit, _RfcHit, _TrailingCount, _InputLen, _NonNfcPos)
  when WebhookHit =/= none ->
    {hazard, {webhook_signature_drift, WebhookHit}, [WebhookHit]};
classify(none, none, AuditHit, _RfcHit, _TrailingCount, _InputLen, _NonNfcPos)
  when AuditHit =/= none ->
    {hazard, {audit_log_reinterpretation, AuditHit}, [AuditHit]};
classify(none, none, none, {Rule, Pos}, _TrailingCount, _InputLen, _NonNfcPos) ->
    {hazard, {signed_message_rule, tag(Rule), Pos}, [Pos]};
classify(none, none, none, none, TrailingCount, InputLen, _NonNfcPos)
  when TrailingCount > 0 ->
    P = InputLen - TrailingCount,
    {hazard, {trailing_whitespace, TrailingCount}, [P]};
classify(none, none, none, none, 0, _InputLen, none) ->
    clear;
classify(none, none, none, none, 0, _InputLen, P) ->
    {hazard, {normalization_drift, P}, [P]}.

%% @doc Convenience wrapper over `detect_with_context/2' with the empty context
%% — equivalent to running only the two bare-input probes (trailingWhitespace,
%% normalizationDrift).
detect(Input) ->
    detect_with_context(#{}, Input).
