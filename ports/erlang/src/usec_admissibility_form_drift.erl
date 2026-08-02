%% admissibility-form-drift — cross-layer identifier-admissibility × form drift
%% (boundary-layer detector, layer X).
%%
%% Direct port of the verified Rust reference implementation (itself a port of
%% the Lean `Unicode/Security/Boundary/AdmissibilityFormDrift' specification).
%%
%% Fires on inputs whose UTS #39 whole-string admissibility verdict
%% (`isAllowedIdentifier') differs between the input and its NFKC form. This is
%% the string-level complement of IdentifierFormDrift, which scans the
%% per-codepoint `Identifier_Status' against the NFKD head: here the whole-string
%% admissibility predicate is evaluated twice — once on the input, once on
%% `to_nfkc(input)'. The two are not redundant. A sequence of decomposed Hangul
%% jamos passes the per-codepoint scan cleanly (each jamo has identity NFKD and
%% Restricted status on both sides) but fires here: the jamo sequence is rejected
%% by `isAllowedIdentifier', while its NFKC composition into a precomposed Hangul
%% syllable is accepted.
%%
%% Every predicate reuses a table this port already bundles, never a host
%% normalization or identifier library:
%%   - the UTS #39 whole-string admissibility predicate via
%%     `usec_ucd:is_allowed_identifier/1' (UAX #31 default identifier ∧ every
%%     codepoint `Identifier_Status = Allowed'), built on the port's bundled
%%     DerivedCoreProperties.txt (XID_Start / XID_Continue) and
%%     IdentifierStatus.txt;
%%   - the UAX #15 NFKC pipeline via `usec_ucd:to_nfkc/1' (shared with
%%     NormalizationBomb and the NFKD path).
%%
%% Sub-threat (direction-agnostic):
%%   AdmissibilityFormDrift — `is_allowed_identifier(input)' differs from
%%   `is_allowed_identifier(to_nfkc(input))'. The pair of booleans is carried so
%%   the verdict records which direction the drift goes; no position is reported
%%   because the predicate is whole-string.

-module(usec_admissibility_form_drift).

-export([sub_threat_tag/1,
         classify_tag/1, classify_positions/1, is_clear/1,
         detect/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Types
%% ─────────────────────────────────────────────────────────────────────
%%
%% SubThreat — one tuple per rust variant (there is exactly one):
%%   {admissibility_form_drift, InputAdmissible, NfkcAdmissible}
%%       InputAdmissible  = `is_allowed_identifier(input)'
%%       NfkcAdmissible   = `is_allowed_identifier(to_nfkc(input))'
%%
%% Classification — `clear' | {hazard, SubThreat, Positions, Decoded}.
%% `Positions' is always the empty list (the predicate is whole-string) and
%% `Decoded' is always the empty list, kept for shape parity with the Lean
%% `Classification.hazard' decoded-byte projection.
%%
%% Verdict — a map #{input, classify, input_admissible, nfkc_admissible}.

%% @doc Fixture-row tag string for a sub-threat tuple (matches `SubThreat.tag').
sub_threat_tag({admissibility_form_drift, _InputAdmissible, _NfkcAdmissible}) ->
    <<"AdmissibilityFormDrift">>.

%% @doc Human-facing tag for a classification, or `none' when clear.
classify_tag(clear) -> none;
classify_tag({hazard, Sub, _Positions, _Decoded}) -> sub_threat_tag(Sub).

%% @doc Implicated positions (always empty — the predicate is whole-string).
classify_positions(clear) -> [];
classify_positions({hazard, _Sub, Positions, _Decoded}) -> Positions.

%% @doc True iff the classification is `clear'.
is_clear(clear) -> true;
is_clear({hazard, _Sub, _Positions, _Decoded}) -> false.

%% ─────────────────────────────────────────────────────────────────────
%% §2 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The AdmissibilityFormDrift detection function. Reuses the port's own
%% NFKC pipeline (`usec_ucd:to_nfkc/1') and whole-string admissibility predicate
%% (`usec_ucd:is_allowed_identifier/1').
detect(Input) ->
    Nfkc = usec_ucd:to_nfkc(Input),
    InOk = usec_ucd:is_allowed_identifier(Input),
    NfkcOk = usec_ucd:is_allowed_identifier(Nfkc),
    Classification = case InOk =:= NfkcOk of
                         true -> clear;
                         false ->
                             {hazard, {admissibility_form_drift, InOk, NfkcOk}, [], []}
                     end,
    #{input => Input,
      classify => Classification,
      input_admissible => InOk,
      nfkc_admissible => NfkcOk}.
