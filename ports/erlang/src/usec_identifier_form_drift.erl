%% identifier-form-drift — cross-layer identifier × form drift (boundary-layer
%% detector, layer X). Answers the question: does normalising a codepoint change
%% the UTS #39 identifier verdict an identity validator would render for it?
%%
%% Direct port of the verified Rust reference implementation (itself a port of
%% the Lean `Unicode/Security/Boundary/IdentifierFormDrift' specification).
%%
%% Threat model. A two-system bypass. An identity validator and a form
%% normalizer disagree about a codepoint: one stage runs the `Identifier_Status'
%% check before normalisation and rejects, say, U+1D44E MATHEMATICAL ITALIC
%% SMALL A (Restricted); the other normalises first and then runs the same check,
%% seeing U+0061 'a' (Allowed) and accepting. The attacker controls which stage
%% processes the input and exploits the disagreement. The same shape covers
%% fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01), and Roman-numeral
%% (U+2163) compatibility forms.
%%
%% The detector fires on the form transition itself: it reports the first input
%% position whose `Identifier_Status' (Allowed vs Restricted) differs from the
%% `Identifier_Status' of that codepoint's NFKD head. The verdict carries the
%% total shift count across the input.
%%
%% Note on Hangul: precomposed syllables are Allowed while their NFKD-head jamos
%% are Restricted, so pure Korean text fires; callers intending to accept Korean
%% identifiers should apply NFC before evaluating admissibility.
%%
%% Every predicate reuses a table this port already bundles, never a host
%% normalization or identifier library:
%%   - the UTS #39 `Identifier_Status = Allowed' predicate via
%%     `usec_ucd:is_id_allowed/1' (the port's IdentifierStatus.txt Allowed-set,
%%     shared with HomoglyphConfusable / MixedScriptAdmissibility);
%%   - the UAX #15 compatibility decomposition + canonical reorder via
%%     `usec_ucd:to_nfkd/1' (the port's NFKD pipeline, shared with
%%     NormalizationBomb and the NFKC path).
%%
%% Sub-threat (direction-agnostic):
%%   IdentifierStatusShift — the first input position whose `Identifier_Status'
%%   differs from its NFKD-head's.

-module(usec_identifier_form_drift).

-export([sub_threat_tag/1,
         classify_tag/1, classify_positions/1, is_clear/1,
         nfkd_head_allowed/1,
         detect/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Types
%% ─────────────────────────────────────────────────────────────────────
%%
%% SubThreat — one tuple per rust variant (there is exactly one):
%%   {identifier_status_shift, BasePos, Cp}   a codepoint at BasePos whose
%%       `Identifier_Status' differs from its NFKD-head's (codepoint Cp).
%%
%% Classification — `clear' | {hazard, SubThreat, Positions, Decoded}. `Decoded'
%% is always the empty list here; it is kept for shape parity with the Lean
%% `Classification.hazard' decoded-byte projection.
%%
%% Verdict — a map #{input, classify, shift_count}. `shift_count' is the total
%% number of input positions whose status shifts under NFKD.

%% @doc Fixture-row tag string for a sub-threat tuple (matches `SubThreat.tag').
sub_threat_tag({identifier_status_shift, _BasePos, _Cp}) -> <<"IdentifierStatusShift">>.

%% @doc Human-facing tag for a classification, or `none' when clear.
classify_tag(clear) -> none;
classify_tag({hazard, Sub, _Positions, _Decoded}) -> sub_threat_tag(Sub).

%% @doc Implicated positions (empty when clear).
classify_positions(clear) -> [];
classify_positions({hazard, _Sub, Positions, _Decoded}) -> Positions.

%% @doc True iff the classification is `clear'.
is_clear(clear) -> true;
is_clear({hazard, _Sub, _Positions, _Decoded}) -> false.

%% ─────────────────────────────────────────────────────────────────────
%% §2 Core predicate (reuses the port's own Identifier_Status + NFKD)
%% ─────────────────────────────────────────────────────────────────────

%% @doc `Identifier_Status = Allowed' of the first codepoint of `Cp''s NFKD
%% form, or `Cp''s own status when NFKD is empty (defensive — `to_nfkd/1' is
%% total and returns at least `[Cp]'). Reuses `usec_ucd:is_id_allowed/1' and
%% `usec_ucd:to_nfkd/1'.
nfkd_head_allowed(Cp) ->
    case usec_ucd:to_nfkd([Cp]) of
        [Head | _Rest] -> usec_ucd:is_id_allowed(Head);
        [] -> usec_ucd:is_id_allowed(Cp)
    end.

%% ─────────────────────────────────────────────────────────────────────
%% §3 Sub-detectors
%% ─────────────────────────────────────────────────────────────────────

%% @doc Position and codepoint of the first input position whose
%% `is_id_allowed' differs from its NFKD-head's, or `none'.
first_status_shift(Input) -> first_status_shift(Input, 0).

first_status_shift([], _I) -> none;
first_status_shift([Cp | Rest], I) ->
    case usec_ucd:is_id_allowed(Cp) =/= nfkd_head_allowed(Cp) of
        true -> {I, Cp};
        false -> first_status_shift(Rest, I + 1)
    end.

%% @doc Total count of input positions where the per-cp status shifts under NFKD.
status_shift_count(Input) ->
    length([Cp || Cp <- Input, usec_ucd:is_id_allowed(Cp) =/= nfkd_head_allowed(Cp)]).

%% ─────────────────────────────────────────────────────────────────────
%% §4 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The IdentifierFormDrift detection function.
detect(Input) ->
    Classification = case first_status_shift(Input) of
                         {Pos, Cp} ->
                             {hazard, {identifier_status_shift, Pos, Cp}, [Pos], []};
                         none ->
                             clear
                     end,
    #{input => Input,
      classify => Classification,
      shift_count => status_shift_count(Input)}.
