%% case-expansion-mismatch — codepoints whose UAX #21 default-locale case mapping
%% changes the codepoint count (form-layer detector, layer F).
%%
%% Byte-faithful transliteration of the verified Rust reference implementation
%% (itself a port of the Lean `Unicode/Security/Form/CaseExpansionMismatch'
%% specification).
%%
%% Threat model. Tier A1..A2. An attacker submits text whose case-mapped form has
%% a different codepoint count than the input. A receiver that fixes a 16-byte
%% username column and stores toUpper(username) overflows when the user picks
%% "ßßßßßßßß" (8 in → 16 stored); a receiver that checks len(stored) == len(input)
%% rejects valid case-insensitive logins whose names expand under folding.
%% Examples: U+00DF ß toUpper → "SS", U+FB01 ﬁ toUpper → "FI", U+0130 İ toLower
%% under the default locale → "i" + U+0307.
%%
%% Distinct from LocaleCaseInversion (case mapping that changes ACROSS locales):
%% this fires on shapes whose mapping is locale-stable but length-changing under
%% the default locale itself.
%%
%% It reuses the port's own UAX #21 case mapping — `usec_casing:upper_codepoint/4'
%% and `usec_casing:lower_codepoint/4', which evaluate the SpecialCasing context
%% predicates — never a host casing library.
%%
%% Sub-threats (priority order):
%%   1. UpperExpansion — first position whose default `upper_codepoint' yields > 1 cp.
%%   2. LowerExpansion — first position whose default `lower_codepoint' yields > 1 cp
%%      (reached only when no upper expansion fires first).

-module(usec_case_expansion_mismatch).

-export([sub_threat_tag/1,
         classify_tag/1, classify_positions/1, is_clear/1,
         detect/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Types
%% ─────────────────────────────────────────────────────────────────────
%%
%% SubThreat — one tuple per rust variant, in priority order:
%%   {upper_expansion, BasePos, Cp, ExpansionLen}   a codepoint at BasePos whose
%%       default uppercase mapping expands to ExpansionLen (> 1) codepoints.
%%   {lower_expansion, BasePos, Cp, ExpansionLen}   a codepoint at BasePos whose
%%       default lowercase mapping expands to ExpansionLen (> 1) codepoints.
%%
%% Classification — `clear' | {hazard, SubThreat, Positions, Decoded}. `Decoded'
%% is always the empty list here; it is kept for shape parity with the Lean
%% `Classification.hazard' decoded-byte projection.
%%
%% Verdict — a map #{input, classify, upper_expansion_count, lower_expansion_count,
%% max_expansion_len}. `max_expansion_len' is the maximum case-mapped expansion
%% length across all positions (upper or lower), 0 for empty input.

%% @doc Fixture-row tag string for a sub-threat tuple (matches `SubThreat.tag').
sub_threat_tag({upper_expansion, _BasePos, _Cp, _ExpansionLen}) -> <<"UpperExpansion">>;
sub_threat_tag({lower_expansion, _BasePos, _Cp, _ExpansionLen}) -> <<"LowerExpansion">>.

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
%% §2 Per-position expansion scan
%% ─────────────────────────────────────────────────────────────────────
%%
%% At position `I': `rev_prefix' is the preceding codepoints nearest-first
%% (input[..i] reversed), `suffix' the strictly-following ones (input[i+1..]).
%% The default-locale mapping is evaluated in that context.

%% @doc The per-position expansion lengths in one left-to-right pass, as
%% `{Pos, Cp, UpperLen, LowerLen}' in input order. The reversed prefix grows by
%% one codepoint per step and the suffix is the rest of the list, so the scan
%% is linear where a split per position was quadratic.
expansion_lens(Input) -> expansion_lens(Input, 0, [], []).

expansion_lens([], _I, _RevPrefix, Acc) ->
    lists:reverse(Acc);
expansion_lens([Cp | Suffix], I, RevPrefix, Acc) ->
    Upper = length(usec_casing:upper_codepoint(default, RevPrefix, Suffix, Cp)),
    Lower = length(usec_casing:lower_codepoint(default, RevPrefix, Suffix, Cp)),
    expansion_lens(Suffix, I + 1, [Cp | RevPrefix], [{I, Cp, Upper, Lower} | Acc]).

%% @doc First position whose default uppercase mapping expands to > 1 codepoint,
%% as {Pos, Cp, Len}, or `none'.
first_upper_expansion(Lens) ->
    first_expansion([{I, Cp, Upper} || {I, Cp, Upper, _Lower} <- Lens]).

%% @doc First position whose default lowercase mapping expands to > 1 codepoint,
%% as {Pos, Cp, Len}, or `none'.
first_lower_expansion(Lens) ->
    first_expansion([{I, Cp, Lower} || {I, Cp, _Upper, Lower} <- Lens]).

first_expansion([]) -> none;
first_expansion([{I, Cp, Len} | _Rest]) when Len > 1 -> {I, Cp, Len};
first_expansion([_ | Rest]) -> first_expansion(Rest).

%% @doc Count of positions whose default uppercase mapping expands.
upper_expansion_count(Lens) ->
    length([I || {I, _Cp, Upper, _Lower} <- Lens, Upper > 1]).

%% @doc Count of positions whose default lowercase mapping expands.
lower_expansion_count(Lens) ->
    length([I || {I, _Cp, _Upper, Lower} <- Lens, Lower > 1]).

%% @doc Maximum case-mapped expansion length across all positions (upper or
%% lower); 0 for empty input.
max_expansion_len([]) -> 0;
max_expansion_len(Lens) ->
    lists:max([max(Upper, Lower) || {_I, _Cp, Upper, Lower} <- Lens]).

%% ─────────────────────────────────────────────────────────────────────
%% §3 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The CaseExpansionMismatch detection function.
detect(Input) ->
    Lens = expansion_lens(Input),
    Classification = classify(Lens),
    #{input => Input,
      classify => Classification,
      upper_expansion_count => upper_expansion_count(Lens),
      lower_expansion_count => lower_expansion_count(Lens),
      max_expansion_len => max_expansion_len(Lens)}.

%% @doc Classification by first trigger in priority order: UpperExpansion then
%% LowerExpansion; `clear' when neither fires. Reads the one-pass expansion
%% lengths.
classify(Lens) ->
    case first_upper_expansion(Lens) of
        {Pos, Cp, Len} ->
            {hazard, {upper_expansion, Pos, Cp, Len}, [Pos], []};
        none ->
            case first_lower_expansion(Lens) of
                {Pos, Cp, Len} ->
                    {hazard, {lower_expansion, Pos, Cp, Len}, [Pos], []};
                none ->
                    clear
            end
    end.
