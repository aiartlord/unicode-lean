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

%% @doc Length of the default-locale uppercase mapping at position `I'.
upper_len_at(Input, I) ->
    {RevPrefix, Cp, Suffix} = context_at(Input, I),
    length(usec_casing:upper_codepoint(default, RevPrefix, Suffix, Cp)).

%% @doc Length of the default-locale lowercase mapping at position `I'.
lower_len_at(Input, I) ->
    {RevPrefix, Cp, Suffix} = context_at(Input, I),
    length(usec_casing:lower_codepoint(default, RevPrefix, Suffix, Cp)).

%% @doc The (reversed-prefix, codepoint, suffix) context of position `I'.
context_at(Input, I) ->
    {Prefix, [Cp | Suffix]} = lists:split(I, Input),
    {lists:reverse(Prefix), Cp, Suffix}.

%% @doc First position whose default uppercase mapping expands to > 1 codepoint,
%% as {Pos, Cp, Len}, or `none'.
first_upper_expansion(Input) -> first_expansion(Input, 0, fun upper_len_at/2).

%% @doc First position whose default lowercase mapping expands to > 1 codepoint,
%% as {Pos, Cp, Len}, or `none'.
first_lower_expansion(Input) -> first_expansion(Input, 0, fun lower_len_at/2).

first_expansion(Input, I, LenFn) ->
    case I >= length(Input) of
        true -> none;
        false ->
            Len = LenFn(Input, I),
            case Len > 1 of
                true -> {I, lists:nth(I + 1, Input), Len};
                false -> first_expansion(Input, I + 1, LenFn)
            end
    end.

%% @doc Count of positions whose default uppercase mapping expands.
upper_expansion_count(Input) -> expansion_count(Input, fun upper_len_at/2).

%% @doc Count of positions whose default lowercase mapping expands.
lower_expansion_count(Input) -> expansion_count(Input, fun lower_len_at/2).

expansion_count(Input, LenFn) ->
    length([I || I <- indices(Input), LenFn(Input, I) > 1]).

%% @doc Maximum case-mapped expansion length across all positions (upper or
%% lower); 0 for empty input.
max_expansion_len([]) -> 0;
max_expansion_len(Input) ->
    lists:max([max(upper_len_at(Input, I), lower_len_at(Input, I)) || I <- indices(Input)]).

%% @doc The 0-based indices of `Input'.
indices([]) -> [];
indices(Input) -> lists:seq(0, length(Input) - 1).

%% ─────────────────────────────────────────────────────────────────────
%% §3 Top-level detection
%% ─────────────────────────────────────────────────────────────────────

%% @doc The CaseExpansionMismatch detection function.
detect(Input) ->
    Classification = classify(Input),
    #{input => Input,
      classify => Classification,
      upper_expansion_count => upper_expansion_count(Input),
      lower_expansion_count => lower_expansion_count(Input),
      max_expansion_len => max_expansion_len(Input)}.

%% @doc Classification by first trigger in priority order: UpperExpansion then
%% LowerExpansion; `clear' when neither fires.
classify(Input) ->
    case first_upper_expansion(Input) of
        {Pos, Cp, Len} ->
            {hazard, {upper_expansion, Pos, Cp, Len}, [Pos], []};
        none ->
            case first_lower_expansion(Input) of
                {Pos, Cp, Len} ->
                    {hazard, {lower_expansion, Pos, Cp, Len}, [Pos], []};
                none ->
                    clear
            end
    end.
