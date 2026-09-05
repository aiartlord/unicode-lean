%% identifier-tokens — identifier-shaped tokens of a running-text field.
%%
%% Direct port of `Unicode/Security/Identity/IdentifierTokens.lean'. A source
%% line, a chat message or a display name is not one identifier, but the
%% identifier-shaped words inside it are the surface a homoglyph attack targets
%% (`scоpe' with a Cyrillic о in `let scоpe = 1;'). A token is a maximal run of
%% `XID_Continue' codepoints; everything else (space, punctuation, operators,
%% format controls) separates tokens. Each token carries its 0-based start
%% position so a finding made on the token can be reported in input
%% coordinates.
%%
%% `XID_Continue' is the port's own `usec_ucd:is_xid_continue/1' over the
%% bundled DerivedCoreProperties.txt.

-module(usec_identifier_tokens).

-export([tokens/1, shift_positions/2]).

%% @doc The maximal `XID_Continue' runs of the input, in input order, as
%% `#{start => Pos, cps => Cps}' maps.
tokens(Input) -> tokens(Input, 0, none, []).

%% The open run is carried reversed and flipped on close, as in the Lean.
tokens([], _Idx, none, Acc) ->
    lists:reverse(Acc);
tokens([], _Idx, Open, Acc) ->
    lists:reverse([close(Open) | Acc]);
tokens([Cp | Rest], Idx, Open, Acc) ->
    case usec_ucd:is_xid_continue(Cp) of
        true ->
            Open1 = case Open of
                        none -> #{start => Idx, cps => [Cp]};
                        #{cps := Cps} = Token -> Token#{cps := [Cp | Cps]}
                    end,
            tokens(Rest, Idx + 1, Open1, Acc);
        false ->
            case Open of
                none -> tokens(Rest, Idx + 1, none, Acc);
                Token -> tokens(Rest, Idx + 1, none, [close(Token) | Acc])
            end
    end.

close(#{cps := Cps} = Token) -> Token#{cps := lists:reverse(Cps)}.

%% @doc Move token-local positions back into input coordinates.
shift_positions(Start, Positions) -> [P + Start || P <- Positions].
