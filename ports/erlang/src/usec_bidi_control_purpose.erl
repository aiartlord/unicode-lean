%% bidi-control-purpose — which bidi format controls serve a purpose, and which
%% do not.
%%
%% Direct port of `Unicode/Security/Display/BidiControlPurpose.lean'. The nine
%% UAX #9 format controls exist to manage right-to-left text: a span is doing
%% that job when the text it encloses is right-to-left, or when it forces
%% left-to-right text inside a right-to-left context. A span enclosing no strong
%% right-to-left character in a left-to-right context manages nothing (`LRI user
%% PDI' around Latin text, `LRO return PDF' around a keyword), and an unbalanced
%% control never manages anything. Every Trojan Source payload is a control of
%% that kind; a balanced embedding around an Arabic string literal is the
%% opposite case and renders the literal as written.
%%
%% This is not source-region filtering: the question is asked of every control
%% wherever it sits, and it is decided from the codepoints the span encloses,
%% never from where a tokenizer would place it.
%%
%% Rule, as the Lean `walk' states it:
%%   - An opener pushes a span: its position, whether it is an isolate (closed
%%     by PDI) or an embedding/override (closed by PDF), and whether it is
%%     right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right (LRE, LRO,
%%     LRI).
%%   - Every other codepoint is recorded against the innermost open span only:
%%     strong right-to-left (R or AL), strong left-to-right (L), or ASCII code
%%     syntax. A nested span manages its own content.
%%   - PDF closes the top span when it is an embedding; against an isolate on
%%     top, or an empty stack, it is an orphan. PDI closes down to the innermost
%%     isolate, implicitly terminating the embeddings above it, which are
%%     thereby unbalanced; with no isolate open it is an orphan.
%%   - A closed span is purposeful iff its direct content is exactly its own
%%     direction and carries no code syntax; a left-to-right span additionally
%%     needs right-to-left context (an enclosing right-to-left span, or a
%%     paragraph whose first strong character is right-to-left).
%%   - Reported: every orphan, every opener still open at the end, every
%%     embedding a PDI terminated implicitly, and both ends of every closed span
%%     that was not purposeful.
%%
%% The strong-direction predicates are the port's own `usec_ucd:is_strong_rtl/1'
%% / `usec_ucd:is_strong_ltr/1' over the pinned bidi table. Positions are
%% 0-based.

-module(usec_bidi_control_purpose).

-export([opens_rtl_kind/1, opens_ltr_kind/1, opens_isolate_kind/1,
         is_code_syntax/1, paragraph_is_rtl/1,
         purposeless_control_positions/1, has_purposeless_control/1,
         first_purposeless_control/1]).

%% @doc RLE, RLO, RLI, or FSI (whose direction resolves from its content).
opens_rtl_kind(Cp) -> lists:member(Cp, [16#202B, 16#202E, 16#2067, 16#2068]).

%% @doc LRE, LRO, LRI.
opens_ltr_kind(Cp) -> lists:member(Cp, [16#202A, 16#202D, 16#2066]).

%% @doc LRI, RLI, FSI.
opens_isolate_kind(Cp) -> lists:member(Cp, [16#2066, 16#2067, 16#2068]).

%% @doc The ASCII codepoints a Trojan Source payload moves: quotes, brackets,
%% comment markers, statement separators, operators. Prose punctuation, space
%% and digits are not in the set.
is_code_syntax(Cp) ->
    lists:member(Cp, [16#22, 16#27, 16#60, 16#28, 16#29, 16#5B, 16#5D, 16#7B,
                      16#7D, 16#2F, 16#5C, 16#2A, 16#23, 16#3B, 16#3C, 16#3E,
                      16#3D, 16#2B, 16#7C, 16#26, 16#25, 16#24, 16#40, 16#5E,
                      16#7E]).

%% @doc UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong
%% character is right-to-left.
paragraph_is_rtl([]) -> false;
paragraph_is_rtl([Cp | Rest]) ->
    case usec_ucd:is_strong_rtl(Cp) of
        true -> true;
        false ->
            case usec_ucd:is_strong_ltr(Cp) of
                true -> false;
                false -> paragraph_is_rtl(Rest)
            end
    end.

%% A closed span is purposeful iff its direct content is exactly its own
%% direction and carries no code syntax; a left-to-right span additionally needs
%% right-to-left context.
span_purposeful(#{rtl_kind := true, saw_rtl := SawRtl, saw_ltr := SawLtr, saw_syntax := SawSyntax},
                _Enclosing, _ParagraphRtl) ->
    SawRtl andalso not SawLtr andalso not SawSyntax;
span_purposeful(#{rtl_kind := false, saw_rtl := SawRtl, saw_ltr := SawLtr, saw_syntax := SawSyntax},
                Enclosing, ParagraphRtl) ->
    InRtlContext = ParagraphRtl orelse lists:any(fun(S) -> maps:get(rtl_kind, S) end, Enclosing),
    InRtlContext andalso SawLtr andalso not SawRtl andalso not SawSyntax.

%% @doc 0-based positions of the purposeless bidi format controls in the input,
%% in input order. Empty iff every control is balanced and manages right-to-left
%% text.
purposeless_control_positions(Input) ->
    ParagraphRtl = paragraph_is_rtl(Input),
    %% The stack's head is the innermost open span, as in the Lean list.
    {Stack, Reported} = walk(Input, 0, [], [], ParagraphRtl),
    %% Every opener still open at the end is unbalanced.
    lists:usort(Reported ++ [maps:get(pos, S) || S <- Stack]).

walk([], _Idx, Stack, Reported, _ParagraphRtl) ->
    {Stack, Reported};
walk([Cp | Rest], Idx, Stack, Reported, ParagraphRtl) ->
    IsOpener = opens_rtl_kind(Cp) orelse opens_ltr_kind(Cp),
    {Stack1, Reported1} =
        if
            IsOpener ->
                Span = #{pos => Idx,
                         isolate => opens_isolate_kind(Cp),
                         rtl_kind => opens_rtl_kind(Cp),
                         saw_rtl => false, saw_ltr => false, saw_syntax => false},
                {[Span | Stack], Reported};
            Cp =:= 16#202C ->
                %% PDF closes the top embedding; an isolate on top or an empty
                %% stack makes it an orphan.
                case Stack of
                    [#{isolate := false} = Top | Below] ->
                        case span_purposeful(Top, Below, ParagraphRtl) of
                            true -> {Below, Reported};
                            false -> {Below, Reported ++ [maps:get(pos, Top), Idx]}
                        end;
                    Other -> {Other, Reported ++ [Idx]}
                end;
            Cp =:= 16#2069 ->
                %% PDI closes down to the innermost isolate; the embeddings above
                %% it are terminated implicitly and so unbalanced. No isolate
                %% open: orphan.
                case lists:splitwith(fun(S) -> not maps:get(isolate, S) end, Stack) of
                    {Dropped, [Iso | Below]} ->
                        Reported2 = Reported ++ [maps:get(pos, D) || D <- Dropped],
                        case span_purposeful(Iso, Below, ParagraphRtl) of
                            true -> {Below, Reported2};
                            false -> {Below, Reported2 ++ [maps:get(pos, Iso), Idx]}
                        end;
                    {_NoIsolate, []} -> {Stack, Reported ++ [Idx]}
                end;
            true ->
                case Stack of
                    [Top | Below] ->
                        Top1 = Top#{saw_rtl := maps:get(saw_rtl, Top) orelse usec_ucd:is_strong_rtl(Cp),
                                    saw_ltr := maps:get(saw_ltr, Top) orelse usec_ucd:is_strong_ltr(Cp),
                                    saw_syntax := maps:get(saw_syntax, Top) orelse is_code_syntax(Cp)},
                        {[Top1 | Below], Reported};
                    [] -> {[], Reported}
                end
        end,
    walk(Rest, Idx + 1, Stack1, Reported1, ParagraphRtl).

%% @doc True iff the input carries at least one purposeless bidi format control.
has_purposeless_control(Input) -> purposeless_control_positions(Input) =/= [].

%% @doc 0-based position and codepoint of the first purposeless control as
%% `{Pos, Cp}', or `none' when every control is purposeful.
first_purposeless_control(Input) ->
    case purposeless_control_positions(Input) of
        [] -> none;
        [Pos | _Rest] -> {Pos, lists:nth(Pos + 1, Input)}
    end.
