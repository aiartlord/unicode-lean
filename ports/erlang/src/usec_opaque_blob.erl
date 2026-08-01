%%% Opaque text predicate — structurally valid UTF-8, size-bounded.
%%%
%%% No character-class or codepoint filtering beyond UTF-8 validity. Intended
%%% for callers who apply their own text hardening downstream; hardened
%%% identifier and printable profiles layer on top of this predicate. Byte
%%% sequences are lists of integers in this port. A blob is represented as
%%% #{value => Bytes, max_bytes => Max}; a rejected build returns the atom
%%% none.
-module(usec_opaque_blob).

-export([is_utf8_blob/1, make/2]).

%% Opaque-blob predicate: structurally valid UTF-8. Named so the "blob" framing
%% (no character-class hardening) is explicit at the call site.
-spec is_utf8_blob([byte()]) -> boolean().
is_utf8_blob(Data) ->
    usec_utf8:is_valid_utf8(Data).

%% Build a blob under the size bound MaxBytes. Returns none when either the
%% bound or UTF-8 validity is violated. (Named make/2 rather than of/2 because
%% `of` is an Erlang reserved word.)
-spec make([byte()], non_neg_integer()) -> #{value := [byte()], max_bytes := non_neg_integer()} | none.
make(Data, MaxBytes) when length(Data) > MaxBytes ->
    none;
make(Data, MaxBytes) ->
    case is_utf8_blob(Data) of
        true -> #{value => Data, max_bytes => MaxBytes};
        false -> none
    end.
