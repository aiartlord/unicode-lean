%%% Refinement type for bytes validated as strict RFC 3629 UTF-8.
%%%
%%% The validity claim is pinned at the module boundary: the only way to build a
%%% validated value is via validate/1, which routes through the strict decoder
%%% state machine. A consumer that wants the raw bytes calls unwrap/1, which
%%% reads as "I am consuming the RFC 3629 claim here". Byte sequences are lists
%%% of integers in this port; a validated value is the tagged tuple
%%% {validated_utf8, Bytes} and a rejected validation returns the atom none.
-module(usec_validated_utf8).

-export([validate/1, as_bytes/1, unwrap/1]).

-type validated() :: {validated_utf8, [byte()]}.
-export_type([validated/0]).

%% Validate Data and, on success, return a validated value carrying the
%% RFC 3629 validity claim. Returns none when the bytes fail the strict machine.
-spec validate([byte()]) -> validated() | none.
validate(Data) ->
    case usec_utf8:is_valid_utf8(Data) of
        true -> {validated_utf8, Data};
        false -> none
    end.

%% Borrow the validated bytes.
-spec as_bytes(validated()) -> [byte()].
as_bytes({validated_utf8, Bytes}) ->
    Bytes.

%% Consume the validity claim, returning the underlying bytes.
-spec unwrap(validated()) -> [byte()].
unwrap({validated_utf8, Bytes}) ->
    Bytes.
