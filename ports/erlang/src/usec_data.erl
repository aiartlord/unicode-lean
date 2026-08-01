%%% Self-contained UCD data-file location and text reading for the
%%% Unicode Security Conformance Layer.
%%%
%%% The port reads ONLY files inside `ports/erlang/priv/data/` at runtime.
%%% The directory is resolved relative to this module's compiled `.beam`
%%% location (`ebin/../priv/data`) so no application `.app` metadata is
%%% required; when that is unavailable the source-tree layout
%%% (`src/../priv/data`) is used as a fallback.  Parsed tables are memoised
%%% in `persistent_term` keyed by an atom, so each UCD file is parsed at
%%% most once per node.
-module(usec_data).

-export([data_dir/0, read_file/1, cached/2]).

%% @doc Absolute path of the bundled `priv/data` directory.
-spec data_dir() -> string().
data_dir() ->
    Beam = code:which(?MODULE),
    case Beam of
        Path when is_list(Path) ->
            Ebin = filename:dirname(Path),
            Root = filename:dirname(Ebin),
            Candidate = filename:join([Root, "priv", "data"]),
            case filelib:is_dir(Candidate) of
                true -> Candidate;
                false -> filename:join([Root, "data"])
            end;
        _ ->
            filename:join(["priv", "data"])
    end.

%% @doc Read a bundled data file, relative to `data_dir/0`, as a binary.
-spec read_file(string()) -> binary().
read_file(Name) ->
    Path = filename:join(data_dir(), Name),
    case file:read_file(Path) of
        {ok, Bin} -> Bin;
        {error, Reason} ->
            error({usec_data_read_failed, Path, Reason})
    end.

%% @doc Memoise `Build()` under `persistent_term` key `{?MODULE, Key}`.
%% The builder runs at most once; every later call returns the cached term.
-spec cached(term(), fun(() -> term())) -> term().
cached(Key, Build) ->
    PtKey = {?MODULE, Key},
    try persistent_term:get(PtKey)
    catch
        error:badarg ->
            Value = Build(),
            persistent_term:put(PtKey, Value),
            Value
    end.
