defmodule UnicodeSecurity.Data do
  @moduledoc """
  Self-contained data access for the bundled UCD / security tables.

  Every file this port consumes at runtime lives under `priv/data/`; nothing
  outside `ports/elixir/` is ever read. Parsed tables are memoised in
  `:persistent_term` on first access, mirroring the lazy module-level caches the
  Python reference uses — the file is parsed once and every later lookup is an
  in-memory map/list access.
  """

  @doc "Absolute path to a bundled data file under `priv/data`."
  @spec path(String.t()) :: String.t()
  def path(name) do
    Path.join([:code.priv_dir(:unicode_security), "data", name])
  end

  @doc "Read a bundled data file's full contents as UTF-8 text."
  @spec read(String.t()) :: String.t()
  def read(name) do
    File.read!(path(name))
  end

  @doc """
  Return the memoised value for `key`, computing it with `fun` on first access.
  Subsequent calls return the cached term without re-parsing.
  """
  @spec cached(atom(), (-> term())) :: term()
  def cached(key, fun) do
    pt_key = {__MODULE__, key}

    case :persistent_term.get(pt_key, :__miss__) do
      :__miss__ ->
        value = fun.()
        :persistent_term.put(pt_key, value)
        value

      value ->
        value
    end
  end
end
