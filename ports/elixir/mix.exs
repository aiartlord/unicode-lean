defmodule UnicodeSecurity.MixProject do
  use Mix.Project

  # Elixir port of the Unicode Security Conformance Layer. The port is
  # self-contained: every UCD/security data file it reads at runtime lives
  # under `priv/data/`, digest-pinned by `priv/data/SHA256SUMS`. No external
  # (hex) dependencies — ExUnit and the built-in `JSON` module cover the
  # contract test suite offline.
  def project do
    [
      app: :unicode_security,
      version: "17.0.0",
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: false,
      deps: []
    ]
  end

  def application do
    [extra_applications: [:crypto]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
