ExUnit.start()

defmodule UnicodeSecurity.TestHelpers do
  alias UnicodeSecurity.Policy

  def fixture_json(relative) do
    Path.join([__DIR__, "fixtures", "security", relative])
    |> File.read!()
    |> JSON.decode!()
  end

  @doc """
  One shared segmentation vector fixture: one case per UAX rule, the same bytes
  every port replays, so each port's segmentation tests ask the same questions
  rather than a per-port selection of them. The shape its callers rely on is
  established here before the document is returned.
  """
  def segmentation_fixture(name, algorithm) do
    document =
      Path.join([__DIR__, "fixtures", "segmentation", name])
      |> File.read!()
      |> JSON.decode!()

    ExUnit.Assertions.assert(document["schema"] == 1, "#{name} schema")
    ExUnit.Assertions.assert(document["algorithm"] == algorithm, "#{name} algorithm")
    ExUnit.Assertions.assert(document["cases"] != [], "#{name} carries no cases")
    document
  end

  @doc """
  Every case's boundary mask, reproduced, and how many were replayed. A failure
  names the rule and what the case is for, so the red reads as a sentence
  rather than an index.
  """
  def replay_segmentation_vectors(document, breaks_of) do
    Enum.each(document["cases"], fn case_data ->
      actual = breaks_of.(case_data["input"])

      ExUnit.Assertions.assert(
        actual == case_data["breaks"],
        "#{case_data["rule"]}: #{case_data["name"]}\n" <>
          "  cps      #{inspect(case_data["input"], base: :hex)}\n" <>
          "  expected #{inspect(case_data["breaks"])}\n" <>
          "  actual   #{inspect(actual)}"
      )
    end)

    length(document["cases"])
  end

  def codes(verdict), do: Enum.map(verdict.findings, & &1.code)

  def assert_required_findings_and_positions(case_data, verdict) do
    codes = codes(verdict)

    Enum.each(case_data["required_findings"], fn required ->
      ExUnit.Assertions.assert(required in codes, case_data["name"])
    end)

    positions_by_code =
      Map.new(verdict.findings, fn finding -> {finding.code, finding.positions} end)

    Enum.each(case_data["required_positions"], fn expected ->
      ExUnit.Assertions.assert(
        Map.fetch!(positions_by_code, expected["code"]) == expected["positions"],
        case_data["name"]
      )
    end)
  end

  def scan_encoded_case(case_data) do
    case case_data["encoding"] do
      "utf-8" ->
        Policy.scan_utf8(case_data["profile"], case_data["mode"], case_data["input_bytes"])

      "utf-16be" ->
        Policy.scan_utf16be(case_data["profile"], case_data["mode"], case_data["input_bytes"])

      "utf-16le" ->
        Policy.scan_utf16le(case_data["profile"], case_data["mode"], case_data["input_bytes"])

      "utf-32be" ->
        Policy.scan_utf32be(case_data["profile"], case_data["mode"], case_data["input_bytes"])

      "utf-32le" ->
        Policy.scan_utf32le(case_data["profile"], case_data["mode"], case_data["input_bytes"])
    end
  end
end
