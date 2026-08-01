ExUnit.start()

defmodule UnicodeSecurity.TestHelpers do
  alias UnicodeSecurity.Policy

  def fixture_json(relative) do
    Path.join([__DIR__, "fixtures", "security", relative])
    |> File.read!()
    |> JSON.decode!()
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
