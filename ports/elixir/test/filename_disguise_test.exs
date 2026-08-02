defmodule UnicodeSecurity.FilenameDisguiseTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Display.FilenameDisguise, as: FD
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  # Detector hazard tag for a bare-input detect.
  defp tag(input), do: FD.detect(input).classify |> FD.classification_tag()

  # ── Shared context-free fixture through detect ────────────────────────
  # The 10 shared vectors from
  # `fixtures/security/detectors/filename_disguise.json`, driven through the
  # policy reason-code machinery exactly as the sibling display detectors do.

  test "shared detector fixture" do
    fixture = fixture_json(Path.join("detectors", "filename_disguise.json"))

    Enum.each(fixture["cases"], fn case_data ->
      input = case_data["input"]
      classify = FD.detect(input).classify

      code =
        case FD.classification_tag(classify) do
          nil -> nil
          hazard_tag -> Policy.reason_code(:filename_disguise, hazard_tag)
        end

      required = case_data["required_findings"]

      Enum.each(required, fn expected ->
        assert code == expected,
               "#{case_data["name"]}: expected #{expected}, got #{inspect(code)}"
      end)

      if required == [] do
        assert code == nil, "#{case_data["name"]}: expected clear, got #{inspect(code)}"
      end
    end)
  end

  # ── The 10 rust reference spot-checks ─────────────────────────────────

  # `detect_empty_clear`
  test "empty is clear" do
    assert FD.is_clear(FD.detect([]).classify)
  end

  # `detect_plain_txt_clear` — "document.txt", last dot at 0-based 8.
  test "plain document.txt is clear" do
    v = FD.detect([0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74])
    assert FD.is_clear(v.classify)
    assert v.last_dot_pos == 8
  end

  # `detect_no_extension_clear` — "foo", no dot.
  test "no extension is clear" do
    v = FD.detect([0x66, 0x6F, 0x6F])
    assert FD.is_clear(v.classify)
    assert v.last_dot_pos == nil
  end

  # `detect_tar_gz_clear` — "archive.tar.gz" (2 dots, below the multi-ext bound).
  test "archive.tar.gz is clear" do
    assert FD.is_clear(
             FD.detect([0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A]).classify
           )
  end

  # `detect_rlo_flip` — "document<RLO>txt.exe", RLO at 0-based 8.
  test "rlo flip" do
    v = FD.detect([0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65])
    assert FD.classification_tag(v.classify) == "RloFlip"
    assert FD.classification_positions(v.classify) == [8]
  end

  # `detect_fullwidth_exe` — "file.ＥＸＥ".
  test "fullwidth extension" do
    assert tag([0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25]) == "WidthClassExt"
  end

  # `detect_combining_in_ext` — "file.e<combining acute>xe".
  test "combining mark in extension" do
    assert tag([0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65]) == "CombiningInExt"
  end

  # `detect_triple_extension` — "setup.tar.gz.sig" (3 dots).
  test "triple extension" do
    assert tag([0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A, 0x2E, 0x73, 0x69, 0x67]) ==
             "MultipleExtensions"
  end

  # `detect_hebrew_clear` — native Hebrew name, no bidi controls.
  test "hebrew native name is clear" do
    assert FD.is_clear(FD.detect([0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74]).classify)
  end

  # `detect_isolate_flip` — RLI/PDI isolate variant, also RloFlip.
  test "isolate flip" do
    assert tag([0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069]) == "RloFlip"
  end

  # ── priority-ladder structural check ──────────────────────────────────

  # A bidi control outranks a fullwidth extension.
  test "bidi control beats fullwidth extension" do
    assert tag([0x202E, 0x66, 0x2E, 0xFF25]) == "RloFlip"
  end
end
