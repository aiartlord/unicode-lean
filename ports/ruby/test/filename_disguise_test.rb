# frozen_string_literal: true

require_relative "test_helper"

class FilenameDisguiseTest < Minitest::Test
  include RubyPortTestHelpers

  Fd = UnicodeRuby::Security::Display::FilenameDisguise
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  # ── (a) shared context-free detector fixture ─────────────────────────────
  #
  # The 10 shared vectors are context-free, so they exercise `detect` directly.
  # Each hazard tag maps to its stable reason code via the same Policy wiring
  # the sibling display detectors use.

  def code_for(input)
    tag = Fd.detect(input).classify.tag
    tag.nil? ? [] : [Policy.reason_code(Family::FILENAME_DISGUISE, tag)]
  end

  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "filename_disguise.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "filename-disguise", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      codes = code_for(case_data.fetch("input"))
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, name
      end
      next unless case_data.fetch("required_findings").empty?

      assert codes.none? { |code| code.include?(".filename-disguise.") },
             "#{name}: unexpected filename-disguise finding in #{codes.inspect}"
    end
  end

  # ── detect spot checks (one per Rust reference test) ─────────────────────

  def tag(input)
    Fd.detect(input).classify.tag
  end

  # `detect_empty_clear`
  def test_detect_empty_clear
    assert Fd.detect([]).classify.clear?
  end

  # `detect_plain_txt_clear` — "document.txt"
  def test_detect_plain_txt_clear
    v = Fd.detect([0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74])
    assert v.classify.clear?
    assert_equal 8, v.last_dot_pos
  end

  # `detect_no_extension_clear` — "foo"
  def test_detect_no_extension_clear
    v = Fd.detect([0x66, 0x6F, 0x6F])
    assert v.classify.clear?
    assert_nil v.last_dot_pos
  end

  # `detect_tar_gz_clear` — "archive.tar.gz" (2 dots, below the multi-ext bound)
  def test_detect_tar_gz_clear
    assert Fd.detect(
      [0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A]
    ).classify.clear?
  end

  # `detect_hebrew_clear` — native Hebrew name, no bidi controls.
  def test_detect_hebrew_clear
    assert Fd.detect([0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74]).classify.clear?
  end

  # `detect_rlo_flip` — "document<RLO>txt.exe"
  def test_detect_rlo_flip
    v = Fd.detect([
      0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74,
      0x2E, 0x65, 0x78, 0x65
    ])
    assert_equal "RloFlip", v.classify.tag
    assert_equal [8], v.classify.positions
  end

  # `detect_isolate_flip` — RLI/PDI isolate variant, also RloFlip.
  def test_detect_isolate_flip
    assert_equal "RloFlip",
                 tag([0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069])
  end

  # `detect_fullwidth_exe` — "file.ＥＸＥ"
  def test_detect_fullwidth_exe
    assert_equal "WidthClassExt", tag([0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25])
  end

  # `detect_combining_in_ext` — "file.é xe" (combining acute in the extension)
  def test_detect_combining_in_ext
    assert_equal "CombiningInExt", tag([0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65])
  end

  # `detect_triple_extension` — "setup.tar.gz.sig"
  def test_detect_triple_extension
    v = Fd.detect([
      0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A,
      0x2E, 0x73, 0x69, 0x67
    ])
    assert_equal "MultipleExtensions", v.classify.tag
  end

  # ── priority-ladder structural check ─────────────────────────────────────

  # A bidi control outranks a fullwidth extension.
  def test_bidi_beats_fullwidth
    assert_equal "RloFlip", tag([0x202E, 0x66, 0x2E, 0xFF25])
  end
end
