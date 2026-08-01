# frozen_string_literal: true

require_relative "test_helper"

class DetectorFixturesTest < Minitest::Test
  include RubyPortTestHelpers

  Policy = UnicodeRuby::Security::Policy

  DETECTOR_FIXTURES = [
    "tag_block_payload.json",
    "variation_selector_payload.json",
    "zero_width_payload.json",
    "surrogate_reassembly.json",
    "bidi_control_balance.json",
    "noncharacter_control.json",
    "homoglyph_confusable.json",
    "mixed_script_admissibility.json",
    "rtl_injection.json",
    "covert_display_compound.json",
    "confusable_bidi_compound.json"
  ].freeze

  def test_detector_fixture_cases
    DETECTOR_FIXTURES.each do |name|
      fixture = fixture_json("detectors", name)
      assert_equal 1, fixture.fetch("schema"), name
      family = fixture.fetch("family")

      fixture.fetch("cases").each do |case_data|
        verdict = Policy.scan(Policy::Profile::GATEWAY_HEADER, Policy::Mode::OBSERVE, case_data.fetch("input"))
        codes = verdict.findings.map(&:code)
        case_data.fetch("required_findings").each do |required|
          assert_includes codes, required, "#{name}/#{case_data.fetch("name")}"
        end
        next unless case_data.fetch("required_findings").empty?

        assert codes.none? { |code| code.include?(".#{family}.") },
               "#{name}/#{case_data.fetch("name")}: unexpected #{family} in #{codes.sort.inspect}"
      end
    end
  end
end
