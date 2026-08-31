# frozen_string_literal: true

require_relative "../covert/bidi_control_balance"
require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Display
      # Right-to-left injection detection for left-to-right-declared fields.
      # Priority: (1) any bidi format-control fires BidiControlInLTRField; otherwise
      # (2) a leading strong-RTL codepoint fires FieldTakeover; otherwise
      # (3) mid-stream strong-RTL is classified by run length.
      module RtlInjection
        Detection = Struct.new(:sub, :positions)

        module_function

        def count_strong_rtl(input)
          input.count { |cp| Ucd.strong_rtl?(cp) }
        end

        def first_bidi_control_pos(input)
          input.each_index do |i|
            return i if Covert::BidiControlBalance.bidi_format_control?(input[i])
          end
          nil
        end

        # [position, is_rtl] of the first strong (L, R, or AL) codepoint.
        def first_strong_char(input)
          input.each_index do |idx|
            cp = input[idx]
            if Ucd.strong_rtl?(cp)
              return [idx, true]
            elsif Ucd.strong_ltr?(cp)
              return [idx, false]
            end
          end
          nil
        end

        def first_strong_rtl_pos(input)
          input.each_index { |i| return i if Ucd.strong_rtl?(input[i]) }
          nil
        end

        # [longest run length, that run's start] of strong-RTL codepoints.
        def longest_rtl_run(input)
          longest = 0
          longest_start = 0
          current = 0
          current_start = 0
          input.each_index do |idx|
            if Ucd.strong_rtl?(input[idx])
              new_start = current.zero? ? idx : current_start
              current += 1
              current_start = new_start
              if current > longest
                longest = current
                longest_start = new_start
              end
            else
              current = 0
            end
          end
          [longest, longest_start]
        end

        def phase3(input, strong_rtl, run_len, run_start)
          return Detection.new(nil, []) if strong_rtl.zero?
          return Detection.new("MixedOverflow", [run_start]) if run_len >= 4

          pos = first_strong_rtl_pos(input)
          if pos.nil?
            Detection.new(nil, [])
          else
            Detection.new("StrongRTLInLTR", [pos])
          end
        end

        # The declared display direction of the field holding an input. A caller
        # handling Hebrew, Arabic or Persian UI text declares its field
        # right-to-left; every other reading treats the input as a declared-LTR
        # string, under which right-to-left content is itself the hazard.
        #
        # Mirrors FieldDirection in
        # Unicode/Security/Display/RtlInjection.lean, that spec's alias for the
        # UAX #9 paragraph-direction vocabulary.
        module FieldDirection
          LTR = :ltr
          RTL = :rtl
        end

        # Detection in a field whose declared display direction is `direction`.
        #
        # A bidi format control reorders what a reviewer sees whichever way the
        # field runs, so Phase 1 holds unconditionally and trumps all.
        #
        # Phases 2 and 3 ask whether right-to-left text has taken over or been
        # spliced into a left-to-right field. That question has no premise in a
        # right-to-left field, where right-to-left text is the content. The
        # mirror-image hazard, strong-LTR injection into a right-to-left field,
        # belongs to the separate detector the scope note assigns it to.
        def detect_with_context(direction, input)
          strong_rtl = count_strong_rtl(input)
          run_len, run_start = longest_rtl_run(input)

          # Phase 1: bidi format-control trumps all, in either direction.
          pos = first_bidi_control_pos(input)
          return Detection.new("BidiControlInLTRField", [pos]) unless pos.nil?

          # A right-to-left field carrying right-to-left text carries its
          # content.
          return Detection.new(nil, []) if direction == FieldDirection::RTL

          # Phase 2: leading-RTL field-direction takeover.
          strong = first_strong_char(input)
          if !strong.nil? && strong[1]
            Detection.new("FieldTakeover", [strong[0]])
          else
            # Leading strong-LTR, or no strong char at all: fall to phase 3.
            phase3(input, strong_rtl, run_len, run_start)
          end
        end

        # Detection in a field declared left-to-right, the reading the module
        # scope note fixes for an undeclared field.
        def detect(input)
          detect_with_context(FieldDirection::LTR, input)
        end
      end
    end
  end
end
