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

        def detect(input)
          strong_rtl = count_strong_rtl(input)
          run_len, run_start = longest_rtl_run(input)

          # Phase 1: bidi format-control trumps all.
          pos = first_bidi_control_pos(input)
          return Detection.new("BidiControlInLTRField", [pos]) unless pos.nil?

          # Phase 2: leading-RTL field-direction takeover.
          strong = first_strong_char(input)
          if !strong.nil? && strong[1]
            Detection.new("FieldTakeover", [strong[0]])
          else
            # Leading strong-LTR, or no strong char at all: fall to phase 3.
            phase3(input, strong_rtl, run_len, run_start)
          end
        end
      end
    end
  end
end
