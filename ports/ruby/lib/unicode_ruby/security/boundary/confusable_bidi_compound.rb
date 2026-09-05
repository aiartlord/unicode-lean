# frozen_string_literal: true

require_relative "../covert/bidi_control_balance"
require_relative "../display/bidi_control_purpose"
require_relative "../identity/homoglyph_confusable"

module UnicodeRuby
  module Security
    module Boundary
      # Confusable-in-bidi-context compound detector (CVE-2021-42574 class).
      # Fires only when a confusable source co-locates with a purposeless bidi
      # control (`Display::BidiControlPurpose`: unbalanced, or a balanced span
      # enclosing nothing right-to-left in a left-to-right context); a balanced
      # embedding around Arabic text renders that text as written.
      module ConfusableBidiCompound
        Detection = Struct.new(:sub, :positions)

        module_function

        # Override-class bidi control (LRE, RLE, LRO, RLO, PDF).
        def override?(cp)
          Covert::BidiControlBalance.opens_embedding?(cp) ||
            Covert::BidiControlBalance.pdf?(cp)
        end

        # Isolate-class bidi control (LRI, RLI, FSI, PDI).
        def isolate?(cp)
          Covert::BidiControlBalance.opens_isolate?(cp) ||
            Covert::BidiControlBalance.pdi?(cp)
        end

        def first_pos(input)
          input.each_index { |i| return i if yield(input[i]) }
          nil
        end

        # The first position of a purposeless bidi control satisfying the block,
        # or nil. Mirrors the Lean firstOverridePos / firstIsolatePos over the
        # purposeless positions.
        def first_purposeless_pos(input)
          Display::BidiControlPurpose.purposeless_control_positions(input).each do |pos|
            return pos if yield(input[pos])
          end
          nil
        end

        def detect(input)
          confusable_pos = first_pos(input) { |cp| Identity::HomoglyphConfusable.confusable_source?(cp) }
          return Detection.new(nil, []) if confusable_pos.nil?

          override_pos = first_purposeless_pos(input) { |cp| override?(cp) }
          unless override_pos.nil?
            return Detection.new("ConfusableInOverride", [confusable_pos, override_pos])
          end

          isolate_pos = first_purposeless_pos(input) { |cp| isolate?(cp) }
          unless isolate_pos.nil?
            return Detection.new("ConfusableInIsolate", [confusable_pos, isolate_pos])
          end

          Detection.new(nil, [])
        end
      end
    end
  end
end
