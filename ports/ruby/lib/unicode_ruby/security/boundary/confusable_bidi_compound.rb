# frozen_string_literal: true

require_relative "../covert/bidi_control_balance"
require_relative "../identity/homoglyph_confusable"

module UnicodeRuby
  module Security
    module Boundary
      # Confusable-in-bidi-context compound detector (CVE-2021-42574 class).
      # Fires only when a confusable source co-locates with a bidi control.
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

        def detect(input)
          confusable_pos = first_pos(input) { |cp| Identity::HomoglyphConfusable.confusable_source?(cp) }
          return Detection.new(nil, []) if confusable_pos.nil?

          override_pos = first_pos(input) { |cp| override?(cp) }
          unless override_pos.nil?
            return Detection.new("ConfusableInOverride", [confusable_pos, override_pos])
          end

          isolate_pos = first_pos(input) { |cp| isolate?(cp) }
          unless isolate_pos.nil?
            return Detection.new("ConfusableInIsolate", [confusable_pos, isolate_pos])
          end

          Detection.new(nil, [])
        end
      end
    end
  end
end
