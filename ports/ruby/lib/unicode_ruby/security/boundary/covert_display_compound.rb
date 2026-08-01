# frozen_string_literal: true

require_relative "../covert/bidi_control_balance"
require_relative "../covert/variation_selector_payload"

module UnicodeRuby
  module Security
    module Boundary
      # Covert-display compound detector — a bidi control co-located with a
      # covert channel (an unregistered variation selector or a tag-block
      # character).  Fires only when a bidi control coincides with one of them.
      module CovertDisplayCompound
        Detection = Struct.new(:sub, :positions)

        module_function

        def tag_block_char?(cp)
          cp >= 0xE0000 && cp <= 0xE007F
        end

        def first_bidi_pos(input)
          input.each_index do |i|
            return i if Covert::BidiControlBalance.bidi_format_control?(input[i])
          end
          nil
        end

        # First position holding a suspicious variation selector — a VS that
        # does not form a registered (base, VS) pair with its predecessor.
        def first_suspicious_vs_pos(input)
          input.each_index do |i|
            cp = input[i]
            if Covert::VariationSelectorPayload.variation_selector?(cp) &&
               !(i > 0 && Covert::VariationSelectorPayload.registered_variation_pair?(input[i - 1], cp))
              return i
            end
          end
          nil
        end

        def first_tag_block_pos(input)
          input.each_index { |i| return i if tag_block_char?(input[i]) }
          nil
        end

        def detect(input)
          bidi_pos = first_bidi_pos(input)
          return Detection.new(nil, []) if bidi_pos.nil?

          vs_pos = first_suspicious_vs_pos(input)
          unless vs_pos.nil?
            return Detection.new("BidiPlusUnregisteredVs", [bidi_pos, vs_pos])
          end

          tag_pos = first_tag_block_pos(input)
          unless tag_pos.nil?
            return Detection.new("BidiPlusTagBlock", [bidi_pos, tag_pos])
          end

          Detection.new(nil, [])
        end
      end
    end
  end
end
