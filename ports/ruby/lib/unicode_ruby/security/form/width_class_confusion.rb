# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Form
      # Width-class-confusion detection — UAX #11 East Asian Width class
      # confusion. A Fullwidth (EAW = F) or Halfwidth (EAW = H) codepoint whose
      # NFKD form carries a different EAW class is a compatibility-fold
      # homograph:
      #
      #   U+FF21 'Ａ' (F)  ->  U+0041 'A' (Na)
      #   U+FF11 '１' (F)  ->  U+0031 '1' (Na)
      #   U+FF71 'ｱ' (H)  ->  U+30A2 'ア' (W)
      #
      # The two-system bypass: a validator that whitelists ASCII rejects Ａ,
      # while a downstream NFKC step at storage or comparison time folds it to
      # plain A, so ＡＤＭＩＮ claims the username ADMIN.
      #
      # Distinct from RendererDivergence's FullwidthVariance, which fires on
      # F-class codepoints for renderer-cohort reasons; this is the NFKC-fold
      # verdict and both can fire on one input independently. Hangul syllables
      # decompose to jamos that are still W class, so pure Hangul stays clear.
      #
      # Direct port of Unicode/Security/Form/WidthClassConfusion.lean.
      module WidthClassConfusion
        Detection = Struct.new(:sub, :positions)

        module_function

        # True iff the NFKD head of cp carries a different EAW class.
        def width_fold?(cp)
          folded = Ucd.to_nfkd([cp])
          return false if folded.empty?

          Ucd.east_asian_width(folded[0]) != Ucd.east_asian_width(cp)
        end

        # First position whose codepoint has class `want` and folds away from it.
        def first_fold(input, want)
          input.each_with_index do |cp, index|
            return index if Ucd.east_asian_width(cp) == want && width_fold?(cp)
          end
          nil
        end

        def fold_count(input, want)
          input.count { |cp| Ucd.east_asian_width(cp) == want && width_fold?(cp) }
        end

        # A Fullwidth fold takes priority over a Halfwidth one, matching the
        # reference's sub-threat order.
        def detect(input)
          pos = first_fold(input, Ucd::EastAsianWidth::F)
          return Detection.new("FullwidthFold", [pos]) unless pos.nil?

          pos = first_fold(input, Ucd::EastAsianWidth::H)
          return Detection.new("HalfwidthFold", [pos]) unless pos.nil?

          Detection.new(nil, [])
        end
      end
    end
  end
end
