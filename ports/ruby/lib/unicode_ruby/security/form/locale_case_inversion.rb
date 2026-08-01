# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Form
      # Locale-case-inversion — inputs whose lowercase result inverts across
      # locales (CVE-2007-6692, CVE-2021-30245, the Spotify "İSTANBUL" class).
      # Compares per-position lower_codepoint under each locale against the
      # default; Turkish divergence (which covers Azeri) takes priority over
      # Lithuanian.
      module LocaleCaseInversion
        Detection = Struct.new(:sub, :positions)

        module_function

        # First input position whose lower_codepoint under `locale` differs from
        # the default-locale result, with the codepoint at that position.
        def first_locale_divergence(locale, input)
          rev_prefix = []
          input.each_with_index do |cp, index|
            suffix = input[(index + 1)..]
            default_lower = Ucd.lower_codepoint(Ucd::Locale::DEFAULT, rev_prefix, suffix, cp)
            locale_lower = Ucd.lower_codepoint(locale, rev_prefix, suffix, cp)
            return [index, cp] if default_lower != locale_lower

            rev_prefix.unshift(cp)
          end
          nil
        end

        def detect(input)
          turkish = first_locale_divergence(Ucd::Locale::TURKISH, input)
          return Detection.new("TurkishCaseDivergence", [turkish[0]]) unless turkish.nil?

          lithuanian = first_locale_divergence(Ucd::Locale::LITHUANIAN, input)
          return Detection.new("LithuanianCaseDivergence", [lithuanian[0]]) unless lithuanian.nil?

          Detection.new(nil, [])
        end
      end
    end
  end
end
