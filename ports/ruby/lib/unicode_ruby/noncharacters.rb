# frozen_string_literal: true

module UnicodeRuby
  # Detection and enumeration of the 66 designated Unicode noncharacters per
  # UAX #44 §5.6 / Unicode Standard 17.0 §23.7.
  #
  #   - BMP block:  U+FDD0 .. U+FDEF                (32 codepoints)
  #   - Plane ends: U+nnFFFE / U+nnFFFF for n=0..16 (34 codepoints)
  module Noncharacters
    module_function

    # Whether `cp` is one of the 66 designated Unicode noncharacters.
    def noncharacter?(cp)
      return true if cp >= 0xFDD0 && cp <= 0xFDEF
      return false if cp > 0x10FFFF

      low16 = cp & 0xFFFF
      low16 == 0xFFFE || low16 == 0xFFFF
    end

    # Enumerate the 66 noncharacters in ascending order.
    def all_noncharacters
      out = []
      (0xFDD0..0xFDEF).each { |cp| out << cp }
      (0..16).each do |n|
        out << (n * 0x10000 + 0xFFFE)
        out << (n * 0x10000 + 0xFFFF)
      end
      out
    end
  end
end
