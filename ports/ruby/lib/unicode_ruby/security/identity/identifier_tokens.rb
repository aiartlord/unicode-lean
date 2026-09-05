# frozen_string_literal: true

require_relative "ucd"

module UnicodeRuby
  module Security
    module Identity
      # Identifier-shaped tokens of a running-text field.
      #
      # Direct port of `Unicode/Security/Identity/IdentifierTokens.lean`. A
      # source line, a chat message or a display name is not one identifier,
      # but the identifier-shaped words inside it are the surface a homoglyph
      # attack targets (`scоpe` with a Cyrillic о in `let scоpe = 1;`). A token
      # is a maximal run of `XID_Continue` codepoints; everything else (space,
      # punctuation, operators, format controls) separates tokens. Each token
      # carries its start position so a finding made on the token can be
      # reported in input coordinates.
      #
      # `XID_Continue` is the port's own `Ucd.xid_continue?` over the bundled
      # DerivedCoreProperties.txt.
      module IdentifierTokens
        # One identifier-shaped run: its start position in the input and its
        # codepoints.
        Token = Struct.new(:start, :cps)

        module_function

        # The maximal `XID_Continue` runs of the input, in input order.
        def tokens(input)
          out = []
          start = nil
          current = nil
          input.each_with_index do |cp, idx|
            if Ucd.xid_continue?(cp)
              if current.nil?
                current = []
                start = idx
              end
              current << cp
            elsif !current.nil?
              out << Token.new(start, current)
              current = nil
            end
          end
          out << Token.new(start, current) unless current.nil?
          out
        end

        # Move token-local positions back into input coordinates.
        def shift_positions(start, positions)
          positions.map { |pos| pos + start }
        end
      end
    end
  end
end
