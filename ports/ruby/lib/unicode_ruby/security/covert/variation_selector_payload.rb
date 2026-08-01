# frozen_string_literal: true

require "set"

module UnicodeRuby
  module Security
    module Covert
      # Detection of GlassWorm-class invisible payloads encoded in Unicode
      # variation selectors (U+FE00..U+FE0F, U+E0100..U+E01EF, U+180B..U+180D).
      # Exempts (base, VS) pairs registered in StandardizedVariants.txt and
      # emoji-variation-sequences.txt per UCD 17.0 / UTS #51.
      module VariationSelectorPayload
        Verdict = Struct.new(:kind, :sub, :vs_positions, :recovered_bytes)

        module_function

        def parse_hex(str)
          token = str.strip
          return nil if token.empty?
          return nil unless token.match?(/\A[0-9A-Fa-f]+\z/)

          token.to_i(16)
        end

        def legal_pairs
          @legal_pairs ||= parse_legal_pairs
        end

        def parse_legal_pairs
          out = Set.new
          ["StandardizedVariants.txt", "emoji-variation-sequences.txt"].each do |file|
            UnicodeRuby.read_data(file).each_line do |raw|
              hash = raw.index("#")
              body = (hash ? raw[0...hash] : raw)
              stripped = body.strip
              next if stripped.empty?

              semi = stripped.index(";")
              pair_part = semi ? stripped[0...semi] : stripped
              tokens = pair_part.split(/\s+/)
              next if tokens.length < 2

              base = parse_hex(tokens[0])
              vs = parse_hex(tokens[1])
              next if base.nil? || vs.nil?

              out.add([base, vs])
            end
          end
          out
        end

        # True iff (base, vs) is a registered variation sequence.
        def registered_variation_pair?(base, vs)
          legal_pairs.include?([base, vs])
        end

        def variation_selector?(cp)
          (cp >= 0xFE00 && cp <= 0xFE0F) ||
            (cp >= 0xE0100 && cp <= 0xE01EF) ||
            (cp >= 0x180B && cp <= 0x180D)
        end

        # Decode a single VS codepoint to its nibble value in [0, 255], or nil
        # for the Mongolian FVS codepoints.
        def vs_to_nibble(cp)
          if cp >= 0xFE00 && cp <= 0xFE0F
            cp - 0xFE00
          elsif cp >= 0xE0100 && cp <= 0xE01EF
            cp - 0xE0100 + 16
          end
        end

        def decode_vs_run(input, positions)
          out = []
          high = nil
          positions.each do |p|
            n = vs_to_nibble(input[p])
            next if n.nil?

            if high.nil?
              high = n
            else
              out << (((high << 4) | n) & 0xFF)
              high = nil
            end
          end
          out
        end

        def all_same_vs(input, positions)
          first = positions.first
          return true if first.nil?

          cp0 = input[first]
          positions.all? { |p| input[p] == cp0 }
        end

        def lossy_ascii(bytes)
          s = +""
          bytes.each do |b|
            s << if (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D
                   b.chr(Encoding::UTF_8)
                 else
                   "?"
                 end
          end
          s
        end

        def detect(input)
          vs_positions = []
          input.each_with_index { |cp, i| vs_positions << i if variation_selector?(cp) }

          if vs_positions.empty?
            return Verdict.new(Calculus::ClassificationKind::CLEAR, nil, [], [])
          end

          recovered_bytes = decode_vs_run(input, vs_positions)

          # Single-VS exemption: a registered (base, VS) pair is legitimate.
          if vs_positions.length == 1
            p = vs_positions[0]
            if p > 0 && registered_variation_pair?(input[p - 1], input[p])
              return Verdict.new(Calculus::ClassificationKind::CLEAR, nil, vs_positions, recovered_bytes)
            end
          end

          sub =
            if vs_positions.length >= 4 && all_same_vs(input, vs_positions)
              "RepeatedBase"
            elsif !recovered_bytes.empty?
              "DirectPayload"
            else
              "IllegalTarget"
            end

          Verdict.new(Calculus::ClassificationKind::HAZARD, sub, vs_positions, recovered_bytes)
        end
      end
    end
  end
end
