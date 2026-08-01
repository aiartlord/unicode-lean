# frozen_string_literal: true

require "set"
require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Crypto
      # bip39-canonical: BIP-39 mnemonic canonicalisation + wordlist checks.
      # Canonical form is NFKD -> to_lower(default) -> collapse BIP-39
      # whitespace -> trim; detect runs six probes in priority order.
      module Bip39Canonical
        Detection = Struct.new(:sub, :positions, :language, :canonical, :word_count)

        # Wordlist files in Unicode.Generated.BIP39.allLanguages order.
        WORDLIST_FILES = [
          ["english", "english.txt"],
          ["japanese", "japanese.txt"],
          ["korean", "korean.txt"],
          ["spanish", "spanish.txt"],
          ["chinese_simplified", "chinese_simplified.txt"],
          ["chinese_traditional", "chinese_traditional.txt"],
          ["french", "french.txt"],
          ["italian", "italian.txt"],
          ["czech", "czech.txt"],
          ["portuguese", "portuguese.txt"]
        ].freeze

        module_function

        def wordlist_set(raw)
          set = Set.new
          raw.each_line do |line|
            word = line.chomp
            next if word.empty?

            set.add(word.chars.map(&:ord))
          end
          set
        end

        def wordlists
          @wordlists ||= WORDLIST_FILES.map do |name, file|
            [name, wordlist_set(UnicodeRuby.read_data(File.join("bip39", file)))]
          end
        end

        def split_words(canonical)
          words = []
          current = []
          canonical.each do |cp|
            if cp == 0x0020
              unless current.empty?
                words << current
                current = []
              end
            else
              current << cp
            end
          end
          words << current unless current.empty?
          words
        end

        def wordlists_containing(word)
          wordlists.select { |_name, set| set.include?(word) }.map { |name, _set| name }
        end

        def unique_language(words)
          pair = wordlists.find { |_name, set| words.all? { |w| set.include?(w) } }
          pair.nil? ? nil : pair[0]
        end

        def bip39_whitespace?(cp)
          cp == 0x0020 || cp == 0x3000
        end

        def collapse_whitespace_to_single(cps)
          out = []
          in_ws = false
          cps.each do |cp|
            if bip39_whitespace?(cp)
              out << 0x0020 unless in_ws
              in_ws = true
            else
              out << cp
              in_ws = false
            end
          end
          out
        end

        def trim_leading_trailing(cps)
          start = cps.index { |cp| cp != 0x0020 }
          return [] if start.nil?

          last = cps.rindex { |cp| cp != 0x0020 }
          endi = last.nil? ? start : last + 1
          cps[start...endi]
        end

        def bip39_canonical(cps)
          nfkd = Ucd.to_nfkd(cps)
          lowered = Ucd.to_lower(Ucd::Locale::DEFAULT, nfkd)
          collapsed = collapse_whitespace_to_single(lowered)
          trim_leading_trailing(collapsed)
        end

        def count_trailing_whitespace(cps)
          count = 0
          cps.reverse_each do |cp|
            break unless bip39_whitespace?(cp)

            count += 1
          end
          count
        end

        def first_uppercase_pos(cps)
          cps.index { |cp| cp >= 0x41 && cp <= 0x5A }
        end

        def first_whitespace_run_pos(cps)
          cps.each_index do |i|
            cp = cps[i]
            next unless bip39_whitespace?(cp)
            return i if i.zero?

            nxt = cps[i + 1]
            return i if !nxt.nil? && bip39_whitespace?(nxt)
          end
          nil
        end

        def first_array_divergence(a, b)
          n = [a.length, b.length].min
          (0...n).each do |i|
            return i if a[i] != b[i]
          end
          return n if a.length != b.length

          nil
        end

        # Six probes in priority order (first hit wins).
        def detect(input)
          canonical = bip39_canonical(input)
          words = split_words(canonical)
          word_count = words.length

          trailing_count = count_trailing_whitespace(input)
          uppercase_pos = first_uppercase_pos(input)
          whitespace_pos = first_whitespace_run_pos(input)
          nfkd = Ucd.to_nfkd(input)
          non_nfkd_pos = input == nfkd ? nil : first_array_divergence(input, nfkd)
          first_unknown_idx = words.index { |w| wordlists_containing(w).empty? }

          if trailing_count > 0
            Detection.new("TrailingWhitespace", [input.length - trailing_count], nil, canonical, word_count)
          elsif !uppercase_pos.nil?
            Detection.new("MixedCase", [uppercase_pos], nil, canonical, word_count)
          elsif !whitespace_pos.nil?
            Detection.new("WhitespaceAnomaly", [whitespace_pos], nil, canonical, word_count)
          elsif !non_nfkd_pos.nil?
            Detection.new("NonNFKD", [non_nfkd_pos], nil, canonical, word_count)
          elsif !first_unknown_idx.nil?
            Detection.new("WordlistMismatch", [first_unknown_idx], nil, canonical, word_count)
          else
            lang = unique_language(words)
            if lang.nil?
              Detection.new("LanguageAmbiguous", [], nil, canonical, word_count)
            else
              Detection.new(nil, [], lang, canonical, word_count)
            end
          end
        end
      end
    end
  end
end
