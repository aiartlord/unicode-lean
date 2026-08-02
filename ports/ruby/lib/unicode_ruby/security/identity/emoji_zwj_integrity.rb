# frozen_string_literal: true

require "set"

module UnicodeRuby
  module Security
    module Identity
      # EmojiZwjIntegrity — detection of malformed / unsanctioned emoji
      # ZWJ-sequence shapes per UTS #51 (the identity-layer detector I3).
      #
      # Byte-faithful port of the verified Rust reference
      # (`ports/rust/src/security/identity/emoji_zwj_integrity.rs`) and of
      # `Unicode/Security/Identity/EmojiZwjIntegrity.lean`.
      #
      # Threat model.  An adversary crafts an emoji-shaped codepoint sequence
      # containing one or more U+200D ZERO WIDTH JOINERs but violating the
      # sanctioned RGI ZWJ-sequence shape — by exceeding the RGI length cap, by
      # joining a non-emoji codepoint, by emitting adjacent ZWJ pairs, or by
      # overflowing the skin-tone count.  Any non-RGI ZWJ-containing sequence is
      # renderer-dependent, and that renderer divergence is the attack surface.
      #
      # Sanctioning data.  UTS #51 defines the RGI ZWJ sequences in
      # `emoji-zwj-sequences.txt`, bundled byte-identically in this port's own
      # `data/emoji-zwj-sequences.txt` and parsed here with the port's own text
      # idiom (never a host emoji library, never String normalization).  The
      # registered set gives both the exact-match membership test
      # (`registered_zwj_sequence?`) and the ZWJ *alphabet* — every distinct
      # codepoint occurring at any position of any registered sequence, excluding
      # the joiner — which is the canonical "what may flank a ZWJ?" predicate.
      #
      # Algorithm (one pass over `input`).
      #   Phase 1 — collect ZWJ positions and the skin-tone count.
      #   Phase 2 — short-circuit Clear if there are no ZWJs and the skin-tone
      #             count is at most 1.
      #   Phase 3 — a registered RGI sequence is always Clear.
      #   Phase 4 — check sub-threats by priority:
      #               1. DoubleZWJ            ZWJ-ZWJ adjacency
      #               2. NonEmojiInjection    ZWJ adjacent to a non-emoji codepoint
      #               3. OverLength           sequence longer than the RGI cap
      #               4. SkinToneOverflow     skin-tone count >= 5
      #               5. UnregisteredSequence catch-all when ZWJs are present but
      #                                       the sequence is not registered.
      module EmojiZwjIntegrity
        # Conservative cap on the length of a sanctioned RGI ZWJ sequence
        # (`maxRgiLength` in the Lean spec).  The longest current entry (a
        # four-person family with skin tones) reaches ~13-14 codepoints; 16 is a
        # safe upper bound.
        MAX_RGI_LENGTH = 16

        # The ZERO WIDTH JOINER codepoint.
        ZWJ = 0x200D

        # A sub-threat this detector can fire.  `tag` is the fixture-row / wire
        # tag string; `data` carries the variant-specific position payload
        # (`positions`, `zwj_pos` + `non_emoji_cp`, `length` + `max_length`,
        # `count`, or `chain_len`).
        SubThreat = Struct.new(:tag, :data)

        # Top-level classification.  `sub` is nil when clear; `positions` is the
        # codepoint indices the sub-threat implicates (empty when clear);
        # `decoded` is the decoded-byte projection (always empty for this
        # detector, kept for shape parity with the Lean `Classification.hazard`).
        Classification = Struct.new(:sub, :positions, :decoded) do
          def clear?
            sub.nil?
          end

          def tag
            sub.nil? ? nil : sub.tag
          end
        end

        # The structured output of `detect` (mirrors the Lean `Verdict`).
        # `chain_length` is 0 when there are no ZWJs, else the input length;
        # `is_registered_rgi` is true iff the input is exactly a registered RGI
        # ZWJ sequence; `skin_tone_count` counts U+1F3FB..U+1F3FF.
        Verdict = Struct.new(
          :input, :classify, :zwj_positions, :chain_length,
          :is_registered_rgi, :skin_tone_count
        )

        module_function

        # ── Sub-threat constructors ────────────────────────────────────────

        # ZWJ-ZWJ adjacency; `positions` are the first ZWJ of each adjacent pair.
        def double_zwj(positions)
          SubThreat.new("DoubleZWJ", { positions: positions })
        end

        # A ZWJ flanked by a non-emoji codepoint (or sitting at an input edge).
        # `non_emoji_cp` is the offending codepoint (0 for an edge ZWJ).
        def non_emoji_injection(zwj_pos, non_emoji_cp)
          SubThreat.new("NonEmojiInjection", { zwj_pos: zwj_pos, non_emoji_cp: non_emoji_cp })
        end

        # The sequence is longer than `MAX_RGI_LENGTH`.
        def over_length(length, max_length)
          SubThreat.new("OverLength", { length: length, max_length: max_length })
        end

        # Five or more skin-tone modifiers (the family-emoji maximum is four).
        def skin_tone_overflow(count)
          SubThreat.new("SkinToneOverflow", { count: count })
        end

        # ZWJs are present and no other sub-threat matched, but the sequence is
        # not a registered RGI ZWJ sequence.
        def unregistered_sequence(chain_len)
          SubThreat.new("UnregisteredSequence", { chain_len: chain_len })
        end

        # ── Classification constructors ────────────────────────────────────

        def clear
          Classification.new(nil, [], [])
        end

        def hazard(sub, positions, decoded)
          Classification.new(sub, positions, decoded)
        end

        # ── RGI ZWJ-sequence data (bundled data/emoji-zwj-sequences.txt) ────

        # Parse a hex codepoint token, or nil when the token is not all-hex.
        def parse_hex(str)
          token = str.strip
          return nil if token.empty?
          return nil unless token.match?(/\A[0-9A-Fa-f]+\z/)

          token.to_i(16)
        end

        # The registered RGI ZWJ sequences.  Each non-comment row is
        # `<cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ; <desc> # <cmt>`; the
        # codepoint list is the field before the first `;`.
        def zwj_sequences
          @zwj_sequences ||= parse_zwj_sequences
        end

        def parse_zwj_sequences
          out = []
          UnicodeRuby.read_data("emoji-zwj-sequences.txt").each_line do |raw|
            line = raw.chomp
            idx = line.index("#")
            body = idx.nil? ? line : line[0...idx]
            stripped = body.strip
            next if stripped.empty?

            seq_field = stripped.split(";").first
            next if seq_field.nil?

            seq = []
            parsed_ok = true
            seq_field.split.each do |token|
              cp = parse_hex(token)
              if cp.nil?
                parsed_ok = false
                break
              end
              seq << cp
            end
            out << seq if parsed_ok && !seq.empty?
          end
          out
        end

        # The ZWJ alphabet: every distinct codepoint occurring at any position of
        # any registered RGI ZWJ sequence, excluding the joiner U+200D itself.
        def zwj_alphabet
          @zwj_alphabet ||= build_zwj_alphabet
        end

        def build_zwj_alphabet
          set = Set.new
          zwj_sequences.each do |seq|
            seq.each do |cp|
              set.add(cp) if cp != ZWJ
            end
          end
          set
        end

        # True iff `cps` is exactly a registered RGI ZWJ sequence.
        def registered_zwj_sequence?(cps)
          zwj_sequences.any? { |seq| seq == cps }
        end

        # True iff `cp` appears at some position of a registered RGI ZWJ sequence
        # (the canonical "what may flank a ZWJ?" predicate).
        def emoji_target?(cp)
          zwj_alphabet.include?(cp)
        end

        # ── Core predicates ────────────────────────────────────────────────

        # True iff `cp` is the ZWJ codepoint.
        def zwj?(cp)
          cp == ZWJ
        end

        # True iff `cp` is an emoji skin-tone modifier (U+1F3FB..U+1F3FF).
        def emoji_modifier?(cp)
          cp >= 0x1F3FB && cp <= 0x1F3FF
        end

        # Positions of every ZWJ in `input`.
        def zwj_positions(input)
          out = []
          input.each_index { |i| out << i if zwj?(input[i]) }
          out
        end

        # Count of skin-tone modifier codepoints.
        def skin_tone_count(input)
          input.count { |cp| emoji_modifier?(cp) }
        end

        # Positions of the first ZWJ in each ZWJ-ZWJ adjacent pair.
        def double_zwj_positions(input)
          out = []
          (0...input.length).each do |idx|
            next_cp = input[idx + 1]
            unless next_cp.nil?
              out << idx if zwj?(input[idx]) && zwj?(next_cp)
            end
          end
          out
        end

        # The first ZWJ position where either neighbour is a non-emoji codepoint,
        # as `[zwj_pos, offending_cp]`, or nil when none.  A ZWJ at an input edge
        # (no preceding or no following codepoint) is itself an injection-class
        # hazard, reported with offending codepoint 0.
        def first_non_emoji_injection(input)
          (0...input.length).each do |idx|
            next unless zwj?(input[idx])

            prev = idx.zero? ? nil : input[idx - 1]
            nxt = input[idx + 1]
            if !prev.nil? && !nxt.nil?
              if !emoji_target?(prev)
                return [idx, prev]
              elsif !emoji_target?(nxt)
                return [idx, nxt]
              end
            elsif prev.nil?
              return [idx, 0]
            else
              return [idx, 0]
            end
          end
          nil
        end

        # ── Top-level detection ────────────────────────────────────────────

        # The EmojiZwjIntegrity detection function.
        def detect(input)
          zwjs = zwj_positions(input)
          st_count = skin_tone_count(input)
          is_rgi = registered_zwj_sequence?(input)
          chain_len = zwjs.empty? ? 0 : input.length

          if zwjs.empty? && st_count <= 1
            return Verdict.new(input.dup, clear, [], 0, is_rgi, st_count)
          end

          classification =
            if is_rgi
              # Phase 3: a registered RGI sequence is always clear.
              clear
            else
              # Phase 4.1: ZWJ-ZWJ adjacency.
              dzwj = double_zwj_positions(input)
              if !dzwj.empty?
                hazard(double_zwj(dzwj.dup), dzwj, [])
              else
                # Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
                injection = first_non_emoji_injection(input)
                if !injection.nil?
                  zwj_pos, offend_cp = injection
                  hazard(non_emoji_injection(zwj_pos, offend_cp), [zwj_pos], [])
                elsif input.length > MAX_RGI_LENGTH
                  # Phase 4.3: length cap.
                  hazard(over_length(input.length, MAX_RGI_LENGTH), [], [])
                elsif st_count >= 5
                  # Phase 4.4: skin-tone overflow.
                  hazard(skin_tone_overflow(st_count), [], [])
                elsif !zwjs.empty?
                  # Phase 4.5: catch-all for unregistered ZWJ sequences.
                  hazard(unregistered_sequence(input.length), zwjs.dup, [])
                else
                  clear
                end
              end
            end

          Verdict.new(input.dup, classification, zwjs, chain_len, is_rgi, st_count)
        end
      end
    end
  end
end
