# frozen_string_literal: true

require_relative "ucd"

module UnicodeRuby
  module Security
    module Identity
      # Detection of homoglyph / confusable identifier substitution attacks
      # (Nethereum Oct 2025, IDN homograph, Math-Alpha posing, fullwidth
      # disguise, decomposition swap, cross-script mixing).  Projects the input
      # and a curated attack-target list onto a UTS #39 §4 skeleton and tests
      # equality, layered with Mathematical Alphanumeric Symbols and
      # Halfwidth/Fullwidth Forms range detection.  Six sub-threats in fixed
      # priority order.
      module HomoglyphConfusable
        Verdict = Struct.new(
          :kind, :sub, :skeleton, :iterated_skeleton, :restriction_level,
          :matched_targets, :target
        )

        module_function

        def parse_hex(str)
          token = str.strip
          return nil if token.empty?
          return nil unless token.match?(/\A[0-9A-Fa-f]+\z/)

          token.to_i(16)
        end

        def confusables_map
          @confusables_map ||= parse_confusables
        end

        def parse_confusables
          m = {}
          UnicodeRuby.read_data("confusables.txt").each_line do |raw|
            hash = raw.index("#")
            body = (hash ? raw[0...hash] : raw)
            stripped = body.strip
            next if stripped.empty?

            parts = stripped.split(";", 3)
            next if parts.length < 2

            src = parse_hex(parts[0].strip)
            next if src.nil?

            tgt = parts[1].split(/\s+/).map { |t| parse_hex(t) }.compact
            next if tgt.empty?

            m[src] = tgt
          end
          m
        end

        # True iff `cp` is a confusable source per UTS #39 §4.
        def confusable_source?(cp)
          confusables_map.key?(cp)
        end

        # Cached [target_string, target_cps, target_letters] triples.
        def known_attack_targets
          @known_attack_targets ||= parse_known_attack_targets
        end

        def parse_known_attack_targets
          out = []
          UnicodeRuby.read_data("KnownAttackTargets.txt").each_line do |raw|
            trimmed = raw.strip
            next if trimmed.empty? || trimmed.start_with?("#")

            cps = trimmed.chars.map(&:ord)
            out << [trimmed, cps, letter_skeleton(cps)]
          end
          out
        end

        # True when the input violates the mixed-script admissibility policy.
        def has_mixed_script_admissibility(input)
          !mixed_script_verdict(input, true).nil?
        end

        # The specific script-collision sub-threat.  Latin/Cyrillic and
        # Latin/Greek are named explicitly (Cyrillic before Greek).
        def mixed_script_subthreat(input)
          mixed_script_verdict(input, true) || "ScriptMixOther"
        end

        # The mixed-script sub-threat for +input+, or nil when admissible.
        #
        # The rung order is MixedScriptAdmissibility.lean's: a Restricted-status
        # codepoint outranks every script question, then the two named Latin
        # pairs, then a multi-script mix split by whether it stays inside a CJK
        # covered set, and finally an Unrestricted level with no script mix.
        #
        # +identifier_field+ carries what the caller knows about the field,
        # mirroring that module's Context. Phase 1 is sound for an identifier,
        # which cannot contain a space, and unsound for a document, where every
        # space and every punctuation mark is Restricted.
        def mixed_script_verdict(input, identifier_field)
          if identifier_field && input.any? { |cp| !Ucd.id_allowed?(cp) }
            return "RestrictedStatusCp"
          end

          union = Ucd.string_script_union(input)
          has = ->(s) { union.include?(s) }
          return "LatinCyrillic" if has.call("Latn") && has.call("Cyrl")
          return "LatinGreek" if has.call("Latn") && has.call("Grek")

          if union.length >= 2 && !Ucd.highly_restrictive?(input)
            return Ucd.covered_cjk?(input) ? "CjkMix" : "ScriptMixOther"
          end
          if identifier_field && Ucd.restriction_level(input) == Ucd::RestrictionLevel::UNRESTRICTED
            return "UnrestrictedLevel"
          end

          nil
        end

        def substitute(input)
          map = confusables_map
          out = []
          input.each do |cp|
            rep = map[cp]
            if rep
              out.concat(rep)
            else
              out << cp
            end
          end
          out
        end

        # skeleton(X) = toNFD(caseFold(substitute(caseFold(toNFD(X))))).
        def skeleton(input)
          step1 = Ucd.to_nfd(input)
          step2 = Ucd.case_fold(step1)
          step3 = substitute(step2)
          step4 = Ucd.case_fold(step3)
          Ucd.to_nfd(step4)
        end

        # Apply skeleton until a fixed point is reached.
        def iterated_skeleton(input)
          current = input.dup
          loop do
            nxt = skeleton(current)
            return current if nxt == current

            current = nxt
          end
        end

        def letter_skeleton(input)
          letter_skeleton_from_iterated(iterated_skeleton(input))
        end

        def letter_skeleton_from_iterated(iterated)
          iterated.select do |cp|
            Ucd.ccc(cp) == 0 && !Ucd.default_ignorable?(cp) && !Ucd.white_space?(cp)
          end
        end

        def math_alphanumeric?(cp)
          cp >= 0x1D400 && cp <= 0x1D7FF
        end

        def fullwidth_halfwidth?(cp)
          cp >= 0xFF01 && cp <= 0xFFEF
        end

        def ascii_codepoints(str)
          str.chars.map(&:ord)
        end

        # Constant-time slice equality (result-equivalent to ==): walks the
        # whole slice with no early break when lengths match.
        def ct_slice_eq(a, b)
          return false if a.length != b.length

          acc = 0
          a.each_index { |i| acc |= (a[i] ^ b[i]) }
          acc.zero?
        end

        # First target whose letter skeleton matches the input's, walking the
        # entire curated list (no early break) and capturing the first match.
        def find_target_match(input, iterated)
          input_letters = letter_skeleton_from_iterated(iterated)
          first_match = nil
          known_attack_targets.each_with_index do |(_name, t_cps, t_letters), idx|
            next if t_cps == input

            is_match = ct_slice_eq(t_letters, input_letters)
            first_match = idx if is_match && first_match.nil?
          end
          first_match.nil? ? nil : known_attack_targets[first_match][0]
        end

        # First codepoint position at which `input` and its NFC form disagree.
        def first_decomposition_diff_pos(input, nfc)
          shorter = [input.length, nfc.length].min
          (0...shorter).each do |i|
            return i if input[i] != nfc[i]
          end
          shorter
        end

        def detect(input)
          skel = skeleton(input)
          iskel = iterated_skeleton(input)
          rl = Ucd.restriction_level(input)
          v = Verdict.new(Calculus::ClassificationKind::CLEAR, nil, skel, iskel, rl, [], nil)

          # Priority 1: target match.
          target = find_target_match(input, iskel)
          unless target.nil?
            v.kind = Calculus::ClassificationKind::HAZARD
            v.matched_targets << target
            v.sub = "TargetMatch"
            v.target = target
            return v
          end

          # Priority 2: Math Alphanumeric.
          if input.any? { |cp| math_alphanumeric?(cp) }
            v.kind = Calculus::ClassificationKind::HAZARD
            v.sub = "MathAlpha"
            return v
          end

          # Priority 3: Fullwidth/Halfwidth.
          if input.any? { |cp| fullwidth_halfwidth?(cp) }
            v.kind = Calculus::ClassificationKind::HAZARD
            v.sub = "WidthClass"
            return v
          end

          # Priority 4: DecompositionSwap.
          nfc = Ucd.to_nfc(input)
          if nfc != input
            v.kind = Calculus::ClassificationKind::HAZARD
            v.sub = "DecompositionSwap"
            return v
          end

          # Priority 5: CrossScriptMix.
          union = Ucd.string_script_union(input)
          if union.length >= 2 && !Ucd.highly_restrictive?(input)
            v.kind = Calculus::ClassificationKind::HAZARD
            v.sub = "CrossScriptMix"
            return v
          end

          # Priority 6: RestrictionLow.
          case rl
          when Ucd::RestrictionLevel::MINIMALLY_RESTRICTIVE,
               Ucd::RestrictionLevel::UNRESTRICTED
            v.kind = Calculus::ClassificationKind::HAZARD
            v.sub = "RestrictionLow"
            v
          when Ucd::RestrictionLevel::ASCII_ONLY,
               Ucd::RestrictionLevel::SINGLE_SCRIPT,
               Ucd::RestrictionLevel::HIGHLY_RESTRICTIVE,
               Ucd::RestrictionLevel::MODERATELY_RESTRICTIVE
            v
          else
            raise "homoglyph_confusable: unknown restriction level #{rl.inspect}"
          end
        end
      end
    end
  end
end
