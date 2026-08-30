# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Boundary
      # IdentifierFormDrift — cross-layer identifier x form drift (boundary-layer
      # detector).
      #
      # Byte-faithful port of the verified Rust reference implementation and of
      # its Lean source of truth.
      #
      # Threat model.  Tier A2 two-system bypass.  An identity validator and a
      # form normalizer disagree about a codepoint: stage A runs the UTS #39
      # `Identifier_Status` check before normalisation and rejects, say, U+1D44E
      # MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and
      # then runs the same check, seeing U+0061 'a' (Allowed) and accepting.  The
      # attacker controls which stage processes the input and exploits the
      # disagreement.  The same shape covers fullwidth (U+FF21), circled
      # (U+24B6), ligature (U+FB01), and Roman-numeral (U+2163) compatibility
      # forms.
      #
      # The detector fires on the *form transition* itself — it reports every
      # input position whose `Identifier_Status` differs from the
      # `Identifier_Status` of that codepoint's NFKD head.  This is orthogonal to
      # the single-form identity-spoofing detectors (which examine the input
      # under one form) and stronger than a form-of-input fold (it asks whether
      # the identifier verdict changes, not whether any output bit changes).
      #
      # Note on Hangul: precomposed syllables are Allowed while their NFKD-head
      # jamos are Restricted, so pure Korean text fires; callers intending to
      # accept Korean identifiers should apply NFC before evaluating
      # admissibility.
      #
      # It reuses the port's own UTS #39 `Identifier_Status` predicate
      # (`Ucd.id_allowed?`) and NFKD pipeline
      # (`Ucd.to_nfkd`), never a host normalization or identifier
      # library.
      #
      # Sub-threat (direction-agnostic):
      #   IdentifierStatusShift — the first input position whose
      #   `Identifier_Status` differs from its NFKD-head's.  The verdict carries
      #   the total shift count.
      module IdentifierFormDrift
        # The sub-threat kind discriminant.  There is exactly one sub-threat, so
        # the dispatch is trivial, but it stays an explicit switch with an error
        # on the unreachable arm.
        module SubKind
          IDENTIFIER_STATUS_SHIFT = :identifier_status_shift
        end

        # A sub-threat this detector can fire.  `kind` is the discriminant;
        # `data` carries `base_pos` (position of the first status-shifting
        # codepoint) and `cp` (that codepoint).  `tag` maps the discriminant to
        # the stable wire tag with an exhaustive switch.
        SubThreat = Struct.new(:kind, :data) do
          def tag
            case kind
            when SubKind::IDENTIFIER_STATUS_SHIFT then "IdentifierStatusShift"
            else
              raise "IdentifierFormDrift::SubThreat#tag: unknown kind #{kind.inspect}"
            end
          end
        end

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
        Verdict = Struct.new(:input, :classify, :shift_count)

        module_function

        # ── Sub-threat constructor ─────────────────────────────────────────

        # A codepoint at `base_pos` whose `Identifier_Status` differs from its
        # NFKD-head's (codepoint `cp`).
        def identifier_status_shift(base_pos, cp)
          SubThreat.new(SubKind::IDENTIFIER_STATUS_SHIFT, { base_pos: base_pos, cp: cp })
        end

        # ── Classification constructors ────────────────────────────────────

        def clear
          Classification.new(nil, [], [])
        end

        def hazard(sub, positions, decoded)
          Classification.new(sub, positions, decoded)
        end

        # ── Core predicate (reuse the port's own tables) ───────────────────

        # `Identifier_Status = Allowed` of the first codepoint of `cp`'s NFKD
        # form, or `cp`'s own status when NFKD is empty (defensive — `to_nfkd` is
        # total and returns at least `[cp]`).  Reuses the port's own UTS #39
        # predicate and NFKD.
        def nfkd_head_allowed?(cp)
          head = Ucd.to_nfkd([cp]).first
          if head.nil?
            Ucd.id_allowed?(cp)
          else
            Ucd.id_allowed?(head)
          end
        end

        # ── Sub-detectors ──────────────────────────────────────────────────

        # First input position whose `id_allowed?` differs from its NFKD-head's,
        # as `[pos, cp]`, or nil.
        def first_status_shift(input)
          input.each_index do |idx|
            cp = input[idx]
            return [idx, cp] if !Ucd.id_allowed?(cp) && nfkd_head_allowed?(cp)
          end
          nil
        end

        # Total count of input positions where the per-cp status shifts under
        # NFKD.
        def status_shift_count(input)
          count = 0
          input.each do |cp|
            count += 1 if !Ucd.id_allowed?(cp) && nfkd_head_allowed?(cp)
          end
          count
        end

        # ── Top-level detection ────────────────────────────────────────────

        # The IdentifierFormDrift detection function.
        def detect(input)
          shift = first_status_shift(input)
          classification =
            if shift.nil?
              clear
            else
              pos, cp = shift
              hazard(identifier_status_shift(pos, cp), [pos], [])
            end

          Verdict.new(input.dup, classification, status_shift_count(input))
        end
      end
    end
  end
end
