# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Boundary
      # AdmissibilityFormDrift — cross-layer identifier-admissibility x form
      # drift (boundary-layer detector).
      #
      # Byte-faithful port of the verified Rust reference implementation and of
      # its Lean source of truth.
      #
      # Fires on inputs whose UTS #39 whole-string admissibility verdict differs
      # between the input and its NFKC form.  This is the string-level
      # complement of IdentifierFormDrift (which scans `Identifier_Status`
      # against the per-codepoint NFKD head): here the whole-string
      # admissibility predicate is evaluated twice — once on the input, once on
      # its NFKC normalisation.  The two are not redundant.  In particular, a
      # sequence of decomposed Hangul jamos passes the per-codepoint scan
      # cleanly (each jamo has identity NFKD and Restricted status on both
      # sides) but fires here: the jamo sequence is rejected by the
      # whole-string admissibility predicate, while its NFKC composition into a
      # precomposed Hangul syllable is accepted.
      #
      # It reuses the port's own UTS #39 admissibility predicate
      # (`Ucd.allowed_identifier?` = UAX #31 default identifier ∧ every
      # codepoint Allowed) and NFKC pipeline (`Ucd.to_nfkc`), never a host
      # normalization or identifier library.
      #
      # Sub-threat (direction-agnostic):
      #   AdmissibilityFormDrift — `allowed_identifier?(input) !=
      #   allowed_identifier?(to_nfkc(input))`.  The pair of booleans is carried
      #   so the verdict records which direction the drift goes; no position is
      #   reported because the predicate is whole-string.
      module AdmissibilityFormDrift
        # The sub-threat kind discriminant.  There is exactly one sub-threat, so
        # the dispatch is trivial, but it stays an explicit switch with an error
        # on the unreachable arm.
        module SubKind
          ADMISSIBILITY_FORM_DRIFT = :admissibility_form_drift
        end

        # A sub-threat this detector can fire.  `kind` is the discriminant;
        # `data` carries `input_admissible` (`allowed_identifier?(input)`) and
        # `nfkc_admissible` (`allowed_identifier?(to_nfkc(input))`).  `tag` maps
        # the discriminant to the stable wire tag with an exhaustive switch.
        SubThreat = Struct.new(:kind, :data) do
          def tag
            case kind
            when SubKind::ADMISSIBILITY_FORM_DRIFT then "AdmissibilityFormDrift"
            else
              raise "AdmissibilityFormDrift::SubThreat#tag: unknown kind #{kind.inspect}"
            end
          end
        end

        # Top-level classification.  `sub` is nil when clear; `positions` is the
        # implicated codepoint indices (always empty — the predicate is
        # whole-string); `decoded` is the decoded-byte projection (always empty,
        # kept for shape parity with the Lean `Classification.hazard`).
        Classification = Struct.new(:sub, :positions, :decoded) do
          def clear?
            sub.nil?
          end

          def tag
            sub.nil? ? nil : sub.tag
          end
        end

        # The structured output of `detect` (mirrors the Lean `Verdict`):
        # the scanned input, the classification, and the two admissibility
        # booleans it was decided from.
        Verdict = Struct.new(:input, :classify, :input_admissible, :nfkc_admissible)

        module_function

        # ── Sub-threat constructor ─────────────────────────────────────────

        # The whole-string admissibility verdict differs between the input
        # (`input_admissible`) and its NFKC form (`nfkc_admissible`).
        def admissibility_form_drift(input_admissible, nfkc_admissible)
          SubThreat.new(
            SubKind::ADMISSIBILITY_FORM_DRIFT,
            { input_admissible: input_admissible, nfkc_admissible: nfkc_admissible }
          )
        end

        # ── Classification constructors ────────────────────────────────────

        def clear
          Classification.new(nil, [], [])
        end

        def hazard(sub, positions, decoded)
          Classification.new(sub, positions, decoded)
        end

        # ── Top-level detection ────────────────────────────────────────────

        # The AdmissibilityFormDrift detection function.  Reuses the port's own
        # NFKC pipeline and whole-string admissibility predicate.
        def detect(input)
          nfkc = Ucd.to_nfkc(input)
          in_ok = Ucd.allowed_identifier?(input)
          nfkc_ok = Ucd.allowed_identifier?(nfkc)

          classification =
            if in_ok == nfkc_ok
              clear
            else
              hazard(admissibility_form_drift(in_ok, nfkc_ok), [], [])
            end

          Verdict.new(input.dup, classification, in_ok, nfkc_ok)
        end
      end
    end
  end
end
