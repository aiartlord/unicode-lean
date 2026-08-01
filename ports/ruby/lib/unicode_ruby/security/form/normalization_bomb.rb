# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Form
      # Normalization-bomb detection — inputs whose NFD or NFKD expansion
      # exceeds documented bounds, the classic normalization-expansion DoS.
      # Priority: a per-codepoint blow-up scan, an overall NFKD ratio, an
      # overall NFD ratio.  Ratios are expressed in hundredths to avoid floats.
      module NormalizationBomb
        # Maximum allowed NFKD expansion per single codepoint.
        MAX_NFKD_PER_CP = 8
        # Overall NFD expansion ratio threshold, in hundredths (300 = 3x).
        NFD_RATIO_PCT = 300
        # Overall NFKD expansion ratio threshold, in hundredths (400 = 4x).
        NFKD_RATIO_PCT = 400

        Detection = Struct.new(:sub, :positions)

        module_function

        # First position whose single-codepoint NFKD expansion exceeds the cap.
        def first_blowup_cp(input)
          input.each_index do |index|
            expand = Ucd.to_nfkd([input[index]]).length
            return index if expand > MAX_NFKD_PER_CP
          end
          nil
        end

        def nfd_ratio_pct(input)
          return 0 if input.empty?

          Ucd.to_nfd(input).length * 100 / input.length
        end

        def nfkd_ratio_pct(input)
          return 0 if input.empty?

          Ucd.to_nfkd(input).length * 100 / input.length
        end

        def detect(input)
          pos = first_blowup_cp(input)
          return Detection.new("SingleCpBlowup", [pos]) unless pos.nil?

          return Detection.new("NfkdHighExpansion", []) if nfkd_ratio_pct(input) > NFKD_RATIO_PCT
          return Detection.new("NfdHighExpansion", []) if nfd_ratio_pct(input) > NFD_RATIO_PCT

          Detection.new(nil, [])
        end
      end
    end
  end
end
