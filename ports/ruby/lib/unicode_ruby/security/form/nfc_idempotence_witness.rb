# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Form
      # NFC-idempotence-witness detection — inputs not already in NFC (or,
      # failing that, not in NFKC), the silent normalization-drift class.
      # Reports the first divergent position: a mismatch against NFC is
      # NonNfcForm; a sequence already in NFC but not NFKC is NonNfkcCompatForm.
      module NfcIdempotenceWitness
        Detection = Struct.new(:sub, :positions)

        module_function

        def first_divergence(a, b)
          common = [a.length, b.length].min
          (0...common).each do |i|
            return i if a[i] != b[i]
          end
          return common if a.length != b.length

          nil
        end

        def detect(input)
          nfc = Ucd.to_nfc(input)
          pos = first_divergence(input, nfc)
          return Detection.new("NonNfcForm", [pos]) unless pos.nil?

          nfkc = Ucd.to_nfkc(input)
          pos = first_divergence(input, nfkc)
          return Detection.new("NonNfkcCompatForm", [pos]) unless pos.nil?

          Detection.new(nil, [])
        end
      end
    end
  end
end
