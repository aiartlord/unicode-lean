# frozen_string_literal: true

# Ruby port of the Unicode Security Conformance Layer.
#
# Byte-faithful translation of the Rust reference (`ports/rust/src/security/`)
# and structural mirror of the Python port (`ports/python/`).  All Unicode
# normalization and casing is computed from the pinned UCD 17.0.0 tables
# bundled under `ports/ruby/data/`; the port never uses Ruby's built-in
# String#unicode_normalize or String#downcase, which track the interpreter's
# own (possibly divergent) Unicode version.

module UnicodeRuby
  # Absolute path to this port's self-contained data directory.  The port
  # reads only files under `ports/ruby/` at runtime.
  DATA_DIR = File.expand_path("../data", __dir__)

  # Read a bundled data file to a String, resolved against DATA_DIR.
  def self.data_path(relative)
    File.join(DATA_DIR, relative)
  end

  def self.read_data(relative)
    File.read(data_path(relative), encoding: "UTF-8")
  end
end

require_relative "unicode_ruby/strict"
require_relative "unicode_ruby/noncharacters"
require_relative "unicode_ruby/utf8"
require_relative "unicode_ruby/opaque_blob"
require_relative "unicode_ruby/validated_utf8"
require_relative "unicode_ruby/segmentation/grapheme_tables"
require_relative "unicode_ruby/segmentation/grapheme"
require_relative "unicode_ruby/security/calculus"
require_relative "unicode_ruby/security/identity/ucd"
require_relative "unicode_ruby/security/covert/tag_block_payload"
require_relative "unicode_ruby/security/covert/variation_selector_payload"
require_relative "unicode_ruby/security/covert/zero_width_payload"
require_relative "unicode_ruby/security/covert/bidi_control_balance"
require_relative "unicode_ruby/security/covert/surrogate_reassembly"
require_relative "unicode_ruby/security/identity/homoglyph_confusable"
require_relative "unicode_ruby/security/identity/emoji_zwj_integrity"
require_relative "unicode_ruby/security/boundary/confusable_bidi_compound"
require_relative "unicode_ruby/security/boundary/covert_display_compound"
require_relative "unicode_ruby/security/display/rtl_injection"
require_relative "unicode_ruby/security/display/renderer_divergence"
require_relative "unicode_ruby/security/display/filename_disguise"
require_relative "unicode_ruby/security/form/locale_case_inversion"
require_relative "unicode_ruby/security/form/nfc_idempotence_witness"
require_relative "unicode_ruby/security/form/normalization_bomb"
require_relative "unicode_ruby/security/form/stream_safe_violation"
require_relative "unicode_ruby/security/crypto/bip39_canonical"
require_relative "unicode_ruby/security/crypto/hash_input_stability"
require_relative "unicode_ruby/security/crypto/ai_watermark_detectability"
require_relative "unicode_ruby/security/policy"
