# frozen_string_literal: true

require_relative "utf8"

module UnicodeRuby
  # Opaque text predicate — structurally valid UTF-8, size-bounded.
  #
  # No character-class or codepoint filtering beyond UTF-8 validity. Intended
  # for callers who apply their own text hardening downstream; hardened
  # identifier and printable profiles layer on top of this predicate.
  module OpaqueBlob
    module_function

    # Opaque-blob predicate: structurally valid UTF-8. Exposed under this name
    # so the "blob" framing — no character-class hardening — is explicit at the
    # call site. +data+ is a byte array (Array<Integer>).
    def utf8_blob?(data)
      Utf8.valid?(data)
    end
  end

  # A byte sequence carrying its size bound and UTF-8 validity claim. Construct
  # via {Utf8Blob.of}.
  class Utf8Blob
    attr_reader :value, :max_bytes

    def initialize(value, max_bytes)
      @value = value
      @max_bytes = max_bytes
      freeze
    end

    # Build a Utf8Blob under the size bound +max_bytes+. Returns +nil+ when
    # either the bound or UTF-8 validity is violated.
    def self.of(data, max_bytes)
      return nil if data.length > max_bytes
      return nil unless OpaqueBlob.utf8_blob?(data)

      new(data, max_bytes)
    end
  end
end
