# frozen_string_literal: true

require_relative "utf8"

module UnicodeRuby
  # Refinement type for bytes validated as strict RFC 3629 UTF-8.
  #
  # The validity claim is pinned at the module-boundary level: the only way to
  # construct a ValidatedUtf8 is via the smart constructor {ValidatedUtf8.validate},
  # which routes through the strict decoder state machine. A downstream consumer
  # that wants the raw bytes has to explicitly {unwrap} — which reads as "I am
  # consuming the RFC 3629 claim here".
  class ValidatedUtf8
    # Conventionally private; use {ValidatedUtf8.validate}. +bytes+ is a byte
    # array (Array<Integer>).
    def initialize(bytes)
      @bytes = bytes
      freeze
    end

    # Validate +data+ and, on success, return a ValidatedUtf8 carrying the
    # RFC 3629 validity claim. Returns +nil+ when the bytes fail the strict
    # state machine.
    def self.validate(data)
      return nil unless Utf8.valid?(data)

      new(data)
    end

    # Borrow the validated bytes.
    def as_bytes
      @bytes
    end
  end

  module ValidatedUtf8Ops
    module_function

    # Consume the validity claim, returning the underlying bytes. After this
    # call the validity claim is no longer carried at the module-boundary
    # level — the caller owns the "these bytes are RFC 3629 valid" reasoning.
    def unwrap(validated)
      validated.as_bytes
    end
  end
end
