package com.unicodesecurity;

import java.util.Arrays;
import java.util.Optional;

// Refinement type for bytes validated as strict RFC 3629 UTF-8.
//
// The validity claim is pinned at the module boundary: the only way to build a
// ValidatedUtf8 is the smart constructor validate, which routes through the
// port's strict decoder state machine (Security.isValidUtf8), never a host
// round-trip such as new String(bytes, UTF_8). A direct port of the Rust port's
// validated_utf8 module.
//
// Rationale: the ingestion layer is security-critical. A bare byte[] carries no
// claim about its UTF-8 validity — downstream consumers have to re-validate or
// trust the producer. ValidatedUtf8 makes the claim module-level, so a consumer
// that wants the raw bytes has to explicitly unwrap — which reads as "I am
// consuming the RFC 3629 claim here".
public final class ValidatedUtf8 {
  private final byte[] bytes;

  private ValidatedUtf8(byte[] bytes) {
    this.bytes = bytes;
  }

  // Validate a byte array and, on success, return a ValidatedUtf8 carrying the
  // RFC 3629 validity claim. Returns an empty Optional when the bytes fail the
  // strict state machine. The bytes are copied in so the carried claim cannot be
  // invalidated by a later mutation of the caller's array.
  public static Optional<ValidatedUtf8> validate(byte[] data) {
    if (Security.isValidUtf8(data)) {
      return Optional.of(new ValidatedUtf8(data.clone()));
    }
    return Optional.empty();
  }

  // The validated bytes, as a fresh copy so the module-level claim stays intact.
  public byte[] asBytes() {
    return bytes.clone();
  }

  // Consume the validity claim, returning the underlying bytes. After this call
  // the validity claim is no longer carried at the module boundary — the caller
  // owns the "these bytes are RFC 3629 valid" reasoning from here forward.
  public byte[] unwrap() {
    return bytes.clone();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof ValidatedUtf8 that)) return false;
    return Arrays.equals(bytes, that.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }

  @Override
  public String toString() {
    return "ValidatedUtf8{len=" + bytes.length + "}";
  }
}
