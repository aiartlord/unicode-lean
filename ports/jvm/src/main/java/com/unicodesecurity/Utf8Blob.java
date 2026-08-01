package com.unicodesecurity;

import java.util.Arrays;
import java.util.Optional;

// Opaque text refinement — structurally valid UTF-8, size-bounded.
//
// No character-class or codepoint filtering beyond UTF-8 validity. Intended
// for callers who apply their own text hardening downstream; hardened
// identifier and printable profiles layer on top of this predicate. A direct
// port of the Rust port's opaque_blob module (is_utf8_blob + Utf8Blob).
//
// The constructor is hidden; Utf8Blob.of is the only entry point, so the
// "blob" framing — bounded, structurally valid, no character-class hardening —
// is pinned at the module boundary. Validity is decided by the shared strict
// RFC 3629 decoder state machine via Security.isValidUtf8, never by a host
// round-trip.
public final class Utf8Blob {
  private final byte[] bytes;
  private final int maxBytes;

  private Utf8Blob(byte[] bytes, int maxBytes) {
    this.bytes = bytes;
    this.maxBytes = maxBytes;
  }

  // Opaque-blob predicate: structurally valid UTF-8. Exposed under this name so
  // the "blob" framing — no character-class hardening — is explicit at the call
  // site. Routes through the port's strict decoder, not new String(bytes, UTF_8).
  public static boolean isUtf8Blob(byte[] bytes) {
    return Security.isValidUtf8(bytes);
  }

  // Build a Utf8Blob under the size bound maxBytes. Returns an empty Optional
  // when either the bound or UTF-8 validity is violated. The bytes are copied
  // in, so a later mutation of the caller's array cannot invalidate the claim.
  public static Optional<Utf8Blob> of(byte[] data, int maxBytes) {
    if (data.length > maxBytes) {
      return Optional.empty();
    }
    if (!isUtf8Blob(data)) {
      return Optional.empty();
    }
    return Optional.of(new Utf8Blob(data.clone(), maxBytes));
  }

  // The underlying bytes. A fresh copy is returned so the carried validity and
  // size claims cannot be mutated out from under the value.
  public byte[] bytes() {
    return bytes.clone();
  }

  // The declared size bound.
  public int maxBytes() {
    return maxBytes;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof Utf8Blob blob)) return false;
    return maxBytes == blob.maxBytes && Arrays.equals(bytes, blob.bytes);
  }

  @Override
  public int hashCode() {
    return 31 * Arrays.hashCode(bytes) + maxBytes;
  }

  @Override
  public String toString() {
    return "Utf8Blob{len=" + bytes.length + ", maxBytes=" + maxBytes + "}";
  }
}
