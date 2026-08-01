//! Byte-layer refinements over strict RFC 3629 UTF-8.
//!
//! Two refinement types are exposed here, both pinned at the
//! module-boundary level to the port's strict decoder state machine
//! (`security.isValidUtf8`, backed by `firstInvalidUtf8Offset`) — never
//! `std.unicode`. Callers apply their own character-class hardening
//! downstream; hardened identifier and printable profiles layer on top.
//!
//!   * `Utf8Blob`  — structurally valid UTF-8, carrying a size bound.
//!   * `ValidatedUtf8` — bytes validated as strict RFC 3629 UTF-8, with
//!     the validity claim held at the module boundary.

const std = @import("std");
const security = @import("security.zig");

/// Opaque-blob predicate: structurally valid UTF-8. Exposed under this
/// name so the "blob" framing — no character-class hardening — is
/// explicit at the call site.
pub fn isUtf8Blob(bytes: []const u8) bool {
    return security.isValidUtf8(bytes);
}

/// A byte slice carrying its size bound and UTF-8 validity claim. The
/// constructor is intentionally hidden; `Utf8Blob.of` is the only entry
/// point. The `value` slice is borrowed, not owned — its lifetime is the
/// caller's responsibility.
pub const Utf8Blob = struct {
    value: []const u8,
    max_bytes: usize,

    /// Build a `Utf8Blob` under the size bound `max_bytes`. Returns
    /// `null` when either the bound or UTF-8 validity is violated.
    pub fn of(data: []const u8, max_bytes: usize) ?Utf8Blob {
        if (data.len > max_bytes) {
            return null;
        }
        if (!isUtf8Blob(data)) {
            return null;
        }
        return .{ .value = data, .max_bytes = max_bytes };
    }

    /// The underlying bytes.
    pub fn bytes(self: Utf8Blob) []const u8 {
        return self.value;
    }

    /// The declared size bound.
    pub fn maxBytes(self: Utf8Blob) usize {
        return self.max_bytes;
    }
};

/// A byte slice that has been validated as strict RFC 3629 UTF-8. The
/// constructor is intentionally hidden; `ValidatedUtf8.validate` is the
/// only blessed way to build one. The `value` slice is borrowed.
pub const ValidatedUtf8 = struct {
    value: []const u8,

    /// Validate a byte slice and, on success, return a `ValidatedUtf8`
    /// carrying the RFC 3629 validity claim. Returns `null` when the
    /// bytes fail the strict state machine.
    pub fn validate(data: []const u8) ?ValidatedUtf8 {
        if (security.isValidUtf8(data)) {
            return .{ .value = data };
        }
        return null;
    }

    /// Borrow the validated bytes.
    pub fn asBytes(self: ValidatedUtf8) []const u8 {
        return self.value;
    }

    /// Consume the validity claim, returning the underlying bytes. After
    /// this call the "these bytes are RFC 3629 valid" reasoning is owned
    /// by the caller, no longer held at the module boundary.
    pub fn unwrap(self: ValidatedUtf8) []const u8 {
        return self.value;
    }
};

const testing = std.testing;

test "isUtf8Blob accepts valid ascii, 2-byte, and 4-byte sequences" {
    try testing.expect(isUtf8Blob("hello"));
    // U+00E9 é = C3 A9 (2-byte); U+1F600 😀 = F0 9F 98 80 (4-byte).
    try testing.expect(isUtf8Blob(&[_]u8{ 0xC3, 0xA9 }));
    try testing.expect(isUtf8Blob(&[_]u8{ 0xF0, 0x9F, 0x98, 0x80 }));
    try testing.expect(isUtf8Blob(""));
}

test "isUtf8Blob rejects overlong C0 80 and surrogate ED A0 80" {
    try testing.expect(!isUtf8Blob(&[_]u8{ 0xC0, 0x80 }));
    try testing.expect(!isUtf8Blob(&[_]u8{ 0xED, 0xA0, 0x80 }));
    // Truncated 2-byte sequence: lead byte with no continuation.
    try testing.expect(!isUtf8Blob(&[_]u8{0xC3}));
}

test "Utf8Blob.of accepts valid input within bound" {
    const blob = Utf8Blob.of(&[_]u8{ 0xC3, 0xA9 }, 8) orelse
        return error.TestUnexpectedNull;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xC3, 0xA9 }, blob.bytes());
    try testing.expectEqual(@as(usize, 8), blob.maxBytes());
}

test "Utf8Blob.of rejects over-bound input" {
    // Five valid ASCII bytes, bound of four.
    try testing.expect(Utf8Blob.of("hello", 4) == null);
}

test "Utf8Blob.of rejects invalid utf8 even within bound" {
    try testing.expect(Utf8Blob.of(&[_]u8{ 0xED, 0xA0, 0x80 }, 16) == null);
}

test "Utf8Blob.of accepts empty under any bound" {
    try testing.expect(Utf8Blob.of("", 0) != null);
    try testing.expect(Utf8Blob.of("", 1024) != null);
}

test "ValidatedUtf8 validate + unwrap roundtrip" {
    const data = &[_]u8{ 0xF0, 0x9F, 0x98, 0x80 };
    const v = ValidatedUtf8.validate(data) orelse
        return error.TestUnexpectedNull;
    try testing.expectEqualSlices(u8, data, v.asBytes());
    try testing.expectEqualSlices(u8, data, v.unwrap());
}

test "ValidatedUtf8 validate rejects malformed input" {
    // Overlong, surrogate, and stray continuation byte all rejected.
    try testing.expect(ValidatedUtf8.validate(&[_]u8{ 0xC0, 0x80 }) == null);
    try testing.expect(ValidatedUtf8.validate(&[_]u8{ 0xED, 0xA0, 0x80 }) == null);
    try testing.expect(ValidatedUtf8.validate(&[_]u8{0x80}) == null);
}

test "ValidatedUtf8 validate accepts empty and ascii" {
    try testing.expect(ValidatedUtf8.validate("") != null);
    try testing.expect(ValidatedUtf8.validate("abc") != null);
}
