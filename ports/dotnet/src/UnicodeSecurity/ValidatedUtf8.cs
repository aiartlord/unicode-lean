// Refinement type for bytes validated as strict RFC 3629 UTF-8.
//
// The validity claim is pinned at the module-boundary level: the only way to
// construct a ValidatedUtf8 is via the smart constructor Validate, which routes
// through the port's strict decoder state machine (Security.IsValidUtf8) —
// never through System.Text / Encoding.UTF8.
//
// Rationale: the ingestion layer is security-critical. A plain byte array
// field on a codec output type carries no claim about its UTF-8 validity —
// downstream consumers have to either re-validate or trust the producer.
// ValidatedUtf8 makes the claim module-level, so a downstream consumer that
// wants the raw bytes has to explicitly Unwrap — which reads as "I am consuming
// the RFC 3629 claim here". A transcription of ports/rust/src/validated_utf8.rs.

namespace UnicodeSecurity;

/// <summary>
/// A byte array that has been validated as strict RFC 3629 UTF-8. The
/// constructor is intentionally private; <see cref="Validate"/> is the only
/// blessed way to build a <see cref="ValidatedUtf8"/>.
/// </summary>
public sealed class ValidatedUtf8
{
    private readonly byte[] _bytes;

    private ValidatedUtf8(byte[] bytes) => _bytes = bytes;

    /// <summary>
    /// Validate a byte sequence and, on success, return a
    /// <see cref="ValidatedUtf8"/> carrying the RFC 3629 validity claim.
    /// Returns <c>null</c> when the bytes fail the strict state machine.
    /// </summary>
    public static ValidatedUtf8? Validate(IReadOnlyList<byte> bytes) =>
        Security.IsValidUtf8(bytes) ? new ValidatedUtf8(bytes.ToArray()) : null;

    /// <summary>Borrow the validated bytes.</summary>
    public IReadOnlyList<byte> AsBytes => _bytes;

    /// <summary>
    /// Consume the validity claim, returning the underlying bytes. After this
    /// call the validity claim is no longer carried at the module-boundary
    /// level — the caller owns the "these bytes are RFC 3629 valid" reasoning
    /// from here forward.
    /// </summary>
    public byte[] Unwrap() => (byte[])_bytes.Clone();
}
