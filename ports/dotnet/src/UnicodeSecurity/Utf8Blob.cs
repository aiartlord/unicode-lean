// Opaque text predicate — structurally valid UTF-8, size-bounded.
//
// No character-class or code-point filtering beyond UTF-8 validity. Intended
// for callers who apply their own text hardening downstream; hardened
// identifier and printable profiles layer on top of this predicate. A
// transcription of ports/rust/src/opaque_blob.rs, with validity routed through
// the port's strict decoder (Security.IsValidUtf8), never System.Text.

namespace UnicodeSecurity;

/// <summary>
/// A byte sequence carrying its size bound and UTF-8 validity claim. The
/// constructor is hidden; <see cref="Of"/> is the only entry point.
/// </summary>
public sealed class Utf8Blob
{
    private readonly byte[] _bytes;

    private Utf8Blob(byte[] bytes, int maxBytes)
    {
        _bytes = bytes;
        MaxBytes = maxBytes;
    }

    /// <summary>
    /// Opaque-blob predicate: structurally valid strict UTF-8. Exposed under
    /// this name so the "blob" framing — no character-class hardening — is
    /// explicit at the call site.
    /// </summary>
    public static bool IsUtf8Blob(IReadOnlyList<byte> bytes) => Security.IsValidUtf8(bytes);

    /// <summary>
    /// Build a <see cref="Utf8Blob"/> under the size bound
    /// <paramref name="maxBytes"/>. Returns <c>null</c> when either the bound
    /// or UTF-8 validity is violated.
    /// </summary>
    public static Utf8Blob? Of(IReadOnlyList<byte> bytes, int maxBytes)
    {
        if (bytes.Count > maxBytes)
        {
            return null;
        }
        if (!IsUtf8Blob(bytes))
        {
            return null;
        }
        return new Utf8Blob(bytes.ToArray(), maxBytes);
    }

    /// <summary>The underlying bytes.</summary>
    public IReadOnlyList<byte> Bytes => _bytes;

    /// <summary>The declared size bound.</summary>
    public int MaxBytes { get; }
}
