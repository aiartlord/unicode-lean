package security

// Opaque text predicate and byte-layer refinement types layered over
// the port's strict RFC 3629 UTF-8 validator (firstInvalidUTF8Offset in
// utf8_policy.go). No character-class or codepoint filtering beyond
// UTF-8 validity is applied here; hardened identifier and printable
// profiles layer on top of these predicates.

// IsUTF8Blob is the opaque-blob predicate: it reports whether data is
// structurally valid UTF-8 under the port's strict decoder. Exposed
// under this name so the "blob" framing — no character-class hardening —
// is explicit at the call site.
func IsUTF8Blob(data []byte) bool {
	_, _, invalid := firstInvalidUTF8Offset(data)
	return !invalid
}

// Utf8Blob is a byte sequence carrying its size bound and UTF-8 validity
// claim. The zero value carries no claim; OfUtf8Blob is the only blessed
// entry point.
type Utf8Blob struct {
	bytes    []byte
	maxBytes int
}

// OfUtf8Blob builds a Utf8Blob under the size bound maxBytes. The second
// result is false when either the bound or UTF-8 validity is violated.
func OfUtf8Blob(data []byte, maxBytes int) (Utf8Blob, bool) {
	if len(data) > maxBytes {
		return Utf8Blob{}, false
	}
	if !IsUTF8Blob(data) {
		return Utf8Blob{}, false
	}
	return Utf8Blob{bytes: data, maxBytes: maxBytes}, true
}

// Bytes returns the underlying bytes.
func (b Utf8Blob) Bytes() []byte {
	return b.bytes
}

// MaxBytes returns the declared size bound.
func (b Utf8Blob) MaxBytes() int {
	return b.maxBytes
}

// ValidatedUtf8 is a byte slice that has been validated as strict RFC
// 3629 UTF-8. The validity claim is pinned at the module boundary: the
// only way to construct a ValidatedUtf8 is via Validate, which routes
// through the strict decoder state machine. The zero value carries no
// claim.
type ValidatedUtf8 struct {
	bytes []byte
}

// Validate checks data against the strict state machine and, on success,
// returns a ValidatedUtf8 carrying the RFC 3629 validity claim. The
// second result is false when the bytes fail validation.
func Validate(data []byte) (ValidatedUtf8, bool) {
	if IsUTF8Blob(data) {
		return ValidatedUtf8{bytes: data}, true
	}
	return ValidatedUtf8{}, false
}

// AsBytes borrows the validated bytes.
func (v ValidatedUtf8) AsBytes() []byte {
	return v.bytes
}

// Unwrap consumes the validity claim, returning the underlying bytes.
// After this call the "these bytes are RFC 3629 valid" reasoning is
// owned by the caller, not carried at the module boundary.
func (v ValidatedUtf8) Unwrap() []byte {
	return v.bytes
}
