package security

// Surrogate-reassembly / malformed-byte-stream detection.
//
// Threat model. Tier C. An adversary hides intent in a byte stream that
// is not well-formed UTF-8 — an overlong encoding, a CESU-8 / surrogate
// codepoint, a truncated sequence, an invalid start or continuation byte,
// or a value beyond U+10FFFF — betting a lenient decoder will "reassemble"
// it into something the security scanner never saw in codepoint form.
//
// Direct port of Unicode/Security/Covert/SurrogateReassembly.lean. The
// input codepoint list is treated as a byte stream (one octet per entry);
// the family only applies when every entry is a byte (< 0x100), matching
// the looksLikeByteStream gate in Unicode/Security/RunAll.lean. The verdict
// projects the first UTF-8 violation found by the shared strict decoder
// (firstInvalidUTF8Offset, the same walk ScanUTF8 uses) onto a
// covert-layer sub-threat, distinct from the malformed-utf8 tags.

// looksLikeByteStream reports whether every entry fits in one octet — the
// looksLikeByteStream gate. A codepoint list containing any value >= 0x100
// is not a byte stream, and running the UTF-8 decoder on it would be
// meaningless.
func looksLikeByteStream(input []uint32) bool {
	for _, cp := range input {
		if cp >= 0x100 {
			return false
		}
	}
	return true
}

// subThreatOfRejectKind projects a utf8RejectKind onto its
// surrogate-reassembly sub-threat tag, mirroring subThreatOfRejectKind in
// the Lean spec. These tags deliberately differ from the malformed-utf8
// family's tags so the two verdicts stay distinguishable.
func subThreatOfRejectKind(kind utf8RejectKind) string {
	switch kind {
	case utf8RejectOverlongEncoding:
		return "Overlong"
	case utf8RejectSurrogateCodepoint:
		return "Cesu8"
	case utf8RejectTruncatedSequence:
		return "Truncated"
	case utf8RejectInvalidStartByte:
		return "InvalidStartByte"
	case utf8RejectInvalidContinuationByte:
		return "InvalidContinuation"
	case utf8RejectCodepointBeyondMax:
		return "CodepointBeyondMax"
	default:
		return ""
	}
}

// surrogateReassemblyDetect treats input as a byte stream (one octet per
// entry) and reports the sub-threat of the first UTF-8 violation together
// with its byte offset. Only byte-stream-shaped input (every entry
// < 0x100) is examined; anything else, and any well-formed stream, is
// clear (ok == false).
func surrogateReassemblyDetect(input []uint32) (string, []int, bool) {
	if !looksLikeByteStream(input) {
		return "", nil, false
	}
	bytes := make([]byte, len(input))
	for i, cp := range input {
		bytes[i] = byte(cp)
	}
	offset, kind, invalid := firstInvalidUTF8Offset(bytes)
	if !invalid {
		return "", nil, false
	}
	return subThreatOfRejectKind(kind), []int{offset}, true
}

func surrogateReassemblyFinding(input []uint32) (Finding, bool) {
	subThreat, positions, ok := surrogateReassemblyDetect(input)
	if !ok {
		return Finding{}, false
	}
	return Finding{
		Code:      reasonCode(FamilySurrogateReassembly, subThreat),
		Family:    FamilySurrogateReassembly,
		Severity:  2,
		Positions: positions,
		SubThreat: subThreat,
		Detail:    string(FamilySurrogateReassembly),
	}, true
}
