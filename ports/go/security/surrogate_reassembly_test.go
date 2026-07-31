package security

import "testing"

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Covert/SurrogateReassembly.lean, mirrored from the
// verified Rust port's test vectors. An empty sub means clear
// (looksLikeByteStream gate off, or well-formed UTF-8); a non-empty sub is
// the first-violation tag.
func TestSurrogateReassemblyVectors(t *testing.T) {
	sub := func(input []uint32) string {
		subThreat, _, _ := surrogateReassemblyDetect(input)
		return subThreat
	}

	cases := []struct {
		name  string
		input []uint32
		want  string
	}{
		{"empty", []uint32{}, ""},
		{"ascii-hello", []uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F}, ""},
		{"e-acute", []uint32{0xC3, 0xA9}, ""},
		{"han-zhong", []uint32{0xE4, 0xB8, 0xAD}, ""},
		{"emoji-grin", []uint32{0xF0, 0x9F, 0x98, 0x80}, ""},

		{"c0-80", []uint32{0xC0, 0x80}, "InvalidStartByte"},
		{"c0-af", []uint32{0xC0, 0xAF}, "InvalidStartByte"},
		{"fe", []uint32{0xFE}, "InvalidStartByte"},
		{"lone-continuation-80", []uint32{0x80}, "InvalidStartByte"},
		{"ff", []uint32{0xFF}, "InvalidStartByte"},

		{"overlong-slash-3byte", []uint32{0xE0, 0x80, 0xAF}, "Overlong"},
		{"overlong-slash-4byte", []uint32{0xF0, 0x80, 0x80, 0xAF}, "Overlong"},

		{"cesu8-surrogate-low", []uint32{0xED, 0xA0, 0x80}, "Cesu8"},
		{"cesu8-surrogate-high", []uint32{0xED, 0xAF, 0xBF}, "Cesu8"},

		{"truncated-2byte", []uint32{0xC3}, "Truncated"},
		{"truncated-4byte", []uint32{0xF0, 0x9F, 0x98}, "Truncated"},

		// The unit detect clamps values > 0xFF to 0xFF (mirroring the Lean
		// toBytes helper), which the strict decoder rejects as an invalid
		// start byte. The scan orchestrator gates these out (see below).
		{"non-byte-stream-emoji-codepoint", []uint32{0x1F600}, "InvalidStartByte"},
		{"non-byte-stream-mixed", []uint32{0x41, 0x100}, "InvalidStartByte"},
	}

	for _, tc := range cases {
		got := sub(tc.input)
		if got != tc.want {
			t.Errorf("%s: sub(%v) = %q, want %q", tc.name, tc.input, got, tc.want)
		}
	}
}

// TestSurrogateReassemblyByteStreamGate pins that the scan-orchestrator
// wrapper skips the family on non-byte-stream input (mirroring runAll),
// even though the unit detect clamps such input to a malformed byte.
func TestSurrogateReassemblyByteStreamGate(t *testing.T) {
	for _, input := range [][]uint32{{0x1F600}, {0x41, 0x100}} {
		if _, ok := surrogateReassemblyFinding(input); ok {
			t.Errorf("surrogateReassemblyFinding(%v) fired; want gated (no finding)", input)
		}
	}
	// A genuine byte-stream violation still produces a finding.
	if _, ok := surrogateReassemblyFinding([]uint32{0xC0, 0x80}); !ok {
		t.Errorf("surrogateReassemblyFinding([0xC0 0x80]) did not fire; want InvalidStartByte")
	}
}
