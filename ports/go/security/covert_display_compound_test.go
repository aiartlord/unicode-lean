package security

import "testing"

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Boundary/CovertDisplayCompound.lean, mirrored from the
// verified Rust port ports/rust/src/security/boundary/covert_display_compound.rs.

func covertDisplayCompoundSub(input []uint32) string {
	sub, _, ok := covertDisplayCompoundDetect(input)
	if !ok {
		return ""
	}
	return sub
}

func TestCovertDisplayCompoundVectors(t *testing.T) {
	cases := []struct {
		name  string
		input []uint32
		want  string
	}{
		{"empty", []uint32{}, ""},
		{"ascii-hello", []uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F}, ""},
		{"rlo-alone", []uint32{0x202E}, ""},
		{"vs-alone-no-bidi", []uint32{0x0041, 0xFE00}, ""},
		{"rlo-ascii-vs", []uint32{0x202E, 0x0041, 0xFE00}, "BidiPlusUnregisteredVs"},
		{"rlo-ascii-tag", []uint32{0x202E, 0x0041, 0xE0001}, "BidiPlusTagBlock"},
	}
	for _, tc := range cases {
		if got := covertDisplayCompoundSub(tc.input); got != tc.want {
			t.Errorf("%s: sub = %q, want %q", tc.name, got, tc.want)
		}
	}
}
