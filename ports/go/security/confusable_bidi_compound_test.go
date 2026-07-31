package security

import "testing"

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Boundary/ConfusableBidiCompound.lean, mirrored from the
// verified Rust port ports/rust/src/security/boundary/confusable_bidi_compound.rs.

func confusableBidiCompoundSub(input []uint32) string {
	sub, _, ok := confusableBidiCompoundDetect(input)
	if !ok {
		return ""
	}
	return sub
}

func TestConfusableBidiCompoundVectors(t *testing.T) {
	cases := []struct {
		name  string
		input []uint32
		want  string
	}{
		{"empty", []uint32{}, ""},
		{"ascii-hello", []uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F}, ""},
		{"override-without-confusable", []uint32{0x202E, 0x0041, 0x0042, 0x0043}, ""},
		{"confusable-without-bidi", []uint32{0x0430}, ""},
		{"rlo-cyrillic-a", []uint32{0x202E, 0x0430}, "ConfusableInOverride"},
		{"lri-greek-omicron", []uint32{0x2066, 0x03BF}, "ConfusableInIsolate"},
	}
	for _, tc := range cases {
		if got := confusableBidiCompoundSub(tc.input); got != tc.want {
			t.Errorf("%s: sub = %q, want %q", tc.name, got, tc.want)
		}
	}
}
