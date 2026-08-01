package security

import (
	"slices"
	"testing"
)

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/NfcIdempotenceWitness.lean.
func TestNfcIdempotenceWitnessDetect(t *testing.T) {
	sub := func(in []uint32) string {
		s, _, _ := nfcIdempotenceWitnessDetect(in)
		return s
	}

	if got := sub(nil); got != "" {
		t.Errorf("nil: got %q, want clear", got)
	}
	if got := sub([]uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F}); got != "" {
		t.Errorf("ASCII Hello: got %q, want clear", got)
	}
	if got := sub([]uint32{0x00E9}); got != "" {
		t.Errorf("precomposed e-acute: got %q, want clear", got)
	}
	if got := sub([]uint32{0x0065, 0x0301}); got != "NonNfcForm" {
		t.Errorf("decomposed e-acute: got %q, want NonNfcForm", got)
	}
	if _, pos, _ := nfcIdempotenceWitnessDetect([]uint32{0x0065, 0x0301}); !slices.Equal(pos, []int{0}) {
		t.Errorf("decomposed e-acute position: got %v, want [0]", pos)
	}
	if got := sub([]uint32{0xFB01}); got != "NonNfkcCompatForm" {
		t.Errorf("fi ligature FB01: got %q, want NonNfkcCompatForm", got)
	}
}
