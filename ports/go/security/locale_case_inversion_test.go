package security

import (
	"slices"
	"testing"
)

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/LocaleCaseInversion.lean.
func TestLocaleCaseInversionDetect(t *testing.T) {
	sub := func(in []uint32) string {
		s, _, _ := localeCaseInversionDetect(in)
		return s
	}

	if got := sub(nil); got != "" {
		t.Errorf("empty: got %q, want clear", got)
	}
	if got := sub([]uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F}); got != "" {
		t.Errorf("ASCII Hello: got %q, want clear", got)
	}
	if got := sub([]uint32{0x0049}); got != "TurkishCaseDivergence" {
		t.Errorf("capital I: got %q, want TurkishCaseDivergence", got)
	}
	if _, pos, _ := localeCaseInversionDetect([]uint32{0x0049}); !slices.Equal(pos, []int{0}) {
		t.Errorf("capital I position: got %v, want [0]", pos)
	}
	if got := sub([]uint32{0x0130}); got != "TurkishCaseDivergence" {
		t.Errorf("dotted I: got %q, want TurkishCaseDivergence", got)
	}
	if got := sub([]uint32{0x0049, 0x0300}); got != "TurkishCaseDivergence" {
		t.Errorf("I+grave priority: got %q, want TurkishCaseDivergence", got)
	}
	if got := sub([]uint32{0x004A, 0x0300}); got != "LithuanianCaseDivergence" {
		t.Errorf("J+grave: got %q, want LithuanianCaseDivergence", got)
	}
}
