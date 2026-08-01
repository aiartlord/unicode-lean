package security

import (
	"slices"
	"testing"
)

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/NormalizationBomb.lean, plus the two ratio-branch shapes
// the module docstring guarantees (FDFB -> NFKD 8x ratio; a Greek extended form
// -> NFD 4x ratio).
func TestNormalizationBombDetect(t *testing.T) {
	sub := func(in []uint32) string {
		s, _, _ := normalizationBombDetect(in)
		return s
	}

	if got := sub(nil); got != "" {
		t.Errorf("nil: got %q, want clear", got)
	}
	if got := sub([]uint32{}); got != "" {
		t.Errorf("empty: got %q, want clear", got)
	}
	if got := sub([]uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F}); got != "" {
		t.Errorf("ASCII Hello: got %q, want clear", got)
	}
	if got := sub([]uint32{0xD55C}); got != "" {
		t.Errorf("Korean han: got %q, want clear (NFD ratio exactly 300, not > 300)", got)
	}
	if got := sub([]uint32{0x2460}); got != "" {
		t.Errorf("circled one: got %q, want clear (NFKD 1x)", got)
	}
	if got := sub([]uint32{0xFDFA}); got != "SingleCpBlowup" {
		t.Errorf("Arabic ligature FDFA: got %q, want SingleCpBlowup", got)
	}
	if _, pos, _ := normalizationBombDetect([]uint32{0xFDFA}); !slices.Equal(pos, []int{0}) {
		t.Errorf("Arabic ligature FDFA position: got %v, want [0]", pos)
	}
	if got := sub([]uint32{0xFDFB}); got != "NfkdHighExpansion" {
		t.Errorf("FDFB: got %q, want NfkdHighExpansion", got)
	}
	if got := sub([]uint32{0x1F82}); got != "NfdHighExpansion" {
		t.Errorf("Greek extended 1F82: got %q, want NfdHighExpansion", got)
	}
}
