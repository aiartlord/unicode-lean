package security

import "testing"

func TestNFKCKnownVectors(t *testing.T) {
	cases := []struct {
		name string
		in   []uint32
		want []uint32
	}{
		// ﬁ ligature (U+FB01) → "fi": compatibility decomposition, no recompose.
		{"fi ligature", []uint32{0xFB01}, []uint32{0x66, 0x69}},
		// ① circled digit one (U+2460) → "1".
		{"circled one", []uint32{0x2460}, []uint32{0x31}},
		// Fullwidth A (U+FF21) → "A".
		{"fullwidth A", []uint32{0xFF21}, []uint32{0x41}},
		// Precomposed é (U+00E9) stays é under NFKC.
		{"precomposed e-acute", []uint32{0x00E9}, []uint32{0x00E9}},
		// Decomposed e + combining acute → é under NFKC.
		{"decomposed e-acute", []uint32{0x0065, 0x0301}, []uint32{0x00E9}},
		// Hangul jamo L+V+T → precomposed syllable 한 (U+D55C).
		{"hangul jamo", []uint32{0x1112, 0x1161, 0x11AB}, []uint32{0xD55C}},
	}
	for _, tc := range cases {
		got := toNFKC(tc.in)
		if !equalUint32Slices(got, tc.want) {
			t.Errorf("toNFKC(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNFCKnownVectors(t *testing.T) {
	cases := []struct {
		name string
		in   []uint32
		want []uint32
	}{
		// Decomposed e + combining acute recomposes to é under NFC.
		{"decomposed e-acute", []uint32{0x0065, 0x0301}, []uint32{0x00E9}},
		// Precomposed é stays é under NFC.
		{"precomposed e-acute", []uint32{0x00E9}, []uint32{0x00E9}},
		// The ﬁ ligature is a compatibility (not canonical) mapping, so NFC
		// leaves it unchanged — unlike NFKC.
		{"fi ligature unchanged", []uint32{0xFB01}, []uint32{0xFB01}},
		// Hangul jamo L+V+T recompose to 한 (U+D55C) under NFC.
		{"hangul jamo", []uint32{0x1112, 0x1161, 0x11AB}, []uint32{0xD55C}},
		// UAX #15 D115 blocking (matches Lean stepCompose): a combining
		// grave (CCC 230) between Hangul L and V blocks the L+V syllable
		// composition, so nothing recomposes across it.
		{"hangul L+mark+V blocked", []uint32{0x1100, 0x0300, 0x1161}, []uint32{0x1100, 0x0300, 0x1161}},
		// The same jamo without the intervening mark compose to U+AC00.
		{"hangul L+V", []uint32{0x1100, 0x1161}, []uint32{0xAC00}},
		// A + below(CCC 220) + grave(CCC 230): the higher-CCC grave is not
		// blocked and composes to À; the lower-CCC mark stays buffered.
		{"a below grave", []uint32{0x0041, 0x0316, 0x0300}, []uint32{0x00C0, 0x0316}},
	}
	for _, tc := range cases {
		got := toNFC(tc.in)
		if !equalUint32Slices(got, tc.want) {
			t.Errorf("toNFC(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNFKDKnownVectors(t *testing.T) {
	cases := []struct {
		name string
		in   []uint32
		want []uint32
	}{
		// Fullwidth A → "A" (compatibility decomposition, no recomposition).
		{"fullwidth A", []uint32{0xFF21}, []uint32{0x41}},
		// ﬁ → "fi".
		{"fi ligature", []uint32{0xFB01}, []uint32{0x66, 0x69}},
		// Precomposed é → e + combining acute under NFKD.
		{"e-acute", []uint32{0x00E9}, []uint32{0x0065, 0x0301}},
	}
	for _, tc := range cases {
		got := toNFKD(tc.in)
		if !equalUint32Slices(got, tc.want) {
			t.Errorf("toNFKD(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
