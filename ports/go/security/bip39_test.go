package security

import (
	"slices"
	"testing"
)

// Ground truth: the detect + canonicalisation spot-check theorems in
// Unicode.Security.Crypto.Bip39Canonical(VectorsDetect).
func TestBip39Detect(t *testing.T) {
	abandon := []uint32{0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E}
	about := []uint32{0x61, 0x62, 0x6F, 0x75, 0x74}
	tag := func(in []uint32) string { return bip39CanonicalDetect(in).sub }

	if got := bip39CanonicalForm([]uint32{0x61, 0x20, 0x20, 0x62}); !slices.Equal(got, []uint32{0x61, 0x20, 0x62}) {
		t.Errorf("double space canonical: %v", got)
	}
	if got := bip39CanonicalForm([]uint32{0x41}); !slices.Equal(got, []uint32{0x61}) {
		t.Errorf("lowercase canonical: %v", got)
	}
	if got := bip39CanonicalForm([]uint32{0x61, 0x3000, 0x62}); !slices.Equal(got, []uint32{0x61, 0x20, 0x62}) {
		t.Errorf("ideographic-space canonical: %v", got)
	}

	cases := []struct {
		name string
		in   []uint32
		want string
	}{
		{"trailing", append(slices.Clone(abandon), 0x20), "TrailingWhitespace"},
		{"mixed", []uint32{0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E}, "MixedCase"},
		{"double", append(append(slices.Clone(abandon), 0x20, 0x20), about...), "WhitespaceAnomaly"},
		{"leading", append([]uint32{0x20}, abandon...), "WhitespaceAnomaly"},
		{"nfkd-ligature", []uint32{0xFB00}, "NonNFKD"},
		{"nfkd-nbsp", []uint32{0x61, 0x00A0, 0x62}, "NonNFKD"},
		{"mismatch", []uint32{0x71, 0x7A, 0x71, 0x7A}, "WordlistMismatch"},
	}
	for _, tc := range cases {
		if got := tag(tc.in); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}

	if got := bip39CanonicalDetect(append(slices.Clone(abandon), 0x20)).positions; !slices.Equal(got, []int{7}) {
		t.Errorf("trailing position: %v", got)
	}
	if got := bip39CanonicalDetect([]uint32{0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E}).positions; !slices.Equal(got, []int{0}) {
		t.Errorf("mixed-case position: %v", got)
	}

	empty := bip39CanonicalDetect([]uint32{})
	if empty.sub != "" || empty.language != "english" {
		t.Errorf("empty: %+v", empty)
	}

	var mnemonic []uint32
	for i := 0; i < 11; i++ {
		mnemonic = append(mnemonic, abandon...)
		mnemonic = append(mnemonic, 0x20)
	}
	mnemonic = append(mnemonic, about...)
	v := bip39CanonicalDetect(mnemonic)
	if v.sub != "" || v.language != "english" || v.wordCount != 12 {
		t.Errorf("12-word english: %+v", v)
	}
}
