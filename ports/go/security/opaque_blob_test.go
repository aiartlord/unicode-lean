package security

import (
	"bytes"
	"testing"
)

// Ground truth: the byte-layer refinement types mirror the verified Rust
// port's opaque_blob.rs and validated_utf8.rs, both layered over the
// strict RFC 3629 validator (firstInvalidUTF8Offset). Valid multi-byte
// forms are accepted; overlong and surrogate forms are rejected by the
// same strict decoder that ScanUTF8 uses.

func TestIsUTF8BlobPredicate(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", []byte{}, true},
		{"ascii", []byte("Hello"), true},
		{"two-byte-e-acute", []byte{0xC3, 0xA9}, true},
		{"three-byte-han", []byte{0xE4, 0xB8, 0xAD}, true},
		{"four-byte-emoji", []byte{0xF0, 0x9F, 0x98, 0x80}, true},

		{"overlong-c0-80", []byte{0xC0, 0x80}, false},
		{"surrogate-ed-a0-80", []byte{0xED, 0xA0, 0x80}, false},
		{"lone-continuation", []byte{0x80}, false},
		{"truncated-two-byte", []byte{0xC3}, false},
	}
	for _, c := range cases {
		if got := IsUTF8Blob(c.data); got != c.want {
			t.Errorf("IsUTF8Blob(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOfUtf8BlobBound(t *testing.T) {
	valid := []byte{0xF0, 0x9F, 0x98, 0x80} // 4 bytes, valid emoji

	if _, ok := OfUtf8Blob(valid, 4); !ok {
		t.Errorf("OfUtf8Blob at exact bound should be accepted")
	}
	if _, ok := OfUtf8Blob(valid, 10); !ok {
		t.Errorf("OfUtf8Blob under bound should be accepted")
	}
	if _, ok := OfUtf8Blob(valid, 3); ok {
		t.Errorf("OfUtf8Blob over bound should be rejected")
	}

	// Empty is accepted under any bound, including zero.
	for _, bound := range []int{0, 1, 100} {
		if _, ok := OfUtf8Blob([]byte{}, bound); !ok {
			t.Errorf("empty blob should be accepted under bound %d", bound)
		}
	}

	// Invalid bytes are rejected even when within the bound.
	if _, ok := OfUtf8Blob([]byte{0xC0, 0x80}, 100); ok {
		t.Errorf("overlong C0 80 should be rejected regardless of bound")
	}
	if _, ok := OfUtf8Blob([]byte{0xED, 0xA0, 0x80}, 100); ok {
		t.Errorf("surrogate ED A0 80 should be rejected regardless of bound")
	}
}

func TestOfUtf8BlobAccessors(t *testing.T) {
	data := []byte{0xE4, 0xB8, 0xAD} // valid 3-byte han
	blob, ok := OfUtf8Blob(data, 8)
	if !ok {
		t.Fatalf("valid blob should construct")
	}
	if !bytes.Equal(blob.Bytes(), data) {
		t.Errorf("Bytes() = %v, want %v", blob.Bytes(), data)
	}
	if blob.MaxBytes() != 8 {
		t.Errorf("MaxBytes() = %d, want 8", blob.MaxBytes())
	}
}

func TestValidateRoundtrip(t *testing.T) {
	cases := [][]byte{
		{},
		[]byte("ascii text"),
		{0xC3, 0xA9},
		{0xE4, 0xB8, 0xAD},
		{0xF0, 0x9F, 0x98, 0x80},
	}
	for _, data := range cases {
		v, ok := Validate(data)
		if !ok {
			t.Errorf("Validate(% x) should succeed", data)
			continue
		}
		if !bytes.Equal(v.AsBytes(), data) {
			t.Errorf("AsBytes() = % x, want % x", v.AsBytes(), data)
		}
		if !bytes.Equal(v.Unwrap(), data) {
			t.Errorf("Unwrap() = % x, want % x", v.Unwrap(), data)
		}
	}
}

func TestValidateRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"overlong-c0-80", []byte{0xC0, 0x80}},
		{"surrogate-ed-a0-80", []byte{0xED, 0xA0, 0x80}},
		{"overlong-3byte-slash", []byte{0xE0, 0x80, 0xAF}},
		{"lone-continuation", []byte{0x80}},
		{"truncated-4byte", []byte{0xF0, 0x9F, 0x98}},
		{"bare-ff", []byte{0xFF}},
	}
	for _, c := range cases {
		if _, ok := Validate(c.data); ok {
			t.Errorf("Validate(%s) should reject malformed bytes", c.name)
		}
	}
}
