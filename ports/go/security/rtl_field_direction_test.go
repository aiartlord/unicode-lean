package security

import "testing"

// Ground truth: the detectWithContext_rtl_* theorems in
// Unicode/Security/Display/RtlInjection.lean, each proven by decide.
func TestRtlFieldDirection(t *testing.T) {
	cases := []struct {
		name string
		dir  FieldDirection
		in   []uint32
		want string
	}{
		{"hebrew RTL clear", FieldRTL, []uint32{0x05D0, 0x42, 0x43}, ""},
		{"persian RTL clear", FieldRTL, []uint32{0x06CC, 0x200C, 0x0647}, ""},
		{"bidi ctl RTL fires", FieldRTL, []uint32{0x41, 0x202E, 0x42}, "BidiControlInLTRField"},
		{"hebrew LTR fires", FieldLTR, []uint32{0x05D0, 0x42, 0x43}, "FieldTakeover"},
	}
	for _, c := range cases {
		sub, _, ok := rtlInjectionDetectWithContext(c.dir, c.in)
		if !ok {
			sub = ""
		}
		if sub != c.want {
			t.Errorf("%s: got %q want %q", c.name, sub, c.want)
		}
	}
}
