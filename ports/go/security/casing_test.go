package security

import (
	"slices"
	"testing"
)

// Ground truth: the toLower spot-check theorems in Unicode.Casing.
func TestCasingToLowerSpotChecks(t *testing.T) {
	cases := []struct {
		name   string
		locale casingLocale
		in     []uint32
		want   []uint32
	}{
		{"hello", localeDefault, []uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F}, []uint32{0x68, 0x65, 0x6C, 0x6C, 0x6F}},
		{"I-default", localeDefault, []uint32{0x0049}, []uint32{0x0069}},
		{"I-turkish", localeTurkish, []uint32{0x0049}, []uint32{0x0131}},
		{"I-azeri", localeAzeri, []uint32{0x0049}, []uint32{0x0131}},
		{"dotted-I-turkish", localeTurkish, []uint32{0x0130}, []uint32{0x0069}},
		{"dotted-I-default", localeDefault, []uint32{0x0130}, []uint32{0x0069, 0x0307}},
	}
	for _, tc := range cases {
		got := toLower(tc.locale, tc.in)
		if !slices.Equal(got, tc.want) {
			t.Errorf("toLower(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
