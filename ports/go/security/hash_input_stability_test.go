package security

import (
	"slices"
	"testing"
)

// Ground truth: the stable_*, detect_*, and priority theorems in
// Unicode.Security.Crypto.HashInputStability, mirrored from the verified Rust
// port security/crypto/hash_input_stability.rs.

func hisStrPtr(s string) *string          { return &s }
func hisRulePtr(r hisRfcRule) *hisRfcRule { return &r }
func hisCpsPtr(cps []uint32) *[]uint32    { return &cps }

func hisTagOf(input []uint32) (string, bool) {
	return hisDetect(input).classify.tag()
}

func hisCtxTagOf(ctx hisContext, input []uint32) (string, bool) {
	return hisDetectWithContext(ctx, input).classify.tag()
}

// TestHashInputStabilityFixture runs the shared context-free detector fixture
// through hisDetect, mapping the classification tag onto its reason code the
// way TestDetectorFixtures checks required_findings.
func TestHashInputStabilityFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "hash_input_stability.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilyHashInputStability) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		verdict := hisDetect(tc.Input)
		findings := []string{}
		if tag, ok := verdict.classify.tag(); ok {
			findings = append(findings, reasonCode(FamilyHashInputStability, tag))
		}
		for _, required := range tc.RequiredFindings {
			if !slices.Contains(findings, required) {
				t.Fatalf("%s: missing finding %q in %#v", tc.Name, required, findings)
			}
		}
		if len(tc.RequiredFindings) == 0 && len(findings) != 0 {
			t.Fatalf("%s: unexpected finding in %#v", tc.Name, findings)
		}
	}
}

// TestHashInputStabilityContextVectors transcribes every Context-probe vector
// from the Rust reference's comment block: rfc_rule / declared_encoding /
// as_written / server_bytes → expected tag & positions.
func TestHashInputStabilityContextVectors(t *testing.T) {
	cases := []struct {
		name     string
		ctx      hisContext
		input    []uint32
		wantTag  string // "" means clear
		wantPos  []int
		checkPos bool
	}{
		// declared_encoding = Some("utf-16"), [a,b,c] → EncodingMismatch, [0]
		{"enc-utf16-label", hisContext{declaredEncoding: hisStrPtr("utf-16")}, []uint32{0x61, 0x62, 0x63}, "EncodingMismatch", []int{0}, true},
		// declared_encoding = Some("utf-8"), [a,U+D800,b] → EncodingMismatch, [1] (invalid surrogate)
		{"enc-invalid-surrogate", hisContext{declaredEncoding: hisStrPtr("utf-8")}, []uint32{0x61, 0xD800, 0x62}, "EncodingMismatch", []int{1}, true},
		// declared_encoding = Some("utf-8"), [a,0x110000,b] → EncodingMismatch, [1] (out of range)
		{"enc-invalid-out-of-range", hisContext{declaredEncoding: hisStrPtr("utf-8")}, []uint32{0x61, 0x110000, 0x62}, "EncodingMismatch", []int{1}, true},
		// declared_encoding = Some("UTF-8"|"utf-8"|"UTF8"), [a,b,c] → clear
		{"enc-utf8-UTF-8", hisContext{declaredEncoding: hisStrPtr("UTF-8")}, []uint32{0x61, 0x62, 0x63}, "", nil, false},
		{"enc-utf8-utf-8", hisContext{declaredEncoding: hisStrPtr("utf-8")}, []uint32{0x61, 0x62, 0x63}, "", nil, false},
		{"enc-utf8-UTF8", hisContext{declaredEncoding: hisStrPtr("UTF8")}, []uint32{0x61, 0x62, 0x63}, "", nil, false},
		// rfc_rule = Pgp4880TrailingWhitespace, [a,SP] → SignedMessageRule, [1]
		{"rfc-pgp4880", hisContext{rfcRule: hisRulePtr(hisPgp4880TrailingWhitespace)}, []uint32{0x61, 0x20}, "SignedMessageRule", []int{1}, true},
		// rfc_rule = Pgp9580LineEnding, [a,LF,b] → SignedMessageRule, [1] (bare LF)
		{"rfc-pgp9580-bare-lf", hisContext{rfcRule: hisRulePtr(hisPgp9580LineEnding)}, []uint32{0x61, 0x0A, 0x62}, "SignedMessageRule", []int{1}, true},
		// rfc_rule = Pgp9580LineEnding, [a,b,c,CR,LF,d,e,f] → clear (CRLF)
		{"rfc-pgp9580-crlf-clear", hisContext{rfcRule: hisRulePtr(hisPgp9580LineEnding)}, []uint32{0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66}, "", nil, false},
		// rfc_rule = Rfc8785NfcRequirement, [U+0065,U+0301] → SignedMessageRule, [0]
		{"rfc-8785-decomposed", hisContext{rfcRule: hisRulePtr(hisRfc8785NfcRequirement)}, []uint32{0x0065, 0x0301}, "SignedMessageRule", []int{0}, true},
		// rfc_rule = Rfc8259ControlChar, [a,U+0001,b] → SignedMessageRule, [1]
		{"rfc-8259-control", hisContext{rfcRule: hisRulePtr(hisRfc8259ControlChar)}, []uint32{0x61, 0x01, 0x62}, "SignedMessageRule", []int{1}, true},
		// rfc_rule = Rfc7515JwsBase64Url, [A,+,B] → SignedMessageRule, [1] ('+')
		{"rfc-7515-plus", hisContext{rfcRule: hisRulePtr(hisRfc7515JwsBase64Url)}, []uint32{0x41, 0x2B, 0x42}, "SignedMessageRule", []int{1}, true},
		// rfc_rule = Rfc7515JwsBase64Url, [A,a,0,-,_,z,Z,9] → clear
		{"rfc-7515-clean-clear", hisContext{rfcRule: hisRulePtr(hisRfc7515JwsBase64Url)}, []uint32{0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39}, "", nil, false},
		// rfc_rule = Rfc6376DkimRelaxed, [a,SP,SP,b] → SignedMessageRule, [2]
		{"rfc-6376-double-space", hisContext{rfcRule: hisRulePtr(hisRfc6376DkimRelaxed)}, []uint32{0x61, 0x20, 0x20, 0x62}, "SignedMessageRule", []int{2}, true},
		// rfc_rule = Rfc6376DkimRelaxed, [a,SP,b] → clear (single space)
		{"rfc-6376-single-space-clear", hisContext{rfcRule: hisRulePtr(hisRfc6376DkimRelaxed)}, []uint32{0x61, 0x20, 0x62}, "", nil, false},
		// rfc_rule = Rfc5751SmimeLineEnding, [a,LF,b] → SignedMessageRule, [1] (bare LF)
		{"rfc-5751-bare-lf", hisContext{rfcRule: hisRulePtr(hisRfc5751SmimeLineEnding)}, []uint32{0x61, 0x0A, 0x62}, "SignedMessageRule", []int{1}, true},
		// as_written = Some([a,b,c]), input [a,b,d] → AuditLogReinterpretation, [2]
		{"audit-divergence", hisContext{asWritten: hisCpsPtr([]uint32{0x61, 0x62, 0x63})}, []uint32{0x61, 0x62, 0x64}, "AuditLogReinterpretation", []int{2}, true},
		// as_written = Some([a,b,c]), input [a,b,c] → clear
		{"audit-identical-clear", hisContext{asWritten: hisCpsPtr([]uint32{0x61, 0x62, 0x63})}, []uint32{0x61, 0x62, 0x63}, "", nil, false},
		// server_bytes = Some([a,b,d]), input [a,b,c] → WebhookSignatureDrift, [2]
		{"webhook-drift", hisContext{serverBytes: hisCpsPtr([]uint32{0x61, 0x62, 0x64})}, []uint32{0x61, 0x62, 0x63}, "WebhookSignatureDrift", []int{2}, true},
		// server_bytes = Some([a,b,c]), input [a,b,c] → clear
		{"webhook-match-clear", hisContext{serverBytes: hisCpsPtr([]uint32{0x61, 0x62, 0x63})}, []uint32{0x61, 0x62, 0x63}, "", nil, false},
		// declared_encoding = Some("utf-16") + rfc_rule = Pgp9580LineEnding,
		//   [U+0065,U+0301,LF] → EncodingMismatch (priority over rfc)
		{"priority-encoding-over-rfc", hisContext{declaredEncoding: hisStrPtr("utf-16"), rfcRule: hisRulePtr(hisPgp9580LineEnding)}, []uint32{0x0065, 0x0301, 0x0A}, "EncodingMismatch", nil, false},
		// server_bytes = Some([a,b,e]) + as_written = Some([a,b,f]),
		//   input [a,b,c] → WebhookSignatureDrift (priority over audit)
		{"priority-webhook-over-audit", hisContext{serverBytes: hisCpsPtr([]uint32{0x61, 0x62, 0x65}), asWritten: hisCpsPtr([]uint32{0x61, 0x62, 0x66})}, []uint32{0x61, 0x62, 0x63}, "WebhookSignatureDrift", nil, false},
		// rfc_rule = Pgp4880TrailingWhitespace, [a,SP] → SignedMessageRule (priority over trailing)
		{"priority-rfc-over-trailing", hisContext{rfcRule: hisRulePtr(hisPgp4880TrailingWhitespace)}, []uint32{0x61, 0x20}, "SignedMessageRule", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict := hisDetectWithContext(tc.ctx, tc.input)
			tag, ok := verdict.classify.tag()
			if tc.wantTag == "" {
				if ok {
					t.Fatalf("expected clear, got tag %q", tag)
				}
				return
			}
			if !ok {
				t.Fatalf("expected tag %q, got clear", tc.wantTag)
			}
			if tag != tc.wantTag {
				t.Fatalf("tag = %q, want %q", tag, tc.wantTag)
			}
			if tc.checkPos && !slices.Equal(verdict.classify.positions, tc.wantPos) {
				t.Fatalf("positions = %#v, want %#v", verdict.classify.positions, tc.wantPos)
			}
		})
	}
}

// TestHashInputStabilityHashStable mirrors the §4 hash_stable spot checks.
func TestHashInputStabilityHashStable(t *testing.T) {
	cases := []struct {
		name string
		in   []uint32
		want []uint32
	}{
		{"empty", []uint32{}, []uint32{}},
		{"ascii-idempotent", []uint32{0x61, 0x62, 0x63}, []uint32{0x61, 0x62, 0x63}},
		{"strip-trailing-space", []uint32{0x61, 0x20}, []uint32{0x61}},
		{"strip-trailing-tab", []uint32{0x61, 0x09}, []uint32{0x61}},
		{"strip-trailing-lf", []uint32{0x61, 0x0A}, []uint32{0x61}},
		{"strip-trailing-crlf", []uint32{0x61, 0x0D, 0x0A}, []uint32{0x61}},
		{"preserve-internal-space", []uint32{0x61, 0x20, 0x62}, []uint32{0x61, 0x20, 0x62}},
		{"compose-nfc", []uint32{0x0065, 0x0301}, []uint32{0x00E9}},
		{"preserve-trailing-nbsp", []uint32{0x61, 0x00A0}, []uint32{0x61, 0x00A0}},
	}
	for _, tc := range cases {
		if got := hisHashStable(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("%s: hisHashStable = %#v, want %#v", tc.name, got, tc.want)
		}
	}
	// Idempotence: hash_stable(hash_stable(x)) == hash_stable(x).
	once := hisHashStable([]uint32{0x61, 0x62, 0x63})
	if got := hisHashStable(once); !slices.Equal(got, once) {
		t.Errorf("idempotence: %#v vs %#v", got, once)
	}
}

// TestHashInputStabilityBareDetect mirrors the §8 detect spot checks.
func TestHashInputStabilityBareDetect(t *testing.T) {
	// Empty and ASCII are clear.
	if _, ok := hisTagOf([]uint32{}); ok {
		t.Errorf("empty should be clear")
	}
	if _, ok := hisTagOf([]uint32{0x61, 0x62, 0x63}); ok {
		t.Errorf("ascii should be clear")
	}
	// Trailing space: TrailingWhitespace, stableSize 1, position [1].
	v := hisDetect([]uint32{0x61, 0x20})
	if tag, ok := v.classify.tag(); !ok || tag != "TrailingWhitespace" {
		t.Errorf("trailing space tag = %q, %v", tag, ok)
	}
	if v.stableSize != 1 {
		t.Errorf("trailing space stableSize = %d, want 1", v.stableSize)
	}
	if !slices.Equal(v.classify.positions, []int{1}) {
		t.Errorf("trailing space positions = %#v", v.classify.positions)
	}
	// Trailing CRLF: TrailingWhitespace, stableSize 1.
	v = hisDetect([]uint32{0x61, 0x0D, 0x0A})
	if tag, ok := v.classify.tag(); !ok || tag != "TrailingWhitespace" || v.stableSize != 1 {
		t.Errorf("trailing crlf tag = %q, %v, stableSize %d", tag, ok, v.stableSize)
	}
	// Decomposed é: NormalizationDrift at [0].
	v = hisDetect([]uint32{0x0065, 0x0301})
	if tag, ok := v.classify.tag(); !ok || tag != "NormalizationDrift" {
		t.Errorf("decomposed tag = %q, %v", tag, ok)
	}
	if !slices.Equal(v.classify.positions, []int{0}) {
		t.Errorf("decomposed positions = %#v", v.classify.positions)
	}
	// Precomposed é is clear.
	if _, ok := hisTagOf([]uint32{0x00E9}); ok {
		t.Errorf("precomposed é should be clear")
	}
	// Priority: "é " decomposed + trailing space → TrailingWhitespace wins.
	if tag, ok := hisTagOf([]uint32{0x0065, 0x0301, 0x20}); !ok || tag != "TrailingWhitespace" {
		t.Errorf("priority trailing-over-nfc tag = %q, %v", tag, ok)
	}
	// Internal space is clear.
	if _, ok := hisTagOf([]uint32{0x61, 0x20, 0x62}); ok {
		t.Errorf("internal space should be clear")
	}
	// Default context equals bare detect.
	d := hisDetect([]uint32{0x61, 0x62, 0x63})
	c := hisDetectWithContext(hisContext{}, []uint32{0x61, 0x62, 0x63})
	dTag, dOK := d.classify.tag()
	cTag, cOK := c.classify.tag()
	if dTag != cTag || dOK != cOK || d.stableSize != c.stableSize {
		t.Errorf("default context should match bare detect")
	}
	// UTF-8 label with utf8 (no hyphen) is also recognised.
	if _, ok := hisCtxTagOf(hisContext{declaredEncoding: hisStrPtr("utf8")}, []uint32{0x61, 0x62, 0x63}); ok {
		t.Errorf("utf8 label should be recognised as UTF-8")
	}
}

// TestHashInputStabilityRfcRuleRoundtrip mirrors the RfcRule fixture-tag
// round-trip.
func TestHashInputStabilityRfcRuleRoundtrip(t *testing.T) {
	rules := []hisRfcRule{
		hisPgp4880TrailingWhitespace,
		hisPgp9580LineEnding,
		hisRfc8785NfcRequirement,
		hisRfc8259ControlChar,
		hisRfc7515JwsBase64Url,
		hisRfc6376DkimRelaxed,
		hisRfc5751SmimeLineEnding,
	}
	for _, rule := range rules {
		got, ok := hisRfcRuleFromTag(rule.tag())
		if !ok || got != rule {
			t.Errorf("roundtrip failed for %q: got %v, %v", rule.tag(), got, ok)
		}
	}
	if _, ok := hisRfcRuleFromTag("nope"); ok {
		t.Errorf("from_tag(nope) should be false")
	}
}
