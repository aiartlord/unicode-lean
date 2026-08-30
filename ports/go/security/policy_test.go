package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

type policyContract struct {
	Schema   int            `json:"schema"`
	Contract string         `json:"contract"`
	Cases    []contractCase `json:"cases"`
}

type contractCase struct {
	Name             string   `json:"name"`
	Profile          string   `json:"profile"`
	Mode             string   `json:"mode"`
	Input            []uint32 `json:"input"`
	Action           string   `json:"action"`
	RequiredFindings []string `json:"required_findings"`
}

type decodeContract struct {
	Schema   int          `json:"schema"`
	Contract string       `json:"contract"`
	Cases    []decodeCase `json:"cases"`
}

type decodeCase struct {
	Name              string             `json:"name"`
	Encoding          string             `json:"encoding"`
	Profile           string             `json:"profile"`
	Mode              string             `json:"mode"`
	InputBytes        []int              `json:"input_bytes"`
	Input             []uint32           `json:"input"`
	Action            string             `json:"action"`
	RequiredFindings  []string           `json:"required_findings"`
	RequiredPositions []requiredPosition `json:"required_positions"`
}

type requiredPosition struct {
	Code      string `json:"code"`
	Positions []int  `json:"positions"`
}

type verdictContract struct {
	Schema   int           `json:"schema"`
	Contract string        `json:"contract"`
	Cases    []verdictCase `json:"cases"`
}

type verdictCase struct {
	Name    string      `json:"name"`
	Profile string      `json:"profile"`
	Mode    string      `json:"mode"`
	Input   []uint32    `json:"input"`
	Verdict VerdictWire `json:"verdict"`
}

type detectorFixture struct {
	Schema int            `json:"schema"`
	Family string         `json:"family"`
	Cases  []detectorCase `json:"cases"`
}

type detectorCase struct {
	Name             string   `json:"name"`
	Input            []uint32 `json:"input"`
	RequiredFindings []string `json:"required_findings"`
}

func TestPolicyContractFixture(t *testing.T) {
	contract := loadPolicyContract(t)
	if contract.Schema != 1 {
		t.Fatalf("unexpected contract schema: %d", contract.Schema)
	}
	if contract.Contract != "unicode-security-policy-v0" {
		t.Fatalf("unexpected contract name: %s", contract.Contract)
	}

	for _, tc := range contract.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			verdict := Scan(Profile(tc.Profile), Mode(tc.Mode), tc.Input)
			if verdict.Action != Action(tc.Action) {
				t.Fatalf("action = %s, want %s", verdict.Action, tc.Action)
			}
			for _, required := range tc.RequiredFindings {
				if !hasFinding(verdict.Findings, required) {
					t.Fatalf("missing finding %q in %#v", required, verdict.Findings)
				}
			}
		})
	}
}

func TestVerdictContractFixture(t *testing.T) {
	var contract verdictContract
	loadJSON(t, fixturePath(t, "fixtures", "security", "verdict_contract.json"), &contract)
	if contract.Schema != 1 {
		t.Fatalf("unexpected verdict schema: %d", contract.Schema)
	}
	if contract.Contract != "unicode-security-verdict-v0" {
		t.Fatalf("unexpected verdict contract name: %s", contract.Contract)
	}

	for _, tc := range contract.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			verdict := Scan(Profile(tc.Profile), Mode(tc.Mode), tc.Input)
			actual := VerdictToWire(verdict)
			if !reflect.DeepEqual(actual, tc.Verdict) {
				t.Fatalf("verdict mismatch\nactual: %#v\nexpect: %#v", actual, tc.Verdict)
			}
			expectedJSON, err := json.Marshal(tc.Verdict)
			if err != nil {
				t.Fatal(err)
			}
			if VerdictJSON(verdict) != string(expectedJSON) {
				t.Fatalf("verdict JSON mismatch\nactual: %s\nexpect: %s", VerdictJSON(verdict), string(expectedJSON))
			}
		})
	}
}

func TestDecodeContractFixture(t *testing.T) {
	var contract decodeContract
	loadJSON(t, fixturePath(t, "fixtures", "security", "decode_contract.json"), &contract)
	if contract.Schema != 1 {
		t.Fatalf("unexpected decode schema: %d", contract.Schema)
	}
	if contract.Contract != "unicode-security-decode-v0" {
		t.Fatalf("unexpected decode contract name: %s", contract.Contract)
	}

	for _, tc := range contract.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			verdict := ScanUTF8(Profile(tc.Profile), Mode(tc.Mode), bytesFromInts(tc.InputBytes))
			if verdict.Action != Action(tc.Action) {
				t.Fatalf("action = %s, want %s", verdict.Action, tc.Action)
			}
			if !reflect.DeepEqual(verdict.Input, tc.Input) {
				t.Fatalf("input = %#v, want %#v", verdict.Input, tc.Input)
			}
			for _, required := range tc.RequiredFindings {
				if !hasFinding(verdict.Findings, required) {
					t.Fatalf("missing finding %q in %#v", required, verdict.Findings)
				}
			}
			for _, expected := range tc.RequiredPositions {
				actual, ok := positionsFor(verdict.Findings, expected.Code)
				if !ok {
					t.Fatalf("missing positions for %q", expected.Code)
				}
				if !reflect.DeepEqual(actual, expected.Positions) {
					t.Fatalf("positions for %q = %#v, want %#v", expected.Code, actual, expected.Positions)
				}
			}
		})
	}
}

func TestMultiEncodingDecodeContractFixture(t *testing.T) {
	var contract decodeContract
	loadJSON(t, fixturePath(t, "fixtures", "security", "decode_multiencoding_contract.json"), &contract)
	if contract.Schema != 1 {
		t.Fatalf("unexpected multi-encoding decode schema: %d", contract.Schema)
	}
	if contract.Contract != "unicode-security-multiencoding-decode-v0" {
		t.Fatalf("unexpected multi-encoding decode contract name: %s", contract.Contract)
	}

	for _, tc := range contract.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			verdict := scanEncodedCase(tc)
			if verdict.Action != Action(tc.Action) {
				t.Fatalf("action = %s, want %s", verdict.Action, tc.Action)
			}
			if !reflect.DeepEqual(verdict.Input, tc.Input) {
				t.Fatalf("input = %#v, want %#v", verdict.Input, tc.Input)
			}
			for _, required := range tc.RequiredFindings {
				if !hasFinding(verdict.Findings, required) {
					t.Fatalf("missing finding %q in %#v", required, verdict.Findings)
				}
			}
			for _, expected := range tc.RequiredPositions {
				actual, ok := positionsFor(verdict.Findings, expected.Code)
				if !ok {
					t.Fatalf("missing positions for %q", expected.Code)
				}
				if !reflect.DeepEqual(actual, expected.Positions) {
					t.Fatalf("positions for %q = %#v, want %#v", expected.Code, actual, expected.Positions)
				}
			}
		})
	}
}

func TestDetectorFixtures(t *testing.T) {
	for _, name := range []string{
		"tag_block_payload.json",
		"variation_selector_payload.json",
		"zero_width_payload.json",
		"bidi_control_balance.json",
		"noncharacter_control.json",
		"homoglyph_confusable.json",
		"mixed_script_admissibility.json",
	} {
		t.Run(name, func(t *testing.T) {
			var fixture detectorFixture
			loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", name), &fixture)
			if fixture.Schema != 1 {
				t.Fatalf("unexpected detector schema: %d", fixture.Schema)
			}
			for _, tc := range fixture.Cases {
				verdict := Scan(ProfileGatewayHeader, ModeObserve, tc.Input)
				for _, required := range tc.RequiredFindings {
					if !hasFinding(verdict.Findings, required) {
						t.Fatalf("%s: missing finding %q in %#v", tc.Name, required, verdict.Findings)
					}
				}
				if len(tc.RequiredFindings) == 0 && hasFamilyFinding(verdict.Findings, Family(fixture.Family)) {
					t.Fatalf("%s: unexpected %q finding in %#v", tc.Name, fixture.Family, verdict.Findings)
				}
			}
		})
	}
}

func bytesFromInts(input []int) []byte {
	out := make([]byte, len(input))
	for index, value := range input {
		out[index] = byte(value)
	}
	return out
}

func scanEncodedCase(tc decodeCase) Verdict {
	profile := Profile(tc.Profile)
	mode := Mode(tc.Mode)
	input := bytesFromInts(tc.InputBytes)
	switch tc.Encoding {
	case "utf-8":
		return ScanUTF8(profile, mode, input)
	case "utf-16be":
		return ScanUTF16BE(profile, mode, input)
	case "utf-16le":
		return ScanUTF16LE(profile, mode, input)
	case "utf-32be":
		return ScanUTF32BE(profile, mode, input)
	case "utf-32le":
		return ScanUTF32LE(profile, mode, input)
	default:
		return Verdict{Action: ActionReject}
	}
}

func positionsFor(findings []Finding, code string) ([]int, bool) {
	for _, finding := range findings {
		if finding.Code == code {
			return finding.Positions, true
		}
	}
	return nil, false
}

func loadPolicyContract(t *testing.T) policyContract {
	t.Helper()
	var contract policyContract
	loadJSON(t, fixturePath(t, "fixtures", "security", "policy_contract.json"), &contract)
	return contract
}

func fixturePath(t *testing.T, parts ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	all := append([]string{filepath.Dir(file), "testdata"}, parts...)
	return filepath.Join(all...)
}

func loadJSON(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}

func hasFinding(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

// TestRtlInjection pins the detector against the detect_* spot-check
// theorems in Unicode/Security/Display/RtlInjection.lean, each proven
// there by decide.
func TestRtlInjection(t *testing.T) {
	cases := []struct {
		name  string
		input []uint32
		want  string // "" means clear
	}{
		{"clear-digits", []uint32{0x30, 0x31, 0x32, 0x33}, ""},
		{"clear-cyrillic", []uint32{0x043F}, ""},
		{"rlo-in-ltr", []uint32{0x41, 0x202E, 0x42}, "BidiControlInLTRField"},
		{"field-takeover-hebrew", []uint32{0x05D0, 0x42, 0x43}, "FieldTakeover"},
		{"field-takeover-arabic", []uint32{0x0627, 0x42, 0x43}, "FieldTakeover"},
		{"mid-stream-hebrew", []uint32{0x41, 0x42, 0x05D0, 0x44}, "StrongRTLInLTR"},
		{"overflow-hebrew", []uint32{0x41, 0x42, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x44}, "MixedOverflow"},
	}
	for _, tc := range cases {
		verdict := Scan(ProfileGatewayHeader, ModeObserve, tc.input)
		got := ""
		for _, finding := range verdict.Findings {
			if finding.Family == FamilyRtlInjection {
				got = finding.SubThreat
			}
		}
		if got != tc.want {
			t.Fatalf("%s: rtl-injection sub-threat got %q want %q", tc.name, got, tc.want)
		}
	}
}

func hasFamilyFinding(findings []Finding, family Family) bool {
	for _, finding := range findings {
		if finding.Family == family {
			return true
		}
	}
	return false
}
