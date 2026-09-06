package security

import (
	"strconv"
	"strings"
)

type FindingWire struct {
	Code      string `json:"code"`
	Family    string `json:"family"`
	Severity  int    `json:"severity"`
	Positions []int  `json:"positions"`
	SubThreat string `json:"sub_threat"`
	Detail    string `json:"detail"`
}

type VerdictWire struct {
	Action     string        `json:"action"`
	Profile    string        `json:"profile"`
	Mode       string        `json:"mode"`
	Input      []uint32      `json:"input"`
	Findings   []FindingWire `json:"findings"`
	Normalized []uint32      `json:"normalized"`
}

func FindingToWire(finding Finding) FindingWire {
	return FindingWire{
		Code:      finding.Code,
		Family:    string(finding.Family),
		Severity:  finding.Severity,
		Positions: copyInts(finding.Positions),
		SubThreat: finding.SubThreat,
		Detail:    finding.Detail,
	}
}

func VerdictToWire(verdict Verdict) VerdictWire {
	findings := make([]FindingWire, 0, len(verdict.Findings))
	for _, finding := range verdict.Findings {
		findings = append(findings, FindingToWire(finding))
	}
	return VerdictWire{
		Action:     string(verdict.Action),
		Profile:    string(verdict.Profile),
		Mode:       string(verdict.Mode),
		Input:      copyU32s(verdict.Input),
		Findings:   findings,
		Normalized: verdict.Normalized,
	}
}

// VerdictJSON writes the compact wire shape the shared verdict contract pins:
// action, profile, mode, input, findings, normalized, with finding fields
// ordered code, family, severity, positions, sub_threat, detail. It is written
// by hand, as the reference's verdict_to_json is, so there is no error path to
// fall through: a verdict always serialises, never to an empty string.
func VerdictJSON(verdict Verdict) string {
	var out strings.Builder
	out.WriteString("{\"action\":")
	writeJSONString(&out, string(verdict.Action))
	out.WriteString(",\"profile\":")
	writeJSONString(&out, string(verdict.Profile))
	out.WriteString(",\"mode\":")
	writeJSONString(&out, string(verdict.Mode))
	out.WriteString(",\"input\":")
	writeU32Array(&out, verdict.Input)
	out.WriteString(",\"findings\":[")
	for index, finding := range verdict.Findings {
		if index > 0 {
			out.WriteByte(',')
		}
		writeFindingJSON(&out, finding)
	}
	out.WriteString("],\"normalized\":")
	if verdict.Normalized == nil {
		out.WriteString("null")
	} else {
		writeU32Array(&out, verdict.Normalized)
	}
	out.WriteByte('}')
	return out.String()
}

func writeFindingJSON(out *strings.Builder, finding Finding) {
	out.WriteString("{\"code\":")
	writeJSONString(out, finding.Code)
	out.WriteString(",\"family\":")
	writeJSONString(out, string(finding.Family))
	out.WriteString(",\"severity\":")
	out.WriteString(strconv.Itoa(finding.Severity))
	out.WriteString(",\"positions\":")
	writeIntArray(out, finding.Positions)
	out.WriteString(",\"sub_threat\":")
	writeJSONString(out, finding.SubThreat)
	out.WriteString(",\"detail\":")
	writeJSONString(out, finding.Detail)
	out.WriteByte('}')
}

// writeJSONString escapes exactly what RFC 8259 requires: the quote, the
// backslash, and the C0 controls (as \n, \r, \t, \b, \f or \u00XX). Every
// other byte passes through, which matches the reference's writer.
func writeJSONString(out *strings.Builder, value string) {
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString("\\\"")
		case '\\':
			out.WriteString("\\\\")
		case '\n':
			out.WriteString("\\n")
		case '\r':
			out.WriteString("\\r")
		case '\t':
			out.WriteString("\\t")
		case '\b':
			out.WriteString("\\b")
		case '\f':
			out.WriteString("\\f")
		default:
			if r < 0x20 {
				out.WriteString("\\u00")
				out.WriteByte("0123456789abcdef"[r>>4])
				out.WriteByte("0123456789abcdef"[r&0xF])
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

func writeU32Array(out *strings.Builder, values []uint32) {
	out.WriteByte('[')
	for index, value := range values {
		if index > 0 {
			out.WriteByte(',')
		}
		out.WriteString(strconv.FormatUint(uint64(value), 10))
	}
	out.WriteByte(']')
}

func writeIntArray(out *strings.Builder, values []int) {
	out.WriteByte('[')
	for index, value := range values {
		if index > 0 {
			out.WriteByte(',')
		}
		out.WriteString(strconv.Itoa(value))
	}
	out.WriteByte(']')
}

func copyInts(values []int) []int {
	// Guard on length, not on nil: append to a nil slice with nothing to add
	// returns nil, so an empty-but-allocated slice would marshal as null. A
	// finding that localises nothing -- source-display-divergence judges the
	// input as a unit -- carries exactly that slice, and the wire contract
	// pins an empty array for it.
	if len(values) == 0 {
		return []int{}
	}
	return append([]int(nil), values...)
}

func copyU32s(values []uint32) []uint32 {
	if values == nil {
		return []uint32{}
	}
	return append([]uint32(nil), values...)
}
