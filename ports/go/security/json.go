package security

import "encoding/json"

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

func VerdictJSON(verdict Verdict) string {
	data, err := json.Marshal(VerdictToWire(verdict))
	if err != nil {
		return ""
	}
	return string(data)
}

func copyInts(values []int) []int {
	if values == nil {
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
