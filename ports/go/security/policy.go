package security

type Action string

const (
	ActionAllow      Action = "allow"
	ActionReject     Action = "reject"
	ActionQuarantine Action = "quarantine"
	ActionRewrite    Action = "rewrite"
	ActionObserve    Action = "observe"
)

type Mode string

const (
	ModeObserve Mode = "observe"
	ModeWarn    Mode = "warn"
	ModeEnforce Mode = "enforce"
	ModeStrict  Mode = "strict"
)

type Profile string

const (
	ProfileGatewayHeader Profile = "gateway-header"
	ProfileDomainName    Profile = "domain-name"
	ProfileDnsLabel      Profile = "dns-label"
	ProfileURL           Profile = "url"
	ProfileUsername      Profile = "username"
	ProfileDisplayName   Profile = "display-name"
	ProfileChatMessage   Profile = "chat-message"
	ProfileSourceCode    Profile = "source-code"
	ProfileOpaqueSecret  Profile = "opaque-secret"
	ProfileBinaryBlob    Profile = "binary-blob"
)

type PolicyLevel string

const (
	PolicyRestrictive PolicyLevel = "restrictive"
	PolicyModerate    PolicyLevel = "moderate"
	PolicyMinimal     PolicyLevel = "minimal"
)

type Family string

const (
	FamilyMalformedUTF8       Family = "malformed-utf8"
	FamilyMalformedUTF16      Family = "malformed-utf16"
	FamilyMalformedUTF32      Family = "malformed-utf32"
	FamilyTagBlockPayload     Family = "tag-block-payload"
	FamilyVariationSelector   Family = "variation-selector-payload"
	FamilyZeroWidthPayload    Family = "zero-width-payload"
	FamilyBidiControlBalance  Family = "bidi-control-balance"
	FamilyNoncharacterControl Family = "noncharacter-control"
	FamilyHomoglyphConfusable Family = "homoglyph-confusable"
	FamilyMixedScript         Family = "mixed-script-admissibility"
)

type ProfilePolicy struct {
	Level      PolicyLevel
	Quarantine bool
}

type Finding struct {
	Code      string
	Family    Family
	Severity  int
	Positions []int
	SubThreat string
	Detail    string
}

type Verdict struct {
	Input      []uint32
	Profile    Profile
	Mode       Mode
	Action     Action
	Findings   []Finding
	Normalized []uint32
}

func PolicyOfProfile(profile Profile) ProfilePolicy {
	switch profile {
	case ProfileGatewayHeader, ProfileDomainName, ProfileDnsLabel, ProfileSourceCode:
		return ProfilePolicy{Level: PolicyRestrictive}
	case ProfileURL:
		return ProfilePolicy{Level: PolicyModerate}
	case ProfileUsername:
		return ProfilePolicy{Level: PolicyModerate, Quarantine: true}
	case ProfileDisplayName, ProfileChatMessage:
		return ProfilePolicy{Level: PolicyMinimal, Quarantine: true}
	case ProfileOpaqueSecret, ProfileBinaryBlob:
		return ProfilePolicy{Level: PolicyMinimal}
	default:
		return ProfilePolicy{Level: PolicyRestrictive}
	}
}

func Scan(profile Profile, mode Mode, input []uint32) Verdict {
	findings := detect(input)
	action := decide(profile, mode, findings)

	return Verdict{
		Input:    append([]uint32(nil), input...),
		Profile:  profile,
		Mode:     mode,
		Action:   action,
		Findings: findings,
	}
}

func detect(input []uint32) []Finding {
	findings := make([]Finding, 0, 7)

	if positions := positionsWhere(input, isTagBlockAsciiPayload); len(positions) > 0 {
		findings = append(findings, Finding{
			Code:      reasonCode(FamilyTagBlockPayload, "DirectAscii"),
			Family:    FamilyTagBlockPayload,
			Severity:  2,
			Positions: positions,
			SubThreat: "DirectAscii",
			Detail:    "tag-block-payload",
		})
	}

	if finding, ok := variationSelectorFinding(input); ok {
		findings = append(findings, finding)
	}

	if positions := positionsWhere(input, isZeroWidthPayload); len(positions) > 0 {
		findings = append(findings, Finding{
			Code:      reasonCode(FamilyZeroWidthPayload, "BareZeroWidth"),
			Family:    FamilyZeroWidthPayload,
			Severity:  2,
			Positions: positions,
			SubThreat: "BareZeroWidth",
			Detail:    "zero-width-payload",
		})
	}

	if positions := positionsWhere(input, isBidiEmbeddingControl); len(positions) > 0 {
		findings = append(findings, Finding{
			Code:      reasonCode(FamilyBidiControlBalance, "UnbalancedEmbedding"),
			Family:    FamilyBidiControlBalance,
			Severity:  2,
			Positions: positions,
			SubThreat: "UnbalancedEmbedding",
			Detail:    "bidi-control-balance",
		})
	}

	findings = append(findings, noncharacterControlFindings(input)...)
	if finding, ok := homoglyphConfusableFinding(input); ok {
		findings = append(findings, finding)
	}
	if finding, ok := mixedScriptAdmissibilityFinding(input); ok {
		findings = append(findings, finding)
	}

	return findings
}

func decide(profile Profile, mode Mode, findings []Finding) Action {
	if len(findings) == 0 {
		return ActionAllow
	}
	if mode == ModeObserve || mode == ModeWarn {
		return ActionObserve
	}
	if mode == ModeStrict {
		return ActionReject
	}

	policy := PolicyOfProfile(profile)
	for _, finding := range findings {
		if blocks(policy.Level, finding.Family) {
			if policy.Quarantine {
				return ActionQuarantine
			}
			return ActionReject
		}
	}
	return ActionAllow
}

func blocks(level PolicyLevel, family Family) bool {
	switch level {
	case PolicyRestrictive:
		return family == FamilyMalformedUTF8 ||
			family == FamilyMalformedUTF16 ||
			family == FamilyMalformedUTF32 ||
			family == FamilyTagBlockPayload ||
			family == FamilyVariationSelector ||
			family == FamilyZeroWidthPayload ||
			family == FamilyBidiControlBalance ||
			family == FamilyNoncharacterControl ||
			family == FamilyHomoglyphConfusable ||
			family == FamilyMixedScript
	case PolicyModerate:
		return family == FamilyMalformedUTF8 ||
			family == FamilyMalformedUTF16 ||
			family == FamilyMalformedUTF32 ||
			family == FamilyTagBlockPayload ||
			family == FamilyVariationSelector ||
			family == FamilyZeroWidthPayload ||
			family == FamilyBidiControlBalance ||
			family == FamilyNoncharacterControl ||
			family == FamilyHomoglyphConfusable ||
			family == FamilyMixedScript
	case PolicyMinimal:
		return family == FamilyMalformedUTF8 ||
			family == FamilyMalformedUTF16 ||
			family == FamilyMalformedUTF32 ||
			family == FamilyBidiControlBalance ||
			family == FamilyNoncharacterControl
	default:
		return family == FamilyMalformedUTF8 ||
			family == FamilyMalformedUTF16 ||
			family == FamilyMalformedUTF32 ||
			family == FamilyTagBlockPayload ||
			family == FamilyVariationSelector ||
			family == FamilyZeroWidthPayload ||
			family == FamilyBidiControlBalance ||
			family == FamilyNoncharacterControl ||
			family == FamilyHomoglyphConfusable ||
			family == FamilyMixedScript
	}
}

func positionsWhere(input []uint32, pred func(uint32) bool) []int {
	var positions []int
	for i, cp := range input {
		if pred(cp) {
			positions = append(positions, i)
		}
	}
	return positions
}

func isTagBlockAsciiPayload(cp uint32) bool {
	return cp >= 0xE0020 && cp <= 0xE007E
}

func variationSelectorFinding(input []uint32) (Finding, bool) {
	positions := positionsWhere(input, isVariationSelector)
	if len(positions) == 0 {
		return Finding{}, false
	}

	subThreat := "IllegalTarget"
	if len(positions) >= 4 && allSameAt(input, positions) {
		subThreat = "RepeatedBase"
	} else if len(decodeVariationSelectorRun(input, positions)) > 0 {
		subThreat = "DirectPayload"
	}

	return Finding{
		Code:      reasonCode(FamilyVariationSelector, subThreat),
		Family:    FamilyVariationSelector,
		Severity:  2,
		Positions: positions,
		SubThreat: subThreat,
		Detail:    string(FamilyVariationSelector),
	}, true
}

func isVariationSelector(cp uint32) bool {
	return (cp >= 0xFE00 && cp <= 0xFE0F) ||
		(cp >= 0xE0100 && cp <= 0xE01EF) ||
		(cp >= 0x180B && cp <= 0x180D)
}

func variationSelectorNibble(cp uint32) (uint32, bool) {
	if cp >= 0xFE00 && cp <= 0xFE0F {
		return cp - 0xFE00, true
	}
	if cp >= 0xE0100 && cp <= 0xE01EF {
		return cp - 0xE0100 + 16, true
	}
	return 0, false
}

func decodeVariationSelectorRun(input []uint32, positions []int) []byte {
	out := make([]byte, 0, len(positions)/2)
	var high uint32
	haveHigh := false
	for _, position := range positions {
		nibble, ok := variationSelectorNibble(input[position])
		if !ok {
			continue
		}
		if !haveHigh {
			high = nibble
			haveHigh = true
			continue
		}
		out = append(out, byte((high<<4)|nibble))
		haveHigh = false
	}
	return out
}

func allSameAt(input []uint32, positions []int) bool {
	if len(positions) == 0 {
		return true
	}
	first := input[positions[0]]
	for _, position := range positions {
		if input[position] != first {
			return false
		}
	}
	return true
}

func isZeroWidthPayload(cp uint32) bool {
	switch cp {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF:
		return true
	default:
		return false
	}
}

func isBidiEmbeddingControl(cp uint32) bool {
	return cp >= 0x202A && cp <= 0x202E
}

func noncharacterControlFindings(input []uint32) []Finding {
	findings := make([]Finding, 0, 3)
	appendFinding := func(subThreat string, positions []int) {
		if len(positions) == 0 {
			return
		}
		findings = append(findings, Finding{
			Code:      reasonCode(FamilyNoncharacterControl, subThreat),
			Family:    FamilyNoncharacterControl,
			Severity:  2,
			Positions: positions,
			SubThreat: subThreat,
			Detail:    string(FamilyNoncharacterControl),
		})
	}

	appendFinding("Noncharacter", positionsWhere(input, isNoncharacter))
	appendFinding("C0Control", positionsWhere(input, isC0Control))
	appendFinding("C1Control", positionsWhere(input, isC1Control))
	return findings
}

func homoglyphConfusableFinding(input []uint32) (Finding, bool) {
	subThreat := ""
	if _, ok := homoglyphTargetMatch(input); ok {
		subThreat = "TargetMatch"
	} else {
		for _, cp := range input {
			if isMathAlphanumeric(cp) {
				subThreat = "MathAlpha"
				break
			}
		}
		if subThreat == "" {
			for _, cp := range input {
				if isFullwidthHalfwidth(cp) {
					subThreat = "WidthClass"
					break
				}
			}
		}
	}
	if subThreat == "" && hasDecompositionSwap(input) {
		subThreat = "DecompositionSwap"
	}
	if subThreat == "" {
		return Finding{}, false
	}
	return Finding{
		Code:      reasonCode(FamilyHomoglyphConfusable, subThreat),
		Family:    FamilyHomoglyphConfusable,
		Severity:  2,
		Positions: fullSpanPositions(input),
		SubThreat: subThreat,
		Detail:    string(FamilyHomoglyphConfusable),
	}, true
}

func mixedScriptAdmissibilityFinding(input []uint32) (Finding, bool) {
	if !hasCrossScriptMix(input) {
		return Finding{}, false
	}
	return Finding{
		Code:      reasonCode(FamilyMixedScript, "CrossScriptMix"),
		Family:    FamilyMixedScript,
		Severity:  2,
		Positions: fullSpanPositions(input),
		SubThreat: "CrossScriptMix",
		Detail:    string(FamilyMixedScript),
	}, true
}

func fullSpanPositions(input []uint32) []int {
	positions := make([]int, len(input))
	for i := range input {
		positions[i] = i
	}
	return positions
}

func isMathAlphanumeric(cp uint32) bool {
	return cp >= 0x1D400 && cp <= 0x1D7FF
}

func isFullwidthHalfwidth(cp uint32) bool {
	return cp >= 0xFF01 && cp <= 0xFFEF
}

func isNoncharacter(cp uint32) bool {
	if cp >= 0xFDD0 && cp <= 0xFDEF {
		return true
	}
	if cp > 0x10FFFF {
		return false
	}
	low16 := cp & 0xFFFF
	return low16 == 0xFFFE || low16 == 0xFFFF
}

func isC0Control(cp uint32) bool {
	return (cp <= 0x1F && cp != 0x09 && cp != 0x0A && cp != 0x0D) || cp == 0x7F
}

func isC1Control(cp uint32) bool {
	return cp >= 0x80 && cp <= 0x9F
}

func reasonCode(family Family, subThreat string) string {
	return "unicode.security." + layer(family) + "." + string(family) + "." + subThreat
}

func layer(family Family) string {
	switch family {
	case FamilyMalformedUTF8, FamilyMalformedUTF16, FamilyMalformedUTF32, FamilyTagBlockPayload, FamilyVariationSelector, FamilyZeroWidthPayload, FamilyBidiControlBalance, FamilyNoncharacterControl:
		return "C"
	case FamilyHomoglyphConfusable, FamilyMixedScript:
		return "I"
	default:
		return "C"
	}
}
