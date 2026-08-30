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
	FamilyMalformedUTF8            Family = "malformed-utf8"
	FamilyMalformedUTF16           Family = "malformed-utf16"
	FamilyMalformedUTF32           Family = "malformed-utf32"
	FamilyTagBlockPayload          Family = "tag-block-payload"
	FamilyVariationSelector        Family = "variation-selector-payload"
	FamilyZeroWidthPayload         Family = "zero-width-payload"
	FamilySurrogateReassembly      Family = "surrogate-reassembly"
	FamilyBidiControlBalance       Family = "bidi-control-balance"
	FamilyNoncharacterControl      Family = "noncharacter-control"
	FamilyHomoglyphConfusable      Family = "homoglyph-confusable"
	FamilyMixedScript              Family = "mixed-script-admissibility"
	FamilyRtlInjection             Family = "rtl-injection"
	FamilyConfusableBidiCompound   Family = "confusable-bidi-compound"
	FamilyCovertDisplayCompound    Family = "covert-display-compound"
	FamilyHashInputStability       Family = "hash-input-stability"
	FamilyAiWatermarkDetect        Family = "ai-watermark-detectability"
	FamilyStreamSafeViolation      Family = "stream-safe-violation"
	FamilyEmojiZwjIntegrity        Family = "emoji-zwj-integrity"
	FamilyRendererDivergence       Family = "renderer-divergence"
	FamilyFilenameDisguise         Family = "filename-disguise"
	FamilyIdentifierFormDrift      Family = "identifier-form-drift"
	FamilySkinToneVariationForgery Family = "skin-tone-variation-forgery"
	FamilyCaseExpansionMismatch    Family = "case-expansion-mismatch"
	FamilyAdmissibilityFormDrift   Family = "admissibility-form-drift"
	FamilySourceDisplayDivergence  Family = "source-display-divergence"
	FamilyWidthClassConfusion      Family = "width-class-confusion"
	FamilyNormalizationBomb        Family = "normalization-bomb"
	FamilyLocaleCaseInversion      Family = "locale-case-inversion"
	FamilyNfcIdempotenceWitness    Family = "nfc-idempotence-witness"
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

// classifiedFinding builds a Finding from a detector classification's tag and
// positions. Every detector below reports the same shape -- a tag that is
// absent when the input is clear -- so the record is built here once rather
// than repeated per family. The severity is 2 because each of these
// classifications is a hazard, matching the reference's Hazard-to-Moderate
// mapping.
func classifiedFinding(family Family, tag string, ok bool, positions []int) (Finding, bool) {
	if !ok {
		return Finding{}, false
	}
	if positions == nil {
		positions = []int{}
	}
	return Finding{
		Code:      reasonCode(family, tag),
		Family:    family,
		Severity:  2,
		Positions: positions,
		SubThreat: tag,
		Detail:    string(family),
	}, true
}

func appendClassified(findings []Finding, family Family, tag string, ok bool, positions []int) []Finding {
	if finding, fired := classifiedFinding(family, tag, ok, positions); fired {
		return append(findings, finding)
	}
	return findings
}

func detect(input []uint32) []Finding {
	findings := make([]Finding, 0, 8)

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

	if finding, ok := surrogateReassemblyFinding(input); ok {
		findings = append(findings, finding)
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
	if finding, ok := rtlInjectionFinding(input); ok {
		findings = append(findings, finding)
	}
	if finding, ok := confusableBidiCompoundFinding(input); ok {
		findings = append(findings, finding)
	}
	if finding, ok := covertDisplayCompoundFinding(input); ok {
		findings = append(findings, finding)
	}

	ezwj := ezwjDetect(input)
	ezwjTag, ezwjFired := ezwj.classify.tag()
	findings = appendClassified(findings, FamilyEmojiZwjIntegrity, ezwjTag, ezwjFired, ezwj.classify.positions)

	stvf := stvfDetect(input)
	stvfTag, stvfFired := stvf.classify.tag()
	findings = appendClassified(findings, FamilySkinToneVariationForgery, stvfTag, stvfFired, stvf.classify.posns())

	fd := filenameDisguiseDetect(input)
	fdTag, fdFired := fd.classify.tag()
	findings = appendClassified(findings, FamilyFilenameDisguise, fdTag, fdFired, fd.classify.posns())

	rd := rendererDivergenceDetect(input)
	rdTag, rdFired := rd.classify.tag()
	findings = appendClassified(findings, FamilyRendererDivergence, rdTag, rdFired, rd.classify.posns())

	ss := streamSafeViolationDetect(input)
	ssTag, ssFired := ss.classify.tag()
	findings = appendClassified(findings, FamilyStreamSafeViolation, ssTag, ssFired, ss.classify.positions)

	cem := caseExpansionMismatchDetect(input)
	cemTag, cemFired := cem.classify.tag()
	findings = appendClassified(findings, FamilyCaseExpansionMismatch, cemTag, cemFired, cem.classify.posns())

	ifd := identifierFormDriftDetect(input)
	ifdTag, ifdFired := ifd.classify.tag()
	findings = appendClassified(findings, FamilyIdentifierFormDrift, ifdTag, ifdFired, ifd.classify.posns())

	afd := admissibilityFormDriftDetect(input)
	afdTag, afdFired := afd.classify.tag()
	findings = appendClassified(findings, FamilyAdmissibilityFormDrift, afdTag, afdFired, afd.classify.posns())

	if sub, positions, fired := normalizationBombDetect(input); fired {
		findings = appendClassified(findings, FamilyNormalizationBomb, sub, true, positions)
	}

	if sub, positions, fired := localeCaseInversionDetect(input); fired {
		findings = appendClassified(findings, FamilyLocaleCaseInversion, sub, true, positions)
	}

	if sub, positions, fired := nfcIdempotenceWitnessDetect(input); fired {
		findings = appendClassified(findings, FamilyNfcIdempotenceWitness, sub, true, positions)
	}

	if width := DetectWidthClassConfusion(input); width.SubThreat != "" {
		findings = appendClassified(findings, FamilyWidthClassConfusion, width.SubThreat, true, width.Positions)
	}

	// SourceDisplayDivergence judges the input as a unit, so it localises
	// nothing and carries an empty position list.
	if sdd := sourceDisplayDivergenceDetect(input); !sdd.isClear() {
		findings = appendClassified(findings, FamilySourceDisplayDivergence, sdd.sub, true, []int{})
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
			family == FamilySurrogateReassembly ||
			family == FamilyHomoglyphConfusable ||
			family == FamilyMixedScript ||
			family == FamilyEmojiZwjIntegrity ||
			family == FamilySkinToneVariationForgery ||
			family == FamilySourceDisplayDivergence ||
			family == FamilyFilenameDisguise ||
			family == FamilyRtlInjection ||
			family == FamilyRendererDivergence ||
			family == FamilyNormalizationBomb ||
			family == FamilyStreamSafeViolation ||
			family == FamilyLocaleCaseInversion ||
			family == FamilyCaseExpansionMismatch ||
			family == FamilyWidthClassConfusion ||
			family == FamilyNfcIdempotenceWitness ||
			family == FamilyIdentifierFormDrift ||
			family == FamilyCovertDisplayCompound ||
			family == FamilyConfusableBidiCompound ||
			family == FamilyAdmissibilityFormDrift
	case PolicyModerate:
		return family == FamilyMalformedUTF8 ||
			family == FamilyMalformedUTF16 ||
			family == FamilyMalformedUTF32 ||
			family == FamilyTagBlockPayload ||
			family == FamilyVariationSelector ||
			family == FamilyZeroWidthPayload ||
			family == FamilyBidiControlBalance ||
			family == FamilyNoncharacterControl ||
			family == FamilySurrogateReassembly ||
			family == FamilyHomoglyphConfusable ||
			family == FamilyMixedScript ||
			family == FamilySkinToneVariationForgery ||
			family == FamilySourceDisplayDivergence ||
			family == FamilyFilenameDisguise ||
			family == FamilyStreamSafeViolation ||
			family == FamilyLocaleCaseInversion ||
			family == FamilyCaseExpansionMismatch ||
			family == FamilyWidthClassConfusion ||
			family == FamilyNfcIdempotenceWitness ||
			family == FamilyIdentifierFormDrift ||
			family == FamilyCovertDisplayCompound ||
			family == FamilyConfusableBidiCompound ||
			family == FamilyAdmissibilityFormDrift
	case PolicyMinimal:
		return family == FamilyMalformedUTF8 ||
			family == FamilyMalformedUTF16 ||
			family == FamilyMalformedUTF32 ||
			family == FamilySurrogateReassembly ||
			family == FamilyBidiControlBalance ||
			family == FamilyNoncharacterControl ||
			family == FamilyStreamSafeViolation
	default:
		return family == FamilyMalformedUTF8 ||
			family == FamilyMalformedUTF16 ||
			family == FamilyMalformedUTF32 ||
			family == FamilyTagBlockPayload ||
			family == FamilyVariationSelector ||
			family == FamilyZeroWidthPayload ||
			family == FamilyBidiControlBalance ||
			family == FamilyNoncharacterControl ||
			family == FamilySurrogateReassembly ||
			family == FamilyHomoglyphConfusable ||
			family == FamilyMixedScript ||
			family == FamilyEmojiZwjIntegrity ||
			family == FamilySkinToneVariationForgery ||
			family == FamilySourceDisplayDivergence ||
			family == FamilyFilenameDisguise ||
			family == FamilyRtlInjection ||
			family == FamilyRendererDivergence ||
			family == FamilyNormalizationBomb ||
			family == FamilyStreamSafeViolation ||
			family == FamilyLocaleCaseInversion ||
			family == FamilyCaseExpansionMismatch ||
			family == FamilyWidthClassConfusion ||
			family == FamilyNfcIdempotenceWitness ||
			family == FamilyIdentifierFormDrift ||
			family == FamilyCovertDisplayCompound ||
			family == FamilyConfusableBidiCompound ||
			family == FamilyAdmissibilityFormDrift
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
	if len(positions) == 1 && isRegisteredVariationPosition(input, positions[0]) {
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

func isRegisteredVariationPosition(input []uint32, position int) bool {
	return position > 0 && isRegisteredVariationPair(input[position-1], input[position])
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
	seen := map[string]bool{}
	for _, cp := range input {
		if script, ok := scriptClass(cp); ok {
			seen[script] = true
		}
	}
	if len(seen) < 2 {
		return Finding{}, false
	}
	// Name the specific script collision to match the Lean source of truth.
	// Priority follows Lean: Latin/Cyrillic before Latin/Greek.
	subThreat := "ScriptMixOther"
	switch {
	case seen["Latn"] && seen["Cyrl"]:
		subThreat = "LatinCyrillic"
	case seen["Latn"] && seen["Grek"]:
		subThreat = "LatinGreek"
	}
	return Finding{
		Code:      reasonCode(FamilyMixedScript, subThreat),
		Family:    FamilyMixedScript,
		Severity:  2,
		Positions: fullSpanPositions(input),
		SubThreat: subThreat,
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
	case FamilyMalformedUTF8, FamilyMalformedUTF16, FamilyMalformedUTF32, FamilyTagBlockPayload, FamilyVariationSelector, FamilyZeroWidthPayload, FamilySurrogateReassembly, FamilyBidiControlBalance, FamilyNoncharacterControl:
		return "C"
	case FamilyHomoglyphConfusable, FamilyMixedScript, FamilyEmojiZwjIntegrity, FamilySkinToneVariationForgery:
		return "I"
	case FamilyRtlInjection, FamilyRendererDivergence, FamilyFilenameDisguise, FamilySourceDisplayDivergence:
		return "D"
	case FamilyConfusableBidiCompound, FamilyCovertDisplayCompound, FamilyIdentifierFormDrift, FamilyAdmissibilityFormDrift:
		return "X"
	case FamilyStreamSafeViolation, FamilyCaseExpansionMismatch, FamilyWidthClassConfusion,
		FamilyNormalizationBomb, FamilyLocaleCaseInversion, FamilyNfcIdempotenceWitness:
		return "F"
	case FamilyHashInputStability, FamilyAiWatermarkDetect:
		return "K"
	default:
		return "C"
	}
}
