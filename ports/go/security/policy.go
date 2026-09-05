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

// profileIsIdentifierField reports whether the profile names a field that holds
// one identifier rather than running text.
//
// A username, a registrable domain and a DNS label are single identifiers, so a
// codepoint outside the General Security Profile is a hazard in them. The
// remaining profiles carry prose, source, URLs or opaque bytes, where a space
// and a punctuation mark are ordinary content. Mirrors profileIsIdentifierField
// in Unicode/Security/Policy.lean.
func profileIsIdentifierField(profile Profile) bool {
	switch profile {
	case ProfileDomainName, ProfileDnsLabel, ProfileUsername:
		return true
	default:
		return false
	}
}

func PolicyOfProfile(profile Profile) ProfilePolicy {
	switch profile {
	case ProfileGatewayHeader, ProfileDomainName, ProfileDnsLabel:
		return ProfilePolicy{Level: PolicyRestrictive}
	// Source files legitimately carry right-to-left string literals, comments
	// written in Hebrew or Arabic, and emoji. Restrictive admits RtlInjection,
	// whose contract treats its input as a declared-LTR field, so under it an
	// ordinary Hebrew comment is rejected. Moderate retains every detector that
	// catches the Trojan Source class while dropping the field-direction
	// assumption a source file does not satisfy.
	case ProfileURL, ProfileSourceCode:
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

// profileIsRunningText reports whether the profile names a field of running
// text — prose or source, a whole file or message — rather than a single value.
// The identifier-scoped rungs read such a field per identifier token, and the
// declared-field detector rtlInjection, the casing families and the filename
// extension rungs do not run on it. Mirrors profileIsRunningText in
// Unicode/Security/Policy.lean.
func profileIsRunningText(profile Profile) bool {
	switch profile {
	case ProfileDisplayName, ProfileChatMessage, ProfileSourceCode:
		return true
	default:
		return false
	}
}

func Scan(profile Profile, mode Mode, input []uint32) Verdict {
	findings := detect(input, profileIsIdentifierField(profile), profileIsRunningText(profile))
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

// detect runs every family over input. identifierField and runningText carry
// what the caller knows about the field, mirroring Unicode.Security.RunAll's
// Context: a family scoped to identifiers needs to know whether it is holding
// one, and running text is read per identifier token by the identifier
// detectors and not at all by the single-value families.
func detect(input []uint32, identifierField bool, runningText bool) []Finding {
	findings := make([]Finding, 0, 8)

	// The whole tag block counts, not only the ASCII-bearing span, and which
	// hazard it is depends on what the run contains: see tagBlockSubThreat.
	if positions := positionsWhere(input, isTagCharacter); len(positions) > 0 {
		sub := tagBlockSubThreat(input, positions)
		findings = append(findings, Finding{
			Code:      reasonCode(FamilyTagBlockPayload, sub),
			Family:    FamilyTagBlockPayload,
			Severity:  2,
			Positions: positions,
			SubThreat: sub,
			Detail:    "tag-block-payload",
		})
	}

	if finding, ok := variationSelectorFinding(input); ok {
		findings = append(findings, finding)
	}

	// The sanctioning model: a ZWJ inside a registered emoji sequence and a
	// ZWNJ in an RFC 5892 CONTEXTJ-valid position both carry meaning a reader
	// depends on, so they are recorded as present but not treated as
	// suspicious. An input whose zero-width characters are all sanctioned
	// raises nothing.
	if positions := positionsWhere(input, isZeroWidthPayload); len(positions) > 0 && hasSuspiciousZeroWidth(input, positions) {
		sub := zeroWidthSubThreat(input, positions)
		findings = append(findings, Finding{
			Code:      reasonCode(FamilyZeroWidthPayload, sub),
			Family:    FamilyZeroWidthPayload,
			Severity:  2,
			Positions: positions,
			SubThreat: sub,
			Detail:    "zero-width-payload",
		})
	}

	if finding, ok := surrogateReassemblyFinding(input); ok {
		findings = append(findings, finding)
	}

	// Bidi controls that balance within the depth bound are legitimate
	// right-to-left text and raise nothing; bidiSubThreat reports only when the
	// stack walk finds an orphan, an unclosed opener, or excessive nesting.
	if sub, positions, fired := bidiSubThreat(input); fired {
		findings = append(findings, Finding{
			Code:      reasonCode(FamilyBidiControlBalance, sub),
			Family:    FamilyBidiControlBalance,
			Severity:  2,
			Positions: positions,
			SubThreat: sub,
			Detail:    "bidi-control-balance",
		})
	}

	findings = append(findings, noncharacterControlFindings(input)...)
	// Running text is judged per identifier-shaped token by the identifier
	// detectors (Lean homoglyphOverTokens / mixedScriptOverTokens): a bilingual
	// file is not one mixed-script identifier, and a scоpe inside it is. The
	// first token that fires carries the verdict, its positions shifted into
	// the input; when none does, the whole input is read under the running-text
	// reading.
	homoglyphFinding, homoglyphFired := homoglyphOverTokens(input, runningText)
	if homoglyphFired {
		findings = append(findings, homoglyphFinding)
	}
	if finding, ok := mixedScriptOverTokens(input, identifierField, runningText); ok {
		findings = append(findings, finding)
	}
	// RtlInjection judges a field declared left-to-right; running text declares
	// no direction, so the family reports clear on it (Lean: mkGatedResult).
	if !runningText {
		if finding, ok := rtlInjectionFinding(input); ok {
			findings = append(findings, finding)
		}
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

	fd := filenameDisguiseDetectCtx(input, runningText)
	fdTag, fdFired := fd.classify.tag()
	findings = appendClassified(findings, FamilyFilenameDisguise, fdTag, fdFired, fd.classify.posns())

	rd := rendererDivergenceDetectCtx(input, runningText)
	rdTag, rdFired := rd.classify.tag()
	findings = appendClassified(findings, FamilyRendererDivergence, rdTag, rdFired, rd.classify.posns())

	ss := streamSafeViolationDetect(input)
	ssTag, ssFired := ss.classify.tag()
	findings = appendClassified(findings, FamilyStreamSafeViolation, ssTag, ssFired, ss.classify.positions)

	// Case expansion asks whether a length-checked value grows under case
	// mapping; in running text ß and ﬁ are content (Lean: mkGatedResult).
	if !runningText {
		cem := caseExpansionMismatchDetect(input)
		cemTag, cemFired := cem.classify.tag()
		findings = appendClassified(findings, FamilyCaseExpansionMismatch, cemTag, cemFired, cem.classify.posns())
	}

	ifd := identifierFormDriftDetect(input)
	ifdTag, ifdFired := ifd.classify.tag()
	findings = appendClassified(findings, FamilyIdentifierFormDrift, ifdTag, ifdFired, ifd.classify.posns())

	afd := admissibilityFormDriftDetect(input)
	afdTag, afdFired := afd.classify.tag()
	findings = appendClassified(findings, FamilyAdmissibilityFormDrift, afdTag, afdFired, afd.classify.posns())

	if sub, positions, fired := normalizationBombDetect(input); fired {
		findings = appendClassified(findings, FamilyNormalizationBomb, sub, true, positions)
	}

	// Locale case inversion asks whether a credential folds differently across
	// locales; in running text a capital I is content (Lean: mkGatedResult).
	if !runningText {
		if sub, positions, fired := localeCaseInversionDetect(input); fired {
			findings = appendClassified(findings, FamilyLocaleCaseInversion, sub, true, positions)
		}
	}

	if sub, positions, fired := nfcIdempotenceWitnessDetect(input); fired {
		findings = appendClassified(findings, FamilyNfcIdempotenceWitness, sub, true, positions)
	}

	if width := DetectWidthClassConfusion(input); width.SubThreat != "" {
		findings = appendClassified(findings, FamilyWidthClassConfusion, width.SubThreat, true, width.Positions)
	}

	// SourceDisplayDivergence judges the input as a unit, so it localises
	// nothing and carries an empty position list. Its homoglyph constituent is
	// the same verdict the homoglyph family reported above, so a source file's
	// token-level homograph is a display divergence (Lean: detectCore input i1).
	if sdd := sourceDisplayDivergenceDetectCore(input, homoglyphFired); !sdd.isClear() {
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

// isZeroWidthPayload reports whether cp renders as nothing, mirroring
// `isZeroWidth` in Unicode.Security.Covert.ZeroWidthPayload: the explicit
// historical set, which preserves sub-threat dispatch, extended by the UAX #44
// Default_Ignorable_Code_Point property, which catches every other invisible
// codepoint.
//
// The sibling ranges are excluded because their own family detector dispatches
// them with richer payload decoding or bidi-stack tracking, and counting them
// here as well would report one hazard twice: U+FE00..U+FE0F and
// U+E0100..U+E01EF for variation-selector-payload, U+E0000..U+E007F for
// tag-block-payload, and U+202A..U+202E with U+2066..U+2069 for
// bidi-control-balance. LRM and RLM are not excluded: they are direction
// markers rather than push-pop controls, and bidi-control-balance does not
// track them.
func isZeroWidthPayload(cp uint32) bool {
	switch {
	case cp >= 0x200B && cp <= 0x200F:
		return true
	case cp >= 0x2060 && cp <= 0x2064:
		return true
	case cp == 0x202F || cp == 0xFEFF:
		return true
	case cp >= 0xFFF9 && cp <= 0xFFFB:
		return true
	}
	return isDefaultIgnorableCodepoint(cp) && !isZeroWidthSiblingHandled(cp)
}

// isZeroWidthSiblingHandled reports whether cp is Default_Ignorable but belongs
// to a sibling detector's family rather than to zero-width-payload.
func isZeroWidthSiblingHandled(cp uint32) bool {
	switch {
	case cp >= 0xFE00 && cp <= 0xFE0F:
		return true
	case cp >= 0xE0100 && cp <= 0xE01EF:
		return true
	case cp >= 0xE0000 && cp <= 0xE007F:
		return true
	case cp >= 0x202A && cp <= 0x202E:
		return true
	case cp >= 0x2066 && cp <= 0x2069:
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

// homoglyphContext mirrors Unicode.Security.Identity.HomoglyphConfusable.Context.
// runningText says the input is prose or source rather than one value: the
// script-composition rungs (CrossScriptMix, RestrictionLow) would judge such a
// document as one identifier and AsciiConfusable would report a curly quote, so
// they do not run. identifierToken says the input is one identifier-shaped token
// cut out of running text: the homograph rungs run, RestrictionLow does not,
// and AsciiConfusable runs for a Latin token only — admın in a source file is an
// identifier posing as admin, a Greek variable is content.
type homoglyphContext struct {
	runningText     bool
	identifierToken bool
}

// asciiSkeleton is the case-preserving UTS #39 §4 skeleton
// toNFD(substitute(toNFD(x))): the §4 bracket without the §5.4 case folding
// skeleton adds, since full folding would read straße as confusable with
// strasse. Mirrors the Lean asciiSkeleton.
func asciiSkeleton(input []uint32) []uint32 {
	return toNFD(substituteConfusables(toNFD(input)))
}

// isAsciiConfusable reports whether the input is not ASCII but its
// case-preserving skeleton is: every non-ASCII codepoint is a confusable of an
// ASCII one (admın with admin). Mirrors the Lean isAsciiConfusable.
func isAsciiConfusable(input []uint32) bool {
	nonAscii := false
	for _, cp := range input {
		if cp >= 0x80 {
			nonAscii = true
			break
		}
	}
	if !nonAscii {
		return false
	}
	for _, cp := range asciiSkeleton(input) {
		if cp >= 0x80 {
			return false
		}
	}
	return true
}

// nonAsciiPositions mirrors the Lean nonAsciiPositions.
func nonAsciiPositions(input []uint32) []int {
	out := make([]int, 0, 2)
	for idx, cp := range input {
		if cp >= 0x80 {
			out = append(out, idx)
		}
	}
	return out
}

// isLatinOnly reports whether every non-Common, non-Inherited codepoint is
// Latin. Mirrors the Lean isLatinOnly.
func isLatinOnly(input []uint32) bool {
	union := stringScriptUnion(input)
	return len(union) == 1 && union[0] == "Latn"
}

func homoglyphConfusableFinding(input []uint32) (Finding, bool) {
	return homoglyphConfusableFindingCtx(input, homoglyphContext{})
}

// homoglyphConfusableFindingCtx runs the homoglyph ladder under an explicit
// field context. Priority mirrors Unicode/Security/Identity/HomoglyphConfusable
// .lean: TargetMatch, MathAlpha, WidthClass, DecompositionSwap, CrossScriptMix,
// RestrictionLow, AsciiConfusable.
func homoglyphConfusableFindingCtx(input []uint32, ctx homoglyphContext) (Finding, bool) {
	subThreat := ""
	positions := fullSpanPositions(input)
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
	// The script rungs of the Lean ladder, in its order: a cross-script mix that
	// is not Highly Restrictive, then a string that fails every restriction
	// level. Both ask about one identifier; running text mixes scripts as
	// content, and a historic-script token of running text is content too.
	if subThreat == "" && !ctx.runningText && hasCrossScriptMix(input) {
		subThreat = "CrossScriptMix"
	}
	if subThreat == "" && !ctx.runningText && !ctx.identifierToken {
		level := restrictionLevel(input)
		if level == RestrictionMinimallyRestrictive || level == RestrictionUnrestricted {
			subThreat = "RestrictionLow"
		}
	}
	// Last: a non-ASCII input whose skeleton is ASCII poses as an ASCII name.
	// Not in running text; for a token of running text only when it is Latin.
	if subThreat == "" && !ctx.runningText && (!ctx.identifierToken || isLatinOnly(input)) && isAsciiConfusable(input) {
		subThreat = "AsciiConfusable"
		positions = nonAsciiPositions(input)
	}
	if subThreat == "" {
		return Finding{}, false
	}
	return Finding{
		Code:      reasonCode(FamilyHomoglyphConfusable, subThreat),
		Family:    FamilyHomoglyphConfusable,
		Severity:  2,
		Positions: positions,
		SubThreat: subThreat,
		Detail:    string(FamilyHomoglyphConfusable),
	}, true
}

// homoglyphOverTokens mirrors the Lean homoglyphOverTokens for running text
// and the whole-input reading otherwise: in running text the first identifier
// token that fires carries the verdict, with its positions shifted into the
// input; when none does, the whole input is read under the running-text
// reading.
func homoglyphOverTokens(input []uint32, runningText bool) (Finding, bool) {
	if !runningText {
		return homoglyphConfusableFindingCtx(input, homoglyphContext{})
	}
	for _, token := range identifierTokens(input) {
		finding, ok := homoglyphConfusableFindingCtx(token.cps, homoglyphContext{identifierToken: true})
		if ok {
			finding.Positions = shiftPositions(token.start, finding.Positions)
			return finding, true
		}
	}
	return homoglyphConfusableFindingCtx(input, homoglyphContext{runningText: true})
}

// mixedScriptOverTokens mirrors the Lean mixedScriptOverTokens: running text is
// read per identifier token without the Restricted-status phase a token of
// running text does not owe; a single value is read whole.
func mixedScriptOverTokens(input []uint32, identifierField bool, runningText bool) (Finding, bool) {
	if !runningText {
		return mixedScriptAdmissibilityFinding(input, identifierField)
	}
	for _, token := range identifierTokens(input) {
		if finding, ok := mixedScriptAdmissibilityFinding(token.cps, false); ok {
			finding.Positions = shiftPositions(token.start, finding.Positions)
			return finding, true
		}
	}
	return Finding{}, false
}

// mixedScriptVerdict returns the mixed-script sub-threat for input, or false
// when it is admissible.
//
// The rung order is Unicode/Security/Identity/MixedScriptAdmissibility.lean's:
// a Restricted-status codepoint outranks every script question, then the two
// named Latin pairs, then a multi-script mix split by whether it stays inside a
// CJK covered set, and finally an Unrestricted level with no script mix.
//
// identifierField carries what the caller knows about the field, mirroring that
// module's Context. Phase 1 is sound for an identifier, which cannot contain a
// space, and unsound for a document, where every space and every punctuation
// mark is Restricted.
func mixedScriptVerdict(input []uint32, identifierField bool) (string, bool) {
	if identifierField {
		for _, cp := range input {
			if !isIdAllowed(cp) {
				return "RestrictedStatusCp", true
			}
		}
	}
	union := stringScriptUnion(input)
	seen := map[string]bool{}
	for _, s := range union {
		seen[s] = true
	}
	if seen["Latn"] && seen["Cyrl"] {
		return "LatinCyrillic", true
	}
	if seen["Latn"] && seen["Grek"] {
		return "LatinGreek", true
	}
	if len(union) >= 2 && !isHighlyRestrictive(input) {
		if isCoveredCJK(input) {
			return "CjkMix", true
		}
		return "ScriptMixOther", true
	}
	if identifierField && restrictionLevel(input) == RestrictionUnrestricted {
		return "UnrestrictedLevel", true
	}
	return "", false
}

func mixedScriptAdmissibilityFinding(input []uint32, identifierField bool) (Finding, bool) {
	subThreat, ok := mixedScriptVerdict(input, identifierField)
	if !ok {
		return Finding{}, false
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
