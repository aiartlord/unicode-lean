package security

import (
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

//go:embed data/confusables.txt
var confusablesRaw string

//go:embed data/CaseFolding.txt
var caseFoldingRaw string

//go:embed data/KnownAttackTargets.txt
var knownAttackTargetsRaw string

//go:embed data/StandardizedVariants.txt
var standardizedVariantsRaw string

//go:embed data/emoji-variation-sequences.txt
var emojiVariationSequencesRaw string

//go:embed data/UnicodeData.txt
var unicodeDataRaw string

//go:embed data/CompositionExclusions.txt
var compositionExclusionsRaw string

var (
	confusablesOnce sync.Once
	confusablesData map[uint32][]uint32
	caseFoldOnce    sync.Once
	caseFoldData    map[uint32][]uint32
	targetsOnce     sync.Once
	targetsData     []string
	variationOnce   sync.Once
	variationPairs  map[[2]uint32]struct{}
	normalOnce      sync.Once
	normalData      normalizationData
	composeOnce     sync.Once
	composeTable    map[[2]uint32]uint32
)

type normalizationData struct {
	ccc map[uint32]uint8
	// Canonical decomposition (field 5 without a `<tag>` prefix). Used by
	// NFD/NFC.
	decomp map[uint32][]uint32
	// Compatibility decomposition (field 5 with a `<tag>` prefix), tag
	// stripped. Used by NFKD/NFKC only.
	compat map[uint32][]uint32
}

func homoglyphTargetMatch(input []uint32) (string, bool) {
	inputLetters := letterSkeleton(input)
	matchIndex := -1
	targets := knownAttackTargets()
	for index, target := range targets {
		targetCps := asciiCodepoints(target)
		targetLetters := letterSkeleton(targetCps)
		matches := !equalUint32Slices(targetCps, input) && ctUint32SlicesEqual(targetLetters, inputLetters)
		if matches && matchIndex < 0 {
			matchIndex = index
		}
	}
	if matchIndex < 0 {
		return "", false
	}
	return targets[matchIndex], true
}

func letterSkeleton(input []uint32) []uint32 {
	iterated := iteratedSkeleton(input)
	out := make([]uint32, 0, len(iterated))
	for _, cp := range iterated {
		if !isCombiningMark(cp) && !isDefaultIgnorableCodepoint(cp) && !isWhiteSpaceCodepoint(cp) {
			out = append(out, cp)
		}
	}
	return out
}

func iteratedSkeleton(input []uint32) []uint32 {
	current := append([]uint32(nil), input...)
	for range 8 {
		next := skeleton(current)
		if equalUint32Slices(next, current) {
			return current
		}
		current = next
	}
	return current
}

func skeleton(input []uint32) []uint32 {
	step1 := toNFD(input)
	step2 := caseFoldCodepoints(step1)
	step3 := substituteConfusables(step2)
	step4 := caseFoldCodepoints(step3)
	return toNFD(step4)
}

func substituteConfusables(input []uint32) []uint32 {
	table := confusablesMap()
	out := make([]uint32, 0, len(input))
	for _, cp := range input {
		if replacement, ok := table[cp]; ok {
			out = append(out, replacement...)
		} else {
			out = append(out, cp)
		}
	}
	return out
}

func caseFoldCodepoints(input []uint32) []uint32 {
	table := caseFoldingMap()
	out := make([]uint32, 0, len(input))
	for _, cp := range input {
		if replacement, ok := table[cp]; ok {
			out = append(out, replacement...)
		} else {
			out = append(out, cp)
		}
	}
	return out
}

func toNFD(input []uint32) []uint32 {
	out := make([]uint32, 0, len(input))
	for _, cp := range input {
		appendCanonicalDecomposition(&out, cp)
	}
	canonicalOrder(out)
	return out
}

func appendCanonicalDecomposition(out *[]uint32, cp uint32) {
	if jamo, ok := decomposeHangulSyllable(cp); ok {
		*out = append(*out, jamo...)
		return
	}
	if decomposition, ok := normalizationTables().decomp[cp]; ok {
		for _, part := range decomposition {
			appendCanonicalDecomposition(out, part)
		}
		return
	}
	*out = append(*out, cp)
}

func canonicalOrder(values []uint32) {
	for index := 1; index < len(values); index++ {
		currentCCC := canonicalCombiningClass(values[index])
		if currentCCC == 0 {
			continue
		}
		for j := index; j > 0; j-- {
			previousCCC := canonicalCombiningClass(values[j-1])
			if previousCCC == 0 || previousCCC <= currentCCC {
				break
			}
			values[j-1], values[j] = values[j], values[j-1]
		}
	}
}

func canonicalCombiningClass(cp uint32) uint8 {
	return normalizationTables().ccc[cp]
}

func normalizationTables() normalizationData {
	normalOnce.Do(func() {
		normalData = parseUnicodeData(unicodeDataRaw)
	})
	return normalData
}

func parseUnicodeData(raw string) normalizationData {
	out := normalizationData{
		ccc:    make(map[uint32]uint8),
		decomp: make(map[uint32][]uint32),
		compat: make(map[uint32][]uint32),
	}
	for _, rawLine := range strings.Split(raw, "\n") {
		fields := strings.Split(rawLine, ";")
		if len(fields) < 6 {
			continue
		}
		cp, ok := parseHexUint32(fields[0])
		if !ok {
			continue
		}
		if ccc, ok := parseDecimalUint8(fields[3]); ok && ccc != 0 {
			out.ccc[cp] = ccc
		}
		decompField := strings.TrimSpace(fields[5])
		if decompField == "" {
			continue
		}
		if strings.HasPrefix(decompField, "<") {
			// Compatibility decomposition: strip the `<tag>` prefix and
			// keep the codepoints for NFKD/NFKC (not NFD/NFC).
			afterTag := decompField
			if _, rest, found := strings.Cut(decompField, ">"); found {
				afterTag = rest
			}
			compat := parseCodepointField(afterTag)
			if len(compat) > 0 {
				out.compat[cp] = compat
			}
			continue
		}
		decomp := parseCodepointField(decompField)
		if len(decomp) > 0 {
			out.decomp[cp] = decomp
		}
	}
	return out
}

func parseDecimalUint8(field string) (uint8, bool) {
	value, err := strconv.ParseUint(strings.TrimSpace(field), 10, 8)
	if err != nil {
		return 0, false
	}
	return uint8(value), true
}

func decomposeHangulSyllable(cp uint32) ([]uint32, bool) {
	const (
		sBase  uint32 = 0xAC00
		lBase  uint32 = 0x1100
		vBase  uint32 = 0x1161
		tBase  uint32 = 0x11A7
		lCount uint32 = 19
		vCount uint32 = 21
		tCount uint32 = 28
		nCount uint32 = vCount * tCount
		sCount uint32 = lCount * nCount
	)
	if cp < sBase || cp >= sBase+sCount {
		return nil, false
	}
	sIndex := cp - sBase
	l := lBase + sIndex/nCount
	v := vBase + (sIndex%nCount)/tCount
	tIndex := sIndex % tCount
	if tIndex == 0 {
		return []uint32{l, v}, true
	}
	return []uint32{l, v, tBase + tIndex}, true
}

func confusablesMap() map[uint32][]uint32 {
	confusablesOnce.Do(func() {
		confusablesData = parseConfusables(confusablesRaw)
	})
	return confusablesData
}

func caseFoldingMap() map[uint32][]uint32 {
	caseFoldOnce.Do(func() {
		caseFoldData = parseCaseFolding(caseFoldingRaw)
	})
	return caseFoldData
}

func knownAttackTargets() []string {
	targetsOnce.Do(func() {
		targetsData = parseKnownAttackTargets(knownAttackTargetsRaw)
	})
	return targetsData
}

func isRegisteredVariationPair(base uint32, vs uint32) bool {
	pairs := legalVariationPairs()
	_, ok := pairs[[2]uint32{base, vs}]
	return ok
}

func legalVariationPairs() map[[2]uint32]struct{} {
	variationOnce.Do(func() {
		variationPairs = make(map[[2]uint32]struct{})
		parseLegalVariationPairs(standardizedVariantsRaw, variationPairs)
		parseLegalVariationPairs(emojiVariationSequencesRaw, variationPairs)
	})
	return variationPairs
}

func parseConfusables(raw string) map[uint32][]uint32 {
	out := make(map[uint32][]uint32)
	for _, rawLine := range strings.Split(raw, "\n") {
		body, _, _ := strings.Cut(rawLine, "#")
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		fields := strings.Split(body, ";")
		if len(fields) < 2 {
			continue
		}
		src, ok := parseHexUint32(fields[0])
		if !ok {
			continue
		}
		target := parseCodepointField(fields[1])
		if len(target) == 0 {
			continue
		}
		out[src] = target
	}
	return out
}

func parseCaseFolding(raw string) map[uint32][]uint32 {
	out := make(map[uint32][]uint32)
	for _, rawLine := range strings.Split(raw, "\n") {
		body, _, _ := strings.Cut(rawLine, "#")
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		fields := strings.Split(body, ";")
		if len(fields) < 3 {
			continue
		}
		status := strings.TrimSpace(fields[1])
		if status != "C" && status != "F" {
			continue
		}
		cp, ok := parseHexUint32(fields[0])
		if !ok {
			continue
		}
		mapping := parseCodepointField(fields[2])
		if len(mapping) == 0 {
			continue
		}
		out[cp] = mapping
	}
	return out
}

func parseKnownAttackTargets(raw string) []string {
	var out []string
	for _, rawLine := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func parseLegalVariationPairs(raw string, out map[[2]uint32]struct{}) {
	for _, rawLine := range strings.Split(raw, "\n") {
		body, _, _ := strings.Cut(rawLine, "#")
		pairPart, _, _ := strings.Cut(body, ";")
		fields := strings.Fields(pairPart)
		if len(fields) != 2 {
			continue
		}
		base, ok := parseHexUint32(fields[0])
		if !ok {
			continue
		}
		vs, ok := parseHexUint32(fields[1])
		if !ok {
			continue
		}
		out[[2]uint32{base, vs}] = struct{}{}
	}
}

func parseCodepointField(field string) []uint32 {
	var out []uint32
	for _, token := range strings.Fields(field) {
		if cp, ok := parseHexUint32(token); ok {
			out = append(out, cp)
		}
	}
	return out
}

func parseHexUint32(field string) (uint32, bool) {
	value, err := strconv.ParseUint(strings.TrimSpace(field), 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(value), true
}

func asciiCodepoints(value string) []uint32 {
	out := make([]uint32, 0, len(value))
	for _, b := range []byte(value) {
		out = append(out, uint32(b))
	}
	return out
}

func equalUint32Slices(a []uint32, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func ctUint32SlicesEqual(a []uint32, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	var acc uint32
	for index := range a {
		acc |= a[index] ^ b[index]
	}
	return acc == 0
}

func isCombiningMark(cp uint32) bool {
	return (cp >= 0x0300 && cp <= 0x036F) ||
		(cp >= 0x1AB0 && cp <= 0x1AFF) ||
		(cp >= 0x1DC0 && cp <= 0x1DFF) ||
		(cp >= 0x20D0 && cp <= 0x20FF) ||
		(cp >= 0xFE20 && cp <= 0xFE2F)
}

func hasDecompositionSwap(input []uint32) bool {
	for index := 1; index < len(input); index++ {
		previous := input[index-1]
		current := input[index]
		if isCombiningMark(current) && !isCombiningMark(previous) {
			return true
		}
		if isCombiningMark(previous) && isCombiningMark(current) && previous > current {
			return true
		}
		if composeHangulPair(previous, current) {
			return true
		}
	}
	return false
}

func composeHangulPair(first uint32, second uint32) bool {
	const (
		sBase  = 0xAC00
		lBase  = 0x1100
		vBase  = 0x1161
		tBase  = 0x11A7
		lCount = 19
		vCount = 21
		tCount = 28
		nCount = vCount * tCount
		sCount = lCount * nCount
	)
	isL := first >= lBase && first < lBase+lCount
	isV := second >= vBase && second < vBase+vCount
	if isL && isV {
		return true
	}
	isLV := first >= sBase && first < sBase+sCount && (first-sBase)%tCount == 0
	isT := second > tBase && second < tBase+tCount
	return isLV && isT
}

// hasCrossScriptMix reports whether the input resolves to two or more scripts
// and is not Highly Restrictive, the script question UTS #39 asks. Script
// resolution reads the vendored Scripts.txt and ScriptExtensions.txt through
// restriction.go rather than approximating a handful of scripts, so a mix such
// as Latin with Armenian or Latin with Arabic is seen.
func hasCrossScriptMix(input []uint32) bool {
	return len(stringScriptUnion(input)) >= 2 && !isHighlyRestrictive(input)
}

func isDefaultIgnorableCodepoint(cp uint32) bool {
	return cp == 0x00AD ||
		cp == 0x034F ||
		cp == 0x061C ||
		(cp >= 0x115F && cp <= 0x1160) ||
		(cp >= 0x17B4 && cp <= 0x17B5) ||
		(cp >= 0x180B && cp <= 0x180F) ||
		(cp >= 0x200B && cp <= 0x200F) ||
		(cp >= 0x202A && cp <= 0x202E) ||
		(cp >= 0x2060 && cp <= 0x206F) ||
		(cp >= 0xFE00 && cp <= 0xFE0F) ||
		cp == 0xFEFF ||
		(cp >= 0xFFF0 && cp <= 0xFFF8) ||
		(cp >= 0xE0000 && cp <= 0xE0FFF)
}

func isWhiteSpaceCodepoint(cp uint32) bool {
	return cp == 0x0009 ||
		cp == 0x000A ||
		cp == 0x000B ||
		cp == 0x000C ||
		cp == 0x000D ||
		cp == 0x0020 ||
		cp == 0x0085 ||
		cp == 0x00A0 ||
		cp == 0x1680 ||
		(cp >= 0x2000 && cp <= 0x200A) ||
		cp == 0x2028 ||
		cp == 0x2029 ||
		cp == 0x202F ||
		cp == 0x205F ||
		cp == 0x3000
}
