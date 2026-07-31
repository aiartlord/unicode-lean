package security

import "strings"

// This file extends the canonical decomposition support in homoglyph.go
// (toNFD, canonicalOrder, canonicalCombiningClass, decomposeHangulSyllable)
// with canonical composition (NFC) and full compatibility normalization
// (NFKD / NFKC), mirroring the reference Rust port
// ports/rust/src/security/identity/ucd.rs and the Lean specifications
// Unicode.Normalization.NFKD / NFKC. All tables are derived from the
// vendored UCD 17.0.0 data files embedded in homoglyph.go; no external
// dependency is introduced.

const (
	hangulSBase  uint32 = 0xAC00
	hangulLBase  uint32 = 0x1100
	hangulVBase  uint32 = 0x1161
	hangulTBase  uint32 = 0x11A7
	hangulLCount uint32 = 19
	hangulVCount uint32 = 21
	hangulTCount uint32 = 28
	hangulNCount uint32 = hangulVCount * hangulTCount
	hangulSCount uint32 = hangulLCount * hangulNCount
)

// compositionExclusionsSet parses CompositionExclusions.txt into the set of
// codepoints that must not be recomposed during canonical composition.
func compositionExclusionsSet(raw string) map[uint32]struct{} {
	out := make(map[uint32]struct{})
	for _, rawLine := range strings.Split(raw, "\n") {
		body, _, _ := strings.Cut(rawLine, "#")
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		if cp, ok := parseHexUint32(body); ok {
			out[cp] = struct{}{}
		}
	}
	return out
}

// compositionMap returns the canonical composition table: the inverse of the
// two-codepoint canonical decompositions, excluding singleton decompositions
// (len != 2), Composition-Exclusion codepoints, and pairs whose first element
// is a non-starter (CCC != 0). Built once and memoized.
func compositionMap() map[[2]uint32]uint32 {
	composeOnce.Do(func() {
		tables := normalizationTables()
		exclusions := compositionExclusionsSet(compositionExclusionsRaw)
		composeTable = make(map[[2]uint32]uint32)
		for cp, decomp := range tables.decomp {
			if len(decomp) != 2 {
				continue
			}
			if _, excluded := exclusions[cp]; excluded {
				continue
			}
			if canonicalCombiningClass(decomp[0]) != 0 {
				continue
			}
			composeTable[[2]uint32{decomp[0], decomp[1]}] = cp
		}
	})
	return composeTable
}

// composeHangulSyllable applies the algorithmic Hangul composition of UAX #15:
// L + V and LV + T. It returns the composed syllable and true when the pair
// composes, otherwise false.
func composeHangulSyllable(a uint32, b uint32) (uint32, bool) {
	// L + V
	if a >= hangulLBase && a < hangulLBase+hangulLCount &&
		b >= hangulVBase && b < hangulVBase+hangulVCount {
		lIndex := a - hangulLBase
		vIndex := b - hangulVBase
		return hangulSBase + (lIndex*hangulVCount+vIndex)*hangulTCount, true
	}
	// LV + T
	if a >= hangulSBase && a < hangulSBase+hangulSCount &&
		(a-hangulSBase)%hangulTCount == 0 &&
		b > hangulTBase && b < hangulTBase+hangulTCount {
		return a + (b - hangulTBase), true
	}
	return 0, false
}

// canonicalCompose performs the UAX #15 canonical composition pass over a
// sequence that is already in canonical (NFD/NFKD) order. It composes each
// combiner into the most recent eligible starter, honoring the blocked-pair
// rule based on canonical combining classes.
func canonicalCompose(seq []uint32) []uint32 {
	if len(seq) == 0 {
		return []uint32{}
	}
	table := compositionMap()
	out := make([]uint32, 0, len(seq))
	starterIndex := -1
	lastCCC := -1

	for _, cp := range seq {
		cpCCC := int(canonicalCombiningClass(cp))

		if starterIndex >= 0 {
			starter := out[starterIndex]
			composed, ok := composeHangulSyllable(starter, cp)
			if !ok {
				composed, ok = table[[2]uint32{starter, cp}]
			}
			// Blocked check (UAX #15 D115): lastCCC != 0 means a combiner is
			// buffered between the active starter and this candidate. A
			// non-starter candidate is blocked when that buffered combiner
			// has CCC >= its own; a starter candidate (cpCCC == 0) is blocked
			// outright by any buffered combiner.
			blocked := lastCCC != 0 && (cpCCC == 0 || lastCCC >= cpCCC)
			if !blocked && ok {
				out[starterIndex] = composed
				// lastCCC is unchanged: the combiner was absorbed into the
				// starter rather than emitted.
				continue
			}
		}

		out = append(out, cp)
		if cpCCC == 0 {
			starterIndex = len(out) - 1
			lastCCC = 0
		} else {
			lastCCC = cpCCC
		}
	}

	return out
}

// toNFC returns the Unicode Normalization Form C of the input: canonical
// decomposition, canonical ordering, then canonical composition.
func toNFC(input []uint32) []uint32 {
	return canonicalCompose(toNFD(input))
}

// appendCompatibilityDecomposition recursively expands cp by its compatibility
// mapping when present, otherwise its canonical mapping, otherwise Hangul
// algorithmic decomposition — the full decomposition of UAX #15 for NFKD.
func appendCompatibilityDecomposition(out *[]uint32, cp uint32) {
	if jamo, ok := decomposeHangulSyllable(cp); ok {
		*out = append(*out, jamo...)
		return
	}
	tables := normalizationTables()
	if decomposition, ok := tables.compat[cp]; ok {
		for _, part := range decomposition {
			appendCompatibilityDecomposition(out, part)
		}
		return
	}
	if decomposition, ok := tables.decomp[cp]; ok {
		for _, part := range decomposition {
			appendCompatibilityDecomposition(out, part)
		}
		return
	}
	*out = append(*out, cp)
}

// toNFKD returns the Unicode Normalization Form KD of the input: full
// compatibility decomposition followed by canonical ordering.
func toNFKD(input []uint32) []uint32 {
	out := make([]uint32, 0, len(input))
	for _, cp := range input {
		appendCompatibilityDecomposition(&out, cp)
	}
	canonicalOrder(out)
	return out
}

// toNFKC returns the Unicode Normalization Form KC of the input: NFKD
// followed by canonical composition.
func toNFKC(input []uint32) []uint32 {
	return canonicalCompose(toNFKD(input))
}
