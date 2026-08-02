package security

import (
	_ "embed"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// emoji-zwj-integrity — detection of malformed / unsanctioned emoji
// ZWJ-sequence shapes per UTS #51 (the identity-layer detector I3).
//
// Direct port of Unicode.Security.Identity.EmojiZwjIntegrity, mirroring the
// verified Rust port security/identity/emoji_zwj_integrity.rs.
//
// Threat model. An adversary crafts an emoji-shaped codepoint sequence
// containing one or more U+200D ZERO WIDTH JOINERs but violating the sanctioned
// RGI ZWJ-sequence shape — by exceeding the RGI length cap, by joining a
// non-emoji codepoint, by emitting adjacent ZWJ pairs, or by overflowing the
// skin-tone count. Any non-RGI ZWJ-containing sequence is renderer-dependent,
// and that renderer divergence is the attack surface.
//
// Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
// emoji-zwj-sequences.txt, bundled in the port's own
// data/emoji-zwj-sequences.txt (never a host emoji library). The registered set
// gives both the exact-match membership test (ezwjIsRegisteredZwjSequence) and
// the ZWJ alphabet — every distinct codepoint occurring at any position of any
// registered sequence, excluding the joiner — which is the canonical "what may
// flank a ZWJ?" predicate.
//
// Algorithm (one pass over input).
//
//	Phase 1 — collect ZWJ positions and the skin-tone count.
//	Phase 2 — short-circuit Clear if there are no ZWJs and the skin-tone count
//	          is at most 1.
//	Phase 3 — a registered RGI sequence is always Clear.
//	Phase 4 — check sub-threats by priority:
//	            1. DoubleZWJ            ZWJ-ZWJ adjacency
//	            2. NonEmojiInjection    ZWJ adjacent to a non-emoji codepoint
//	            3. OverLength           sequence longer than the RGI cap
//	            4. SkinToneOverflow     skin-tone count >= 5
//	            5. UnregisteredSequence catch-all when ZWJs are present but the
//	                                    sequence is not registered.

// ─────────────────────────────────────────────────────────────────────
// §1 Constants
// ─────────────────────────────────────────────────────────────────────

// ezwjMaxRgiLength is the conservative cap on the length of a sanctioned RGI ZWJ
// sequence (maxRgiLength in the Lean spec). The longest current entry (a
// four-person family with skin tones) reaches ~13-14 codepoints; 16 is a safe
// upper bound.
const ezwjMaxRgiLength = 16

// ezwjZWJ is the ZERO WIDTH JOINER codepoint.
const ezwjZWJ uint32 = 0x200D

// ─────────────────────────────────────────────────────────────────────
// §2 Types
// ─────────────────────────────────────────────────────────────────────

// ezwjSubThreat is the sub-threat this detector fired, in the port's
// struct-with-tag idiom (mirroring aiwmSubThreat). tag is the human-facing
// classification tag; the remaining fields carry the sub-threat's data (only
// those relevant to the fired tag are meaningful). The tag values, in priority
// order, are: DoubleZWJ, NonEmojiInjection, OverLength, SkinToneOverflow,
// UnregisteredSequence.
type ezwjSubThreat struct {
	tag string
	// doubleZwjPositions — DoubleZWJ: the first ZWJ of each ZWJ-ZWJ pair.
	doubleZwjPositions []int
	// zwjPos — NonEmojiInjection: position of the offending ZWJ.
	zwjPos int
	// nonEmojiCp — NonEmojiInjection: the non-emoji codepoint that flanks it
	// (0 for an edge ZWJ).
	nonEmojiCp uint32
	// length — OverLength: the observed sequence length.
	length int
	// maxLength — OverLength: the RGI length cap that was exceeded.
	maxLength int
	// count — SkinToneOverflow: the observed skin-tone modifier count.
	count int
	// chainLen — UnregisteredSequence: the length of the unregistered ZWJ chain.
	chainLen int
}

// ezwjClassification is the top-level EmojiZwjIntegrity classification. When
// clear is true the input is well-formed or non-ZWJ; otherwise sub names the
// fired sub-threat, positions holds the implicated codepoint positions, and
// decoded is the decoded-byte projection (always empty here, kept for shape
// parity with the Lean Classification.hazard).
type ezwjClassification struct {
	clear     bool
	sub       ezwjSubThreat
	positions []int
	decoded   []uint8
}

// isClear reports whether the classification is Clear.
func (c ezwjClassification) isClear() bool {
	return c.clear
}

// tag is the human-facing tag for a hazard; the second result is false when
// clear.
func (c ezwjClassification) tag() (string, bool) {
	if c.clear {
		return "", false
	}
	return c.sub.tag, true
}

// ezwjVerdict is the structured output of ezwjDetect (mirrors the Lean Verdict).
type ezwjVerdict struct {
	input           []uint32
	classify        ezwjClassification
	zwjPositions    []int
	chainLength     int
	isRegisteredRgi bool
	skinToneCount   int
}

// ─────────────────────────────────────────────────────────────────────
// §3 RGI ZWJ-sequence data (bundled data/emoji-zwj-sequences.txt)
// ─────────────────────────────────────────────────────────────────────

//go:embed data/emoji-zwj-sequences.txt
var ezwjSequencesRaw string

var (
	ezwjSequencesOnce  sync.Once
	ezwjSequencesCache [][]uint32
	ezwjAlphabetOnce   sync.Once
	ezwjAlphabetCache  map[uint32]struct{}
)

// ezwjParseSequences parses the registered RGI ZWJ sequences from
// emoji-zwj-sequences.txt. Each non-comment row is
// "<cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ; <desc> # <cmt>"; the codepoint list
// is the field before the first ';'.
func ezwjParseSequences() [][]uint32 {
	out := [][]uint32{}
	for _, rawLine := range strings.Split(ezwjSequencesRaw, "\n") {
		body := rawLine
		if idx := strings.IndexByte(body, '#'); idx >= 0 {
			body = body[:idx]
		}
		stripped := strings.TrimSpace(body)
		if stripped == "" {
			continue
		}
		seqField := strings.SplitN(stripped, ";", 2)[0]
		seq := []uint32{}
		parsedOK := true
		for _, token := range strings.Fields(seqField) {
			cp, err := strconv.ParseUint(token, 16, 32)
			if err != nil {
				parsedOK = false
				break
			}
			seq = append(seq, uint32(cp))
		}
		if parsedOK && len(seq) > 0 {
			out = append(out, seq)
		}
	}
	return out
}

func ezwjSequences() [][]uint32 {
	ezwjSequencesOnce.Do(func() {
		ezwjSequencesCache = ezwjParseSequences()
	})
	return ezwjSequencesCache
}

// ezwjBuildAlphabet builds the ZWJ alphabet: every distinct codepoint occurring
// at any position of any registered RGI ZWJ sequence, excluding the joiner
// U+200D itself.
func ezwjBuildAlphabet() map[uint32]struct{} {
	set := map[uint32]struct{}{}
	for _, seq := range ezwjSequences() {
		for _, cp := range seq {
			if cp != ezwjZWJ {
				set[cp] = struct{}{}
			}
		}
	}
	return set
}

func ezwjAlphabet() map[uint32]struct{} {
	ezwjAlphabetOnce.Do(func() {
		ezwjAlphabetCache = ezwjBuildAlphabet()
	})
	return ezwjAlphabetCache
}

// ezwjIsRegisteredZwjSequence reports whether cps is exactly a registered RGI
// ZWJ sequence.
func ezwjIsRegisteredZwjSequence(cps []uint32) bool {
	for _, seq := range ezwjSequences() {
		if slices.Equal(seq, cps) {
			return true
		}
	}
	return false
}

// ezwjIsEmojiTarget reports whether cp appears at some position of a registered
// RGI ZWJ sequence (the canonical "what may flank a ZWJ?" predicate).
func ezwjIsEmojiTarget(cp uint32) bool {
	_, ok := ezwjAlphabet()[cp]
	return ok
}

// ─────────────────────────────────────────────────────────────────────
// §4 Core predicates
// ─────────────────────────────────────────────────────────────────────

// ezwjIsZwj reports whether cp is the ZWJ codepoint.
func ezwjIsZwj(cp uint32) bool {
	return cp == ezwjZWJ
}

// ezwjIsEmojiModifier reports whether cp is an emoji skin-tone modifier
// (U+1F3FB..U+1F3FF).
func ezwjIsEmojiModifier(cp uint32) bool {
	return cp >= 0x1F3FB && cp <= 0x1F3FF
}

// ezwjZwjPositions returns the positions of every ZWJ in input.
func ezwjZwjPositions(input []uint32) []int {
	out := []int{}
	for idx, cp := range input {
		if ezwjIsZwj(cp) {
			out = append(out, idx)
		}
	}
	return out
}

// ezwjSkinToneCount returns the count of skin-tone modifier codepoints.
func ezwjSkinToneCount(input []uint32) int {
	count := 0
	for _, cp := range input {
		if ezwjIsEmojiModifier(cp) {
			count++
		}
	}
	return count
}

// ezwjDoubleZwjPositions returns the positions of the first ZWJ in each ZWJ-ZWJ
// adjacent pair.
func ezwjDoubleZwjPositions(input []uint32) []int {
	out := []int{}
	for idx := 0; idx < len(input); idx++ {
		if idx+1 < len(input) {
			if ezwjIsZwj(input[idx]) && ezwjIsZwj(input[idx+1]) {
				out = append(out, idx)
			}
		}
	}
	return out
}

// ezwjFirstNonEmojiInjection returns the first ZWJ position where either
// neighbour is a non-emoji codepoint, as (zwjPos, offendingCp, found). A ZWJ at
// an input edge (no preceding or no following codepoint) is itself an
// injection-class hazard, reported with offending codepoint 0.
func ezwjFirstNonEmojiInjection(input []uint32) (int, uint32, bool) {
	for idx := 0; idx < len(input); idx++ {
		if !ezwjIsZwj(input[idx]) {
			continue
		}
		hasPrev := idx != 0
		hasNext := idx+1 < len(input)
		switch {
		case hasPrev && hasNext:
			prevCp := input[idx-1]
			nextCp := input[idx+1]
			if !ezwjIsEmojiTarget(prevCp) {
				return idx, prevCp, true
			} else if !ezwjIsEmojiTarget(nextCp) {
				return idx, nextCp, true
			}
		case !hasPrev:
			return idx, 0, true
		case hasPrev && !hasNext:
			return idx, 0, true
		}
	}
	return 0, 0, false
}

// ─────────────────────────────────────────────────────────────────────
// §5 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// ezwjDetect is the EmojiZwjIntegrity detection function.
func ezwjDetect(input []uint32) ezwjVerdict {
	zwjs := ezwjZwjPositions(input)
	stCount := ezwjSkinToneCount(input)
	isRgi := ezwjIsRegisteredZwjSequence(input)
	chainLen := 0
	if len(zwjs) != 0 {
		chainLen = len(input)
	}

	inputCopy := make([]uint32, len(input))
	copy(inputCopy, input)

	if len(zwjs) == 0 && stCount <= 1 {
		return ezwjVerdict{
			input:           inputCopy,
			classify:        ezwjClassification{clear: true, positions: []int{}, decoded: []uint8{}},
			zwjPositions:    []int{},
			chainLength:     0,
			isRegisteredRgi: isRgi,
			skinToneCount:   stCount,
		}
	}

	var classification ezwjClassification
	switch {
	case isRgi:
		// Phase 3: a registered RGI sequence is always clear.
		classification = ezwjClassification{clear: true, positions: []int{}, decoded: []uint8{}}
	default:
		// Phase 4.1: ZWJ-ZWJ adjacency.
		dzwj := ezwjDoubleZwjPositions(input)
		switch {
		case len(dzwj) != 0:
			classification = ezwjClassification{
				sub:       ezwjSubThreat{tag: "DoubleZWJ", doubleZwjPositions: dzwj},
				positions: dzwj,
				decoded:   []uint8{},
			}
		default:
			// Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
			zwjPos, offendCp, injected := ezwjFirstNonEmojiInjection(input)
			switch {
			case injected:
				classification = ezwjClassification{
					sub:       ezwjSubThreat{tag: "NonEmojiInjection", zwjPos: zwjPos, nonEmojiCp: offendCp},
					positions: []int{zwjPos},
					decoded:   []uint8{},
				}
			case len(input) > ezwjMaxRgiLength:
				// Phase 4.3: length cap.
				classification = ezwjClassification{
					sub:       ezwjSubThreat{tag: "OverLength", length: len(input), maxLength: ezwjMaxRgiLength},
					positions: []int{},
					decoded:   []uint8{},
				}
			case stCount >= 5:
				// Phase 4.4: skin-tone overflow.
				classification = ezwjClassification{
					sub:       ezwjSubThreat{tag: "SkinToneOverflow", count: stCount},
					positions: []int{},
					decoded:   []uint8{},
				}
			case len(zwjs) != 0:
				// Phase 4.5: catch-all for unregistered ZWJ sequences.
				classification = ezwjClassification{
					sub:       ezwjSubThreat{tag: "UnregisteredSequence", chainLen: len(input)},
					positions: zwjs,
					decoded:   []uint8{},
				}
			default:
				classification = ezwjClassification{clear: true, positions: []int{}, decoded: []uint8{}}
			}
		}
	}

	return ezwjVerdict{
		input:           inputCopy,
		classify:        classification,
		zwjPositions:    zwjs,
		chainLength:     chainLen,
		isRegisteredRgi: isRgi,
		skinToneCount:   stCount,
	}
}
