package security

import (
	"strconv"
	"strings"
	"sync"
)

// skin-tone-variation-forgery — skin-tone modifier and variation-selector abuse
// on emoji bases per UTS #51 (the identity-layer detector).
//
// Direct port of Unicode.Security.Identity.SkinToneVariationForgery, mirroring
// the verified Rust reference security/identity/skin_tone_variation_forgery.rs.
//
// Threat model. Tier A₁. An adversary places a skin-tone modifier on a codepoint
// that does NOT bear Emoji_Modifier_Base, stacks multiple skin tones on one base,
// or forces a text-style render on an emoji-default codepoint via U+FE0E (VS15) —
// sometimes to hide a payload-bearing glyph in plain sight.
//
// Distinct from VariationSelectorPayload (pair-aligned VS runs that decode to
// bytes): this catches the orthogonal case of semantic VS / skin-tone misuse on a
// single base. Both can fire on the same input; SourceDisplayDivergence
// aggregates.
//
// It reuses the port's own emoji property tables (the bundled emoji-data.txt via
// the aiwmEmojiDataRaw embed shared across this package) and the port's own
// skin-tone predicate (ezwjIsEmojiModifier); never a host emoji library.
//
// Sub-threats (priority order):
//
//	1. StackedSkinTones      a base immediately followed by >= 2 skin-tone modifiers.
//	2. InvalidSkinToneTarget a skin-tone modifier on a non-Emoji_Modifier_Base.
//	3. ForcedTextStyle       U+FE0E on an Emoji_Presentation codepoint.

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

// stvfSubThreat is the sub-threat this detector fired, in the port's
// struct-with-tag idiom (mirroring aiwmSubThreat / ezwjSubThreat). tag is the
// human-facing classification tag; the remaining fields carry the sub-threat's
// data (only those relevant to the fired tag are meaningful). The tag values, in
// priority order, are: StackedSkinTones, InvalidSkinToneTarget, ForcedTextStyle.
type stvfSubThreat struct {
	tag string
	// basePos — the position of the base codepoint (all sub-threats).
	basePos int
	// modifiers — StackedSkinTones: the first two stacked skin-tone modifiers.
	modifiers []uint32
	// baseCp — InvalidSkinToneTarget / ForcedTextStyle: the base codepoint.
	baseCp uint32
	// modifierCp — InvalidSkinToneTarget: the skin-tone modifier codepoint.
	modifierCp uint32
}

// stvfClassification is the top-level SkinToneVariationForgery classification.
// When clear is true no abuse pattern fired; otherwise sub names the fired
// sub-threat, positions holds the implicated codepoint positions, and decoded is
// the decoded-byte projection (always empty here, kept for shape parity with the
// Lean Classification.hazard).
type stvfClassification struct {
	clear     bool
	sub       stvfSubThreat
	positions []int
	decoded   []uint8
}

// isClear reports whether the classification is Clear.
func (c stvfClassification) isClear() bool {
	return c.clear
}

// tag is the human-facing tag for a hazard; the second result is false when
// clear.
func (c stvfClassification) tag() (string, bool) {
	if c.clear {
		return "", false
	}
	return c.sub.tag, true
}

// posns returns the implicated positions (empty when clear).
func (c stvfClassification) posns() []int {
	if c.clear {
		return []int{}
	}
	return c.positions
}

// stvfVerdict is the structured output of stvfDetect (mirrors the Lean Verdict).
type stvfVerdict struct {
	input                    []uint32
	classify                 stvfClassification
	skinToneCount            int
	variationSelector15Count int
	variationSelector16Count int
}

// ─────────────────────────────────────────────────────────────────────
// §2 Core predicates (reuse the port's own emoji tables)
// ─────────────────────────────────────────────────────────────────────

// stvfParseEmojiProperty parses the closed intervals for a single emoji property
// from the bundled emoji-data.txt (reusing this package's aiwmEmojiDataRaw
// embed). Each non-comment row is "<range> ; <property> # <comment>"; we keep
// only rows whose property field matches property exactly. Mirrors
// aiwmParseEmojiRanges, generalised over the target property.
func stvfParseEmojiProperty(property string) []aiwmRange {
	out := []aiwmRange{}
	for _, rawLine := range strings.Split(aiwmEmojiDataRaw, "\n") {
		body := rawLine
		if idx := strings.IndexByte(body, '#'); idx >= 0 {
			body = body[:idx]
		}
		stripped := strings.TrimSpace(body)
		if stripped == "" {
			continue
		}
		fields := strings.Split(stripped, ";")
		if len(fields) < 2 {
			continue
		}
		if strings.TrimSpace(fields[1]) != property {
			continue
		}
		rangeField := strings.TrimSpace(fields[0])
		if lohi := strings.SplitN(rangeField, "..", 2); len(lohi) == 2 {
			lo, errLo := strconv.ParseUint(strings.TrimSpace(lohi[0]), 16, 32)
			hi, errHi := strconv.ParseUint(strings.TrimSpace(lohi[1]), 16, 32)
			if errLo != nil || errHi != nil {
				continue
			}
			out = append(out, aiwmRange{lo: uint32(lo), hi: uint32(hi)})
		} else {
			single, err := strconv.ParseUint(rangeField, 16, 32)
			if err != nil {
				continue
			}
			out = append(out, aiwmRange{lo: uint32(single), hi: uint32(single)})
		}
	}
	return out
}

var (
	stvfModifierBaseOnce  sync.Once
	stvfModifierBaseCache []aiwmRange
	stvfPresentationOnce  sync.Once
	stvfPresentationCache []aiwmRange
)

func stvfEmojiModifierBaseRanges() []aiwmRange {
	stvfModifierBaseOnce.Do(func() {
		stvfModifierBaseCache = stvfParseEmojiProperty("Emoji_Modifier_Base")
	})
	return stvfModifierBaseCache
}

func stvfEmojiPresentationRanges() []aiwmRange {
	stvfPresentationOnce.Do(func() {
		stvfPresentationCache = stvfParseEmojiProperty("Emoji_Presentation")
	})
	return stvfPresentationCache
}

// stvfIsSkinTone reports whether cp is an emoji skin-tone modifier. Reuses the
// port's own predicate (ezwjIsEmojiModifier, the U+1F3FB..U+1F3FF set from
// EmojiZwjIntegrity).
func stvfIsSkinTone(cp uint32) bool {
	return ezwjIsEmojiModifier(cp)
}

// stvfIsSkinToneBase reports whether cp has Emoji_Modifier_Base per
// emoji-data.txt.
func stvfIsSkinToneBase(cp uint32) bool {
	for _, r := range stvfEmojiModifierBaseRanges() {
		if r.lo <= cp && cp <= r.hi {
			return true
		}
	}
	return false
}

// stvfIsEmojiPresentation reports whether cp has Emoji_Presentation per
// emoji-data.txt.
func stvfIsEmojiPresentation(cp uint32) bool {
	for _, r := range stvfEmojiPresentationRanges() {
		if r.lo <= cp && cp <= r.hi {
			return true
		}
	}
	return false
}

// stvfIsVS15 reports whether cp is U+FE0E (VS15, text-style variation selector).
func stvfIsVS15(cp uint32) bool {
	return cp == 0xFE0E
}

// stvfIsVS16 reports whether cp is U+FE0F (VS16, emoji-style variation selector).
func stvfIsVS16(cp uint32) bool {
	return cp == 0xFE0F
}

// ─────────────────────────────────────────────────────────────────────
// §3 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

// stvfFirstStackedSkinTones finds the first position p whose next two codepoints
// are both skin-tone modifiers, returning (basePos, [mod1, mod2], true).
func stvfFirstStackedSkinTones(input []uint32) (int, []uint32, bool) {
	for i := 0; i < len(input); i++ {
		if i+2 < len(input) && stvfIsSkinTone(input[i+1]) && stvfIsSkinTone(input[i+2]) {
			return i, []uint32{input[i+1], input[i+2]}, true
		}
	}
	return 0, nil, false
}

// stvfFirstInvalidSkinToneTarget finds the first skin-tone modifier whose
// preceding codepoint is NOT Emoji_Modifier_Base, returning
// (basePos, baseCp, modifierCp, true).
func stvfFirstInvalidSkinToneTarget(input []uint32) (int, uint32, uint32, bool) {
	for i := 0; i < len(input); i++ {
		if i+1 < len(input) && stvfIsSkinTone(input[i+1]) && !stvfIsSkinToneBase(input[i]) {
			return i, input[i], input[i+1], true
		}
	}
	return 0, 0, 0, false
}

// stvfFirstForcedTextStyle finds the first U+FE0E whose preceding codepoint has
// Emoji_Presentation, returning (basePos, baseCp, true).
func stvfFirstForcedTextStyle(input []uint32) (int, uint32, bool) {
	for i := 0; i < len(input); i++ {
		if i+1 < len(input) && stvfIsVS15(input[i+1]) && stvfIsEmojiPresentation(input[i]) {
			return i, input[i], true
		}
	}
	return 0, 0, false
}

func stvfSkinToneCount(input []uint32) int {
	count := 0
	for _, cp := range input {
		if stvfIsSkinTone(cp) {
			count++
		}
	}
	return count
}

func stvfVS15Count(input []uint32) int {
	count := 0
	for _, cp := range input {
		if stvfIsVS15(cp) {
			count++
		}
	}
	return count
}

func stvfVS16Count(input []uint32) int {
	count := 0
	for _, cp := range input {
		if stvfIsVS16(cp) {
			count++
		}
	}
	return count
}

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// stvfDetect is the SkinToneVariationForgery detection function. Sub-threats are
// dispatched in priority order; when none fires the classification is Clear.
func stvfDetect(input []uint32) stvfVerdict {
	stc := stvfSkinToneCount(input)
	v15 := stvfVS15Count(input)
	v16 := stvfVS16Count(input)

	var classification stvfClassification
	if basePos, modifiers, ok := stvfFirstStackedSkinTones(input); ok {
		// Priority 1: a base followed by two stacked skin tones.
		positions := make([]int, len(modifiers))
		for i := range modifiers {
			positions[i] = basePos + 1 + i
		}
		classification = stvfClassification{
			clear: false,
			sub: stvfSubThreat{
				tag:       "StackedSkinTones",
				basePos:   basePos,
				modifiers: modifiers,
			},
			positions: positions,
			decoded:   []uint8{},
		}
	} else if basePos, baseCp, modifierCp, ok := stvfFirstInvalidSkinToneTarget(input); ok {
		// Priority 2: a skin tone on a non-modifier-base.
		classification = stvfClassification{
			clear: false,
			sub: stvfSubThreat{
				tag:        "InvalidSkinToneTarget",
				basePos:    basePos,
				baseCp:     baseCp,
				modifierCp: modifierCp,
			},
			positions: []int{basePos + 1},
			decoded:   []uint8{},
		}
	} else if basePos, baseCp, ok := stvfFirstForcedTextStyle(input); ok {
		// Priority 3: VS15 forcing text style on an emoji-presentation cp.
		classification = stvfClassification{
			clear: false,
			sub: stvfSubThreat{
				tag:     "ForcedTextStyle",
				basePos: basePos,
				baseCp:  baseCp,
			},
			positions: []int{basePos + 1},
			decoded:   []uint8{},
		}
	} else {
		// No abuse pattern fired: the input is clear.
		classification = stvfClassification{clear: true, positions: []int{}, decoded: []uint8{}}
	}

	return stvfVerdict{
		input:                    append([]uint32{}, input...),
		classify:                 classification,
		skinToneCount:            stc,
		variationSelector15Count: v15,
		variationSelector16Count: v16,
	}
}
