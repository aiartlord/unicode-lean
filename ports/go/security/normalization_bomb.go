package security

// Normalization-bomb detector (F1) — inputs whose NFD or NFKD expansion exceeds
// documented bounds, the classic normalization-expansion DoS. A small input that
// expands to a very large normalized form exhausts memory/CPU at the receiving
// layer (Arabic ligature U+FDFA -> 18 codepoints under NFKD, etc.). Mirrors
// Unicode.Security.Form.NormalizationBomb.
//
// Pure functional: compute NFD and NFKD lengths, then three priority-ordered
// checks — a per-codepoint blow-up scan, an overall NFKD ratio, an overall NFD
// ratio. Ratios are expressed in hundredths to avoid floats.

// maxNfkdPerCp is the maximum allowed NFKD expansion per single codepoint.
// Hangul <= 3, Greek extended forms 4, the largest non-FDFA Arabic ligature
// (FDFB) 8; anything greater than 8 is flagged.
const maxNfkdPerCp = 8

// nfdRatioPct is the overall-sequence NFD expansion ratio threshold, in
// hundredths (300 = 3x). Pure Hangul sits at exactly 300 and stays clear under
// strict >.
const nfdRatioPct = 300

// nfkdRatioPct is the overall-sequence NFKD expansion ratio threshold, in
// hundredths (400 = 4x).
const nfkdRatioPct = 400

// firstBlowupCp returns the first position whose single-codepoint NFKD expansion
// exceeds maxNfkdPerCp.
func firstBlowupCp(input []uint32) (int, bool) {
	for i, cp := range input {
		if len(toNFKD([]uint32{cp})) > maxNfkdPerCp {
			return i, true
		}
	}
	return 0, false
}

// nfdRatioPctOf reports the NFD ratio percentage (100 * nfdLen / inputLen); 0 on
// empty input.
func nfdRatioPctOf(input []uint32) int {
	if len(input) == 0 {
		return 0
	}
	return len(toNFD(input)) * 100 / len(input)
}

// nfkdRatioPctOf reports the NFKD ratio percentage (100 * nfkdLen / inputLen); 0
// on empty input.
func nfkdRatioPctOf(input []uint32) int {
	if len(input) == 0 {
		return 0
	}
	return len(toNFKD(input)) * 100 / len(input)
}

// normalizationBombDetect reports the normalization-expansion sub-threat and any
// implicated positions. Priority: per-codepoint blow-up, then overall NFKD
// ratio, then overall NFD ratio.
func normalizationBombDetect(input []uint32) (string, []int, bool) {
	if pos, ok := firstBlowupCp(input); ok {
		return "SingleCpBlowup", []int{pos}, true
	}
	if nfkdRatioPctOf(input) > nfkdRatioPct {
		return "NfkdHighExpansion", nil, true
	}
	if nfdRatioPctOf(input) > nfdRatioPct {
		return "NfdHighExpansion", nil, true
	}
	return "", nil, false
}
