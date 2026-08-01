package security

// NFC-idempotence-witness detector (F6) — inputs that are not already in NFC
// (or, failing that, not in NFKC), the silent normalization-drift class where a
// signer and verifier pick different canonical forms and their hashes diverge.
// Mirrors Unicode.Security.Form.NfcIdempotenceWitness.
//
// Compares input element-wise against toNFC(input) and toNFKC(input), reporting
// the first divergent position: a mismatch against NFC is NonNfcForm; a sequence
// already in NFC but not NFKC is NonNfkcCompatForm. NFC divergence takes
// priority over NFKC.

// firstDivergence returns the first index at which two sequences diverge (in
// element, or one ends), and true; when identical, (0, false).
func firstDivergence(a, b []uint32) (int, bool) {
	common := len(a)
	if len(b) < common {
		common = len(b)
	}
	for i := 0; i < common; i++ {
		if a[i] != b[i] {
			return i, true
		}
	}
	if len(a) != len(b) {
		return common, true
	}
	return 0, false
}

// nfcIdempotenceWitnessDetect reports an input that is not in canonical (NFC),
// or not in compatibility (NFKC), form, with the first divergent position. NFC
// divergence takes priority over NFKC.
func nfcIdempotenceWitnessDetect(input []uint32) (string, []int, bool) {
	nfc := toNFC(input)
	if pos, ok := firstDivergence(input, nfc); ok {
		return "NonNfcForm", []int{pos}, true
	}
	nfkc := toNFKC(input)
	if pos, ok := firstDivergence(input, nfkc); ok {
		return "NonNfkcCompatForm", []int{pos}, true
	}
	return "", nil, false
}
