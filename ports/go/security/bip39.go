package security

import (
	"embed"
	"strings"
	"sync"
)

// bip39-canonical: BIP-39 mnemonic canonicalisation + wordlist checks, mirroring
// Unicode.Security.Crypto.Bip39Canonical. Canonical form is NFKD ->
// toLower(default) -> collapse BIP-39 whitespace -> trim; detect runs six probes
// in priority order over the input and its canonical words.

//go:embed data/bip39
var bip39FS embed.FS

// Declaration order matches Unicode.Generated.BIP39.allLanguages (English
// first, so a multi-wordlist-covered input resolves to English).
var bip39Languages = []string{
	"english", "japanese", "korean", "spanish",
	"chinese_simplified", "chinese_traditional",
	"french", "italian", "czech", "portuguese",
}

var (
	bip39WordlistOnce  sync.Once
	bip39WordlistCache map[string]map[string]struct{}
)

func bip39CpsToKey(cps []uint32) string {
	runes := make([]rune, len(cps))
	for i, cp := range cps {
		runes[i] = rune(cp)
	}
	return string(runes)
}

func bip39Wordlists() map[string]map[string]struct{} {
	bip39WordlistOnce.Do(func() {
		bip39WordlistCache = map[string]map[string]struct{}{}
		for _, lang := range bip39Languages {
			data, err := bip39FS.ReadFile("data/bip39/" + lang + ".txt")
			if err != nil {
				continue
			}
			set := map[string]struct{}{}
			for _, line := range strings.Split(string(data), "\n") {
				if line != "" {
					set[line] = struct{}{}
				}
			}
			bip39WordlistCache[lang] = set
		}
	})
	return bip39WordlistCache
}

func bip39WordlistsContaining(word []uint32) []string {
	out := []string{}
	key := bip39CpsToKey(word)
	for _, lang := range bip39Languages {
		if set, ok := bip39Wordlists()[lang]; ok {
			if _, found := set[key]; found {
				out = append(out, lang)
			}
		}
	}
	return out
}

func bip39UniqueLanguage(words [][]uint32) (string, bool) {
	for _, lang := range bip39Languages {
		set, ok := bip39Wordlists()[lang]
		if !ok {
			continue
		}
		all := true
		for _, w := range words {
			if _, found := set[bip39CpsToKey(w)]; !found {
				all = false
				break
			}
		}
		if all {
			return lang, true
		}
	}
	return "", false
}

func isBip39Whitespace(cp uint32) bool {
	return cp == 0x0020 || cp == 0x3000
}

func collapseBip39Whitespace(cps []uint32) []uint32 {
	out := []uint32{}
	inWs := false
	for _, cp := range cps {
		if isBip39Whitespace(cp) {
			if !inWs {
				out = append(out, 0x0020)
			}
			inWs = true
		} else {
			out = append(out, cp)
			inWs = false
		}
	}
	return out
}

func trimBip39(cps []uint32) []uint32 {
	start := 0
	end := len(cps)
	for start < end && cps[start] == 0x0020 {
		start++
	}
	for end > start && cps[end-1] == 0x0020 {
		end--
	}
	return cps[start:end]
}

func bip39CanonicalForm(cps []uint32) []uint32 {
	nfkd := toNFKD(cps)
	lowered := toLower(localeDefault, nfkd)
	collapsed := collapseBip39Whitespace(lowered)
	return trimBip39(collapsed)
}

func bip39SplitWords(cps []uint32) [][]uint32 {
	words := [][]uint32{}
	current := []uint32{}
	for _, cp := range cps {
		if cp == 0x0020 {
			if len(current) > 0 {
				words = append(words, current)
				current = []uint32{}
			}
		} else {
			current = append(current, cp)
		}
	}
	if len(current) > 0 {
		words = append(words, current)
	}
	return words
}

func bip39CountTrailingWhitespace(cps []uint32) int {
	count := 0
	for i := len(cps) - 1; i >= 0; i-- {
		if isBip39Whitespace(cps[i]) {
			count++
		} else {
			break
		}
	}
	return count
}

func bip39FirstUppercasePos(cps []uint32) (int, bool) {
	for i, cp := range cps {
		if cp >= 0x41 && cp <= 0x5A {
			return i, true
		}
	}
	return 0, false
}

func bip39FirstWhitespaceRunPos(cps []uint32) (int, bool) {
	for i, cp := range cps {
		if isBip39Whitespace(cp) {
			if i == 0 {
				return i, true
			}
			if i+1 < len(cps) && isBip39Whitespace(cps[i+1]) {
				return i, true
			}
		}
	}
	return 0, false
}

func bip39FirstArrayDivergence(a, b []uint32) (int, bool) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i, true
		}
	}
	if len(a) != len(b) {
		return n, true
	}
	return 0, false
}

func bip39EqualCps(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type bip39Detection struct {
	sub       string
	positions []int
	language  string
	canonical []uint32
	wordCount int
}

// bip39CanonicalDetect runs the six probes in priority order (first hit wins),
// mirroring Bip39Canonical.detect.
func bip39CanonicalDetect(input []uint32) bip39Detection {
	canonical := bip39CanonicalForm(input)
	words := bip39SplitWords(canonical)
	wordCount := len(words)

	if trailing := bip39CountTrailingWhitespace(input); trailing > 0 {
		return bip39Detection{sub: "TrailingWhitespace", positions: []int{len(input) - trailing}, canonical: canonical, wordCount: wordCount}
	}
	if p, ok := bip39FirstUppercasePos(input); ok {
		return bip39Detection{sub: "MixedCase", positions: []int{p}, canonical: canonical, wordCount: wordCount}
	}
	if p, ok := bip39FirstWhitespaceRunPos(input); ok {
		return bip39Detection{sub: "WhitespaceAnomaly", positions: []int{p}, canonical: canonical, wordCount: wordCount}
	}
	nfkd := toNFKD(input)
	if !bip39EqualCps(input, nfkd) {
		if p, ok := bip39FirstArrayDivergence(input, nfkd); ok {
			return bip39Detection{sub: "NonNFKD", positions: []int{p}, canonical: canonical, wordCount: wordCount}
		}
	}
	for idx, w := range words {
		if len(bip39WordlistsContaining(w)) == 0 {
			return bip39Detection{sub: "WordlistMismatch", positions: []int{idx}, canonical: canonical, wordCount: wordCount}
		}
	}
	if lang, ok := bip39UniqueLanguage(words); ok {
		return bip39Detection{sub: "", positions: []int{}, language: lang, canonical: canonical, wordCount: wordCount}
	}
	return bip39Detection{sub: "LanguageAmbiguous", positions: []int{}, canonical: canonical, wordCount: wordCount}
}
