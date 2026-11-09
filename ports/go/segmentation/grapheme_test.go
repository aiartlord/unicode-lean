package segmentation

// UAX #29 default extended grapheme cluster segmentation.
//
// Validates the port's cluster breaker against the official Unicode
// GraphemeBreakTest.txt (bundled under segmentation/testdata/ so the package
// stays self-contained), plus the shared vector fixture every other port
// replays and targeted cases for shapes a boundary mask does not state.
//
// The two corpus gates are the ones the line-break suite runs: agree with
// every published row, and separately account for the whole file so a row lost
// between the file and the fold fails rather than shrinking the denominator.
// The corpus reader, the mask comparison and the code point formatter are the
// line-break suite's, shared across the package's tests.

import (
	"os"
	"testing"
)

const graphemeVectorPath = "testdata/fixtures/segmentation/grapheme_vectors.json"

const graphemeCorpusPath = "testdata/GraphemeBreakTest.txt"

func readGraphemeVectors(t *testing.T) vectorFixture {
	t.Helper()
	payload, err := os.ReadFile(graphemeVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", graphemeVectorPath, err)
	}
	fixture, err := parseVectorFixture(payload, "uax29-grapheme-cluster")
	if err != nil {
		t.Fatalf("%s: %v", graphemeVectorPath, err)
	}
	return fixture
}

// What the corpus must be before it can judge anything: every row carries one
// more flag than code points, and the vendored copy carries every row the
// canonical file did.
func TestGraphemeCorpusIsWellFormed(t *testing.T) {
	rows := readCorpusFile(t, graphemeCorpusPath)
	ragged := 0
	for _, row := range rows {
		if len(row.expected) != len(row.codepoints)+1 {
			ragged++
		}
	}
	if ragged != 0 {
		t.Errorf("%d row(s) carry a wrong flag count", ragged)
	}
	if len(rows) != GraphemePublishedRowCount {
		t.Errorf("vendored corpus carries %d rows, the canonical file carried %d",
			len(rows), GraphemePublishedRowCount)
	}
}

// Hand-written vectors cannot establish a segmentation algorithm: its rules
// read context on both sides of a boundary and the answer depends on state
// carried from earlier in the sequence, so a wrong rule survives any vector a
// person would pick.
func TestGraphemeAgreesWithEveryPublishedRow(t *testing.T) {
	rows := readCorpusFile(t, graphemeCorpusPath)
	disagreements := 0
	for _, row := range rows {
		produced := GraphemeBreaks(row.codepoints)
		if !sameMask(produced, row.expected) {
			disagreements++
			if disagreements <= 5 {
				// A conformance red is only actionable if it says which row
				// disagreed and how.
				t.Errorf("line %d: cps=%s\n  published: %v\n  produced:  %v",
					row.line, formatCodepoints(row.codepoints), row.expected,
					produced)
			}
		}
	}
	if disagreements != 0 {
		t.Errorf("%d of %d published rows disagree", disagreements, len(rows))
	}
}

func TestGraphemeOutputCarriesOneFlagPerBoundary(t *testing.T) {
	for length := 0; length < 8; length++ {
		cps := make([]uint32, 0, length)
		for i := 0; i < length; i++ {
			cps = append(cps, uint32(0x61+i))
		}
		breaks := GraphemeBreaks(cps)
		if len(breaks) != length+1 {
			t.Errorf("length %d: got %d flags, want %d", length, len(breaks),
				length+1)
			continue
		}
		if !breaks[len(breaks)-1] {
			t.Errorf("length %d: GB2 must break at the end of text", length)
		}
		if length > 0 && !breaks[0] {
			t.Errorf("length %d: GB1 must break at the start of text", length)
		}
	}
}

// One case per UAX #29 rule, the same bytes every port replays, so no port can
// carry a weaker set of rule checks than another. The published corpus above is
// the authority; these name which rule each boundary exercises.
func TestTheSharedGraphemeVectorsReplay(t *testing.T) {
	fixture := readGraphemeVectors(t)
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Rule+" "+testCase.Name, func(t *testing.T) {
			got := GraphemeBreaks(testCase.Input)
			if !sameMask(got, testCase.Breaks) {
				t.Errorf("cps=%s\n  fixture:  %v\n  produced: %v",
					formatCodepoints(testCase.Input), testCase.Breaks, got)
			}
		})
	}
}

// Both gates count the same published file, so they cannot drift apart.
func TestTheGraphemeCorpusAndTheVectorsAgreeOnTheRowCount(t *testing.T) {
	if got := readGraphemeVectors(t).PublishedRowCount; got != GraphemePublishedRowCount {
		t.Errorf("the vectors carry %d published rows, the table carries %d",
			got, GraphemePublishedRowCount)
	}
}

// The cluster split is a shape the boundary masks do not state.
func TestGraphemeClusters(t *testing.T) {
	cases := []struct {
		name  string
		cps   []uint32
		runs  int
		first string
	}{
		// GB999 leaves each ASCII letter its own cluster.
		{"ascii letters", []uint32{0x61, 0x62, 0x63}, 3, "0061"},
		// GB9 keeps a combining mark with its base.
		{"a combining mark joins its base", []uint32{0x65, 0x0301}, 1, "0065 0301"},
		// GB3 keeps CR LF together.
		{"CR LF", []uint32{0x0D, 0x0A}, 1, "000D 000A"},
		// GB12 pairs regional indicators.
		{"one flag", []uint32{0x1F1EF, 0x1F1F5}, 1, "1F1EF 1F1F5"},
		// GB13 ends the pair, so a second flag opens a second cluster.
		{"two flags", []uint32{0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8}, 2,
			"1F1EF 1F1F5"},
		// GB11 holds an emoji ZWJ sequence together.
		{"an emoji ZWJ sequence",
			[]uint32{0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467}, 1,
			"1F468 200D 1F469 200D 1F467"},
		// A base with a mark, then a letter, is two clusters and the mark stays
		// with its base.
		{"a mark then a letter", []uint32{0x65, 0x0301, 0x61}, 2, "0065 0301"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			clusters := GraphemeClusters(testCase.cps)
			if len(clusters) != testCase.runs {
				t.Fatalf("got %d clusters, want %d", len(clusters),
					testCase.runs)
			}
			if got := formatCodepoints(clusters[0]); got != testCase.first {
				t.Errorf("first cluster is %s, want %s", got, testCase.first)
			}
		})
	}

	// An empty sequence has one boundary and no cluster.
	if got := len(GraphemeClusters(nil)); got != 0 {
		t.Errorf("an empty sequence yielded %d clusters", got)
	}
}

// The three properties the rules read, each through the table serving it.
func TestGraphemeProperties(t *testing.T) {
	gcbCases := []struct {
		name string
		cp   uint32
		want Gcb
	}{
		{"U+000D is CR", 0x000D, GcbCR},
		{"U+000A is LF", 0x000A, GcbLF},
		{"U+0301 is Extend", 0x0301, GcbExtend},
		{"U+200D is ZWJ", 0x200D, GcbZWJ},
		{"U+1F1EF is Regional_Indicator", 0x1F1EF, GcbRegionalIndicator},
		{"U+093E is SpacingMark", 0x093E, GcbSpacingMark},
		{"U+1100 is L", 0x1100, GcbL},
		// A code point no range covers takes the @missing Other default.
		{"U+0061 is Other", 0x0061, GcbOther},
	}
	for _, testCase := range gcbCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := GcbOf(testCase.cp); got != testCase.want {
				t.Errorf("GcbOf = %d, want %d", got, testCase.want)
			}
		})
	}

	// GB9c reads Indic_Conjunct_Break: U+094D DEVANAGARI SIGN VIRAMA is the
	// Linker and U+0915 DEVANAGARI LETTER KA a Consonant.
	incbCases := []struct {
		name string
		cp   uint32
		want Incb
	}{
		{"U+094D is the Indic conjunct Linker", 0x094D, IncbLinker},
		{"U+0915 is an Indic conjunct Consonant", 0x0915, IncbConsonant},
		{"U+0300 is an Indic conjunct Extend", 0x0300, IncbExtend},
		{"U+0061 carries no Indic_Conjunct_Break", 0x0061, IncbNone},
	}
	for _, testCase := range incbCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := IncbOf(testCase.cp); got != testCase.want {
				t.Errorf("IncbOf = %d, want %d", got, testCase.want)
			}
		})
	}

	// GB11 reads Extended_Pictographic from the table LB30b also reads.
	if !IsExtendedPictographic(0x1F466) {
		t.Error("U+1F466 BOY must be Extended_Pictographic")
	}
	if IsExtendedPictographic(0x0061) {
		t.Error("U+0061 LATIN SMALL LETTER A must not be Extended_Pictographic")
	}
}
