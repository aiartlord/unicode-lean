package segmentation

// UAX #14 default line breaking.
//
// Validates the port's line breaker against the official Unicode
// LineBreakTest.txt (bundled under segmentation/testdata/ so the package stays
// self-contained), plus targeted vectors pinning the individual rules and the
// output shape the Lean lineBreaks_length theorem fixes. Every break
// opportunity (÷) and non-break (×) in the official file must be reproduced
// exactly.

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The markers the published break corpus writes at each boundary.
const (
	breakMarker   = "÷" // ÷ : break opportunity
	noBreakMarker = "×" // × : no break
)

const corpusPath = "testdata/LineBreakTest.txt"

// parseCorpusLine splits one data line into its code points and expected
// boundary mask.
//
// A line is a sequence of alternating boundary markers and hex code points,
// beginning and ending with a marker: e.g. "× 0061 ÷ 0062 ÷". The markers form
// the expected mask (÷ -> true, × -> false) of length len(codepoints)+1; the
// hex tokens are the code points.
func parseCorpusLine(body string) ([]uint32, []bool, error) {
	var codepoints []uint32
	var mask []bool
	for _, token := range strings.Fields(body) {
		switch token {
		case breakMarker:
			mask = append(mask, true)
		case noBreakMarker:
			mask = append(mask, false)
		default:
			value, err := strconv.ParseUint(token, 16, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("unparseable token %q: %w",
					token, err)
			}
			codepoints = append(codepoints, uint32(value))
		}
	}
	return codepoints, mask, nil
}

// corpusRow is one published case.
type corpusRow struct {
	line       int
	codepoints []uint32
	expected   []bool
}

// readCorpus reads every data row of the vendored corpus.
func readCorpus(t *testing.T) []corpusRow {
	t.Helper()
	handle, err := os.Open(corpusPath)
	if err != nil {
		t.Fatalf("open %s: %v", corpusPath, err)
	}
	defer func() {
		if err := handle.Close(); err != nil {
			t.Fatalf("close %s: %v", corpusPath, err)
		}
	}()

	var rows []corpusRow
	scanner := bufio.NewScanner(handle)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		body := scanner.Text()
		if idx := strings.IndexByte(body, '#'); idx >= 0 {
			body = body[:idx]
		}
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		codepoints, expected, err := parseCorpusLine(body)
		if err != nil {
			t.Fatalf("%s line %d: %v", corpusPath, line, err)
		}
		rows = append(rows, corpusRow{
			line:       line,
			codepoints: codepoints,
			expected:   expected,
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read %s: %v", corpusPath, err)
	}
	return rows
}

func sameMask(produced, published []bool) bool {
	if len(produced) != len(published) {
		return false
	}
	for i := range produced {
		if produced[i] != published[i] {
			return false
		}
	}
	return true
}

func formatCodepoints(cps []uint32) string {
	parts := make([]string, len(cps))
	for i, cp := range cps {
		parts[i] = fmt.Sprintf("%04X", cp)
	}
	return strings.Join(parts, " ")
}

// What the corpus must be before it can judge anything: every row carries one
// more flag than code points, and the vendored copy carries every row the
// canonical file did. Without the second check a row lost between the two would
// shrink the denominator instead of failing.
func TestCorpusIsWellFormed(t *testing.T) {
	rows := readCorpus(t)
	ragged := 0
	for _, row := range rows {
		if len(row.expected) != len(row.codepoints)+1 {
			ragged++
		}
	}
	if ragged != 0 {
		t.Errorf("%d row(s) carry a wrong flag count", ragged)
	}
	if len(rows) != PublishedRowCount {
		t.Errorf("vendored corpus carries %d rows, the canonical file carried %d",
			len(rows), PublishedRowCount)
	}
}

// Hand-written vectors cannot establish a segmentation algorithm: its rules
// read context on both sides of a boundary and the answer depends on state
// carried from earlier in the sequence, so a wrong rule survives any vector a
// person would pick. Agreeing with all of them is also the evidence the two
// departures declared at the package head needed — slice-bounded reads in
// place of the Lean's positional lits[i]!, and dropping its write-only
// spSinceNoSp snapshot field.
func TestAgreesWithEveryPublishedRow(t *testing.T) {
	rows := readCorpus(t)
	disagreements := 0
	for _, row := range rows {
		produced := LineBreaks(row.codepoints)
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

func TestOutputCarriesOneFlagPerBoundary(t *testing.T) {
	// The Lean lineBreaks_length theorem: len(cps) + 1 flags.
	for length := 0; length < 8; length++ {
		cps := make([]uint32, 0, length)
		for i := 0; i < length; i++ {
			cps = append(cps, uint32(0x61+i))
		}
		if got := len(LineBreaks(cps)); got != length+1 {
			t.Errorf("length %d: got %d flags, want %d", length, got, length+1)
		}
	}
}

func TestStartOfTextNeverBreaksAndEndAlwaysDoes(t *testing.T) {
	breaks := LineBreaks([]uint32{0x61, 0x62})
	if breaks[0] {
		t.Error("LB2: start of text must not break")
	}
	if !breaks[len(breaks)-1] {
		t.Error("LB3: end of text must break")
	}
}

func TestRuleVectors(t *testing.T) {
	cases := []struct {
		name string
		cps  []uint32
		want []bool
	}{
		{
			// LB28 keeps letters together.
			name: "a word is one run",
			cps:  []uint32{0x61, 0x62},
			want: []bool{false, false, true},
		},
		{
			// LB4: BK divides. U+000C FORM FEED is class BK.
			name: "a mandatory break character breaks after itself",
			cps:  []uint32{0x61, 0x000C, 0x62},
			want: []bool{false, false, true, true},
		},
		{
			// LB5: CR times LF, then a mandatory break after the pair.
			name: "carriage return line feed is not split",
			cps:  []uint32{0x0D, 0x0A, 0x61},
			want: []bool{false, false, true, true},
		},
		{
			// LB9: X CM behaves as X, so no break falls inside the pair.
			name: "a combining mark takes the class of its base",
			cps:  []uint32{0x61, 0x0301},
			want: []bool{false, false, true},
		},
		{
			// LB11: before WJ and after WJ.
			name: "a word joiner glues both sides",
			cps:  []uint32{0x61, 0x2060, 0x62},
			want: []bool{false, false, false, true},
		},
		{
			// LB15c: SP divides IS NU — "a .35" breaks before the period.
			name: "a space before a number opening period breaks",
			cps:  []uint32{0x61, 0x20, 0x2E, 0x33, 0x35},
			want: []bool{false, false, true, false, false, true},
		},
		{
			// LB30a: an even-length RI run takes no break inside a pair, and a
			// second pair may start a new line.
			name: "regional indicators pair off",
			cps:  []uint32{0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8},
			want: []bool{false, false, true, false, true},
		},
		{
			// LB30b: EB times EM.
			name: "an emoji modifier stays on its base",
			cps:  []uint32{0x1F466, 0x1F3FB},
			want: []bool{false, false, true},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := LineBreaks(testCase.cps); !sameMask(got, testCase.want) {
				t.Errorf("got %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestLineRuns(t *testing.T) {
	// LB18 breaks after a space, so the space stays with the word before it.
	runs := LineRuns([]uint32{0x61, 0x20, 0x62})
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want 2", len(runs))
	}
	if formatCodepoints(runs[0]) != "0061 0020" {
		t.Errorf("first run is %s", formatCodepoints(runs[0]))
	}
	if formatCodepoints(runs[1]) != "0062" {
		t.Errorf("second run is %s", formatCodepoints(runs[1]))
	}

	// LB25: "1,000" is one run across the SY separator.
	if got := len(LineRuns([]uint32{0x31, 0x2C, 0x30, 0x30, 0x30})); got != 1 {
		t.Errorf("a numeric chain split into %d runs", got)
	}
}

func TestLB1ResolvesTheTailorableClasses(t *testing.T) {
	cases := []struct {
		name     string
		cp       uint32
		raw      Lb
		resolved Lb
	}{
		// U+3041 HIRAGANA LETTER SMALL A is CJ, resolving to NS.
		{"U+3041 CJ", 0x3041, LbCJ, LbNS},
		// U+00A7 SECTION SIGN is AI, resolving to AL.
		{"U+00A7 AI", 0x00A7, LbAI, LbAL},
		// A surrogate code point is SG, resolving to AL.
		{"U+D800 SG", 0xD800, LbSG, LbAL},
		// U+05EB lies in the Hebrew block's unassigned gap, which no range
		// covers, so it takes the @missing XX default.
		{"U+05EB XX", 0x05EB, LbXX, LbAL},
		// U+0E31 THAI CHARACTER MAI HAN-AKAT is SA with General_Category Mn,
		// so LB1 reads it as CM.
		{"U+0E31 SA Mn", 0x0E31, LbSA, LbCM},
		// U+0E01 THAI CHARACTER KO KAI is SA with category Lo, so LB1 reads it
		// as AL.
		{"U+0E01 SA Lo", 0x0E01, LbSA, LbAL},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := RawClass(testCase.cp); got != testCase.raw {
				t.Errorf("RawClass = %d, want %d", got, testCase.raw)
			}
			if got := ResolvedClass(testCase.cp); got != testCase.resolved {
				t.Errorf("ResolvedClass = %d, want %d", got, testCase.resolved)
			}
		})
	}
}

func TestExtendedPictographic(t *testing.T) {
	// LB30b reads the property, and this package carries its own table because
	// there is no grapheme clustering here to borrow one from.
	if !IsExtendedPictographic(0x1F466) {
		t.Error("U+1F466 BOY must be Extended_Pictographic")
	}
	if IsExtendedPictographic(0x0061) {
		t.Error("U+0061 LATIN SMALL LETTER A must not be Extended_Pictographic")
	}
}
