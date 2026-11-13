// ─────────────────────────────────────────────────────────────────────────────
//                                  // contract-tests // grapheme
// ─────────────────────────────────────────────────────────────────────────────
//
// UAX #29 default extended grapheme cluster segmentation.
//
// Validates the port's cluster breaker against the official Unicode
// GraphemeBreakTest.txt (bundled as a test resource so the port stays
// self-contained), plus the shared vector fixture every other port replays and
// targeted cases for shapes a boundary mask does not state.
//
// The two corpus gates are the ones the line-break suite runs: agree with every
// published row, and separately account for the whole file so a row lost
// between the file and the fold fails rather than shrinking the denominator.
// The corpus reader, the mask comparison and the code point formatter are
// shared with that suite.

import UnicodeSecurity

/// The UAX #29 suite.
enum GraphemeContractTests {
    /// The shared vector fixture for this algorithm.
    private static let vectorPath = "segmentation/grapheme_vectors.json"

    /// The vendored published corpus for this algorithm.
    private static let corpusPath = "GraphemeBreakTest.txt"

    /// Run every check in this suite.
    static func run() throws {
        let rows = try loadCorpus(corpusPath)
        try testCorpusIsWellFormed(rows)
        try testAgreesWithEveryPublishedRow(rows)
        try testOutputCarriesOneFlagPerBoundary()
        try testTheSharedVectorsReplay()
        try testTheCorpusAndTheVectorsAgreeOnTheRowCount()
        try testGraphemeClusters()
        try testGraphemeProperties()
    }

    /// What the corpus must be before it can judge anything.
    private static func testCorpusIsWellFormed(_ rows: [CorpusRow]) throws {
        try expectCorpusIsWellFormed(
            rows, graphemePublishedRowCount, corpusPath)
    }

    /// Hand-written vectors cannot establish a segmentation algorithm: its
    /// rules read context on both sides of a boundary and the answer depends on
    /// state carried from earlier in the sequence, so a wrong rule survives any
    /// vector a person would pick.
    private static func testAgreesWithEveryPublishedRow(
        _ rows: [CorpusRow]
    ) throws {
        var disagreements: [String] = []
        for row in rows {
            let produced = graphemeBreaks(row.codepoints)
            if produced != row.expected {
                if disagreements.count < 5 {
                    disagreements.append(
                        "line \(row.line): cps="
                            + formatCodepoints(row.codepoints)
                            + "\n  published: \(row.expected)"
                            + "\n  produced:  \(produced)")
                } else {
                    disagreements.append("")
                }
            }
        }
        let count = disagreements.count
        try expect(
            count == 0,
            "\(count) of \(rows.count) published grapheme rows disagree\n"
                + disagreements.prefix(5).joined(separator: "\n"))
    }

    /// GB1 and GB2 make both ends of a non-empty sequence boundaries, and the
    /// output carries one flag per boundary.
    private static func testOutputCarriesOneFlagPerBoundary() throws {
        for length in 0..<8 {
            let cps = (0..<length).map { UInt32(0x61 + $0) }
            let breaks = graphemeBreaks(cps)
            try expectEqual(
                breaks.count, length + 1, "length \(length): flag count")
            try expect(
                breaks[breaks.count - 1],
                "length \(length): GB2 must break at the end of text")
            if length > 0 {
                try expect(
                    breaks[0],
                    "length \(length): GB1 must break at the start of text")
            }
        }
    }

    /// One case per UAX #29 rule, the same bytes every port replays, so no port
    /// can carry a weaker set of rule checks than another. The published corpus
    /// above is the authority; these name which rule each boundary exercises.
    private static func testTheSharedVectorsReplay() throws {
        let fixture = try loadVectorFixture(
            vectorPath, algorithm: "uax29-grapheme-cluster")
        for testCase in fixture.cases {
            try expectMask(
                graphemeBreaks(testCase.input), testCase.breaks,
                "\(testCase.rule) \(testCase.name): cps="
                    + formatCodepoints(testCase.input))
        }
    }

    /// Both gates count the same published file, so they cannot drift apart.
    private static func testTheCorpusAndTheVectorsAgreeOnTheRowCount() throws {
        let fixture = try loadVectorFixture(
            vectorPath, algorithm: "uax29-grapheme-cluster")
        try expectEqual(
            fixture.publishedRowCount, graphemePublishedRowCount,
            "the grapheme vectors and the table disagree on the row count")
    }

    /// The cluster split is a shape the boundary masks do not state.
    private static func testGraphemeClusters() throws {
        let cases: [(String, [UInt32], Int, String)] = [
            // GB999 leaves each ASCII letter its own cluster.
            ("ascii letters", [0x61, 0x62, 0x63], 3, "0061"),
            // GB9 keeps a combining mark with its base.
            ("a combining mark joins its base", [0x65, 0x0301], 1,
             "0065 0301"),
            // GB3 keeps CR LF together.
            ("CR LF", [0x0D, 0x0A], 1, "000D 000A"),
            // GB12 pairs regional indicators.
            ("one flag", [0x1F1EF, 0x1F1F5], 1, "1F1EF 1F1F5"),
            // GB13 ends the pair, so a second flag opens a second cluster.
            ("two flags", [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8], 2,
             "1F1EF 1F1F5"),
            // GB11 holds an emoji ZWJ sequence together.
            ("an emoji ZWJ sequence",
             [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467], 1,
             "1F468 200D 1F469 200D 1F467"),
            // A base with a mark, then a letter, is two clusters and the mark
            // stays with its base.
            ("a mark then a letter", [0x65, 0x0301, 0x61], 2, "0065 0301"),
        ]
        for (name, cps, runs, first) in cases {
            let clusters = graphemeClusters(cps)
            try expectEqual(clusters.count, runs, "\(name): cluster count")
            try expectEqual(
                formatCodepoints(clusters[0]), first,
                "\(name): the first cluster")
        }

        // An empty sequence has one boundary and no cluster.
        try expectEqual(
            graphemeClusters([]).count, 0,
            "an empty sequence yields no cluster")
    }

    /// The three properties the rules read, each through the table serving it.
    private static func testGraphemeProperties() throws {
        let gcbCases: [(String, UInt32, GraphemeClusterBreak)] = [
            ("U+000D is CR", 0x000D, .cr),
            ("U+000A is LF", 0x000A, .lf),
            ("U+0301 is Extend", 0x0301, .extend),
            ("U+200D is ZWJ", 0x200D, .zwj),
            ("U+1F1EF is Regional_Indicator", 0x1F1EF, .regionalIndicator),
            ("U+093E is SpacingMark", 0x093E, .spacingMark),
            ("U+1100 is L", 0x1100, .l),
            // A code point no range covers takes the @missing Other default.
            ("U+0061 is Other", 0x0061, .other),
        ]
        for (name, cp, want) in gcbCases {
            try expectEqual(graphemeClusterBreak(cp), want, name)
        }

        // GB9c reads Indic_Conjunct_Break: U+094D DEVANAGARI SIGN VIRAMA is
        // the Linker and U+0915 DEVANAGARI LETTER KA a Consonant.
        let incbCases: [(String, UInt32, IndicConjunctBreak)] = [
            ("U+094D is the Indic conjunct Linker", 0x094D, .linker),
            ("U+0915 is an Indic conjunct Consonant", 0x0915, .consonant),
            ("U+0300 is an Indic conjunct Extend", 0x0300, .extend),
            ("U+0061 carries no Indic_Conjunct_Break", 0x0061,
             IndicConjunctBreak.none),
        ]
        for (name, cp, want) in incbCases {
            try expectEqual(indicConjunctBreak(cp), want, name)
        }

        // GB11 reads Extended_Pictographic from the table LB30b also reads.
        try expect(
            isExtendedPictographic(0x1F466),
            "U+1F466 BOY must be Extended_Pictographic")
        try expect(
            !isExtendedPictographic(0x0061),
            "U+0061 LATIN SMALL LETTER A must not be Extended_Pictographic")
    }
}
