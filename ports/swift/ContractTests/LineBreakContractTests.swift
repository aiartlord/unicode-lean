// ─────────────────────────────────────────────────────────────────────────────
//                                // contract-tests // line-break
// ─────────────────────────────────────────────────────────────────────────────
//
// UAX #14 default line breaking.
//
// Validates the port's line breaker against the official Unicode
// LineBreakTest.txt (bundled as a test resource so the port stays
// self-contained), plus targeted vectors pinning the individual rules and the
// output shape the Lean lineBreaks_length theorem fixes. Every break
// opportunity (÷) and non-break (×) in the official file must be reproduced
// exactly.

import UnicodeSecurity

/// The UAX #14 suite.
enum LineBreakContractTests {
    /// The shared vector fixture for this algorithm.
    private static let vectorPath =
        "segmentation/line_break_vectors.json"

    /// The vendored published corpus for this algorithm.
    private static let corpusPath = "LineBreakTest.txt"

    /// Run every check in this suite.
    static func run() throws {
        let rows = try loadCorpus(corpusPath)
        try testCorpusIsWellFormed(rows)
        try testAgreesWithEveryPublishedRow(rows)
        try testOutputCarriesOneFlagPerBoundary()
        try testStartOfTextNeverBreaksAndEndAlwaysDoes()
        try testTheSharedVectorsReplay()
        try testTheCorpusAndTheVectorsAgreeOnTheRowCount()
        try testLineRuns()
        try testLB1ResolvesTheTailorableClasses()
        try testExtendedPictographic()
    }

    /// What the corpus must be before it can judge anything.
    private static func testCorpusIsWellFormed(_ rows: [CorpusRow]) throws {
        try expectCorpusIsWellFormed(
            rows, lineBreakPublishedRowCount, corpusPath)
    }

    /// Hand-written vectors cannot establish a segmentation algorithm: its
    /// rules read context on both sides of a boundary and the answer depends on
    /// state carried from earlier in the sequence, so a wrong rule survives any
    /// vector a person would pick. Agreeing with all of them is also the
    /// evidence the two departures declared at the algorithm's head needed —
    /// bounded reads in place of the Lean's positional `lits[i]!`, and dropping
    /// its write-only `spSinceNoSp` snapshot field.
    private static func testAgreesWithEveryPublishedRow(
        _ rows: [CorpusRow]
    ) throws {
        var disagreements: [String] = []
        for row in rows {
            let produced = lineBreaks(row.codepoints)
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
            "\(count) of \(rows.count) published line-break rows disagree\n"
                + disagreements.prefix(5).joined(separator: "\n"))
    }

    /// The Lean lineBreaks_length theorem: `cps.count + 1` flags.
    private static func testOutputCarriesOneFlagPerBoundary() throws {
        for length in 0..<8 {
            let cps = (0..<length).map { UInt32(0x61 + $0) }
            try expectEqual(
                lineBreaks(cps).count, length + 1,
                "length \(length): flag count")
        }
    }

    private static func testStartOfTextNeverBreaksAndEndAlwaysDoes() throws {
        let breaks = lineBreaks([0x61, 0x62])
        try expect(!breaks[0], "LB2: start of text must not break")
        try expect(
            breaks[breaks.count - 1], "LB3: end of text must break")
    }

    /// One case per UAX #14 rule, the same bytes every port replays, so no port
    /// can carry a weaker set of rule checks than another. The published corpus
    /// above is the authority; these name which rule each boundary exercises.
    private static func testTheSharedVectorsReplay() throws {
        let fixture = try loadVectorFixture(
            vectorPath, algorithm: "uax14-line-break")
        for testCase in fixture.cases {
            try expectMask(
                lineBreaks(testCase.input), testCase.breaks,
                "\(testCase.rule) \(testCase.name): cps="
                    + formatCodepoints(testCase.input))
        }
    }

    /// Both gates count the same published file, so they cannot drift apart.
    private static func testTheCorpusAndTheVectorsAgreeOnTheRowCount() throws {
        let fixture = try loadVectorFixture(
            vectorPath, algorithm: "uax14-line-break")
        try expectEqual(
            fixture.publishedRowCount, lineBreakPublishedRowCount,
            "the line-break vectors and the table disagree on the row count")
    }

    private static func testLineRuns() throws {
        // LB18 breaks after a space, so the space stays with the word before
        // it.
        let runs = lineRuns([0x61, 0x20, 0x62])
        try expectEqual(runs.count, 2, "a space splits into two runs")
        try expectEqual(
            formatCodepoints(runs[0]), "0061 0020", "the first run")
        try expectEqual(formatCodepoints(runs[1]), "0062", "the second run")

        // LB25: "1,000" is one run across the SY separator.
        try expectEqual(
            lineRuns([0x31, 0x2C, 0x30, 0x30, 0x30]).count, 1,
            "a numeric chain is one run")
    }

    /// LB1 folds the tailorable classes into the working alphabet.
    private static func testLB1ResolvesTheTailorableClasses() throws {
        let cases: [(String, UInt32, LineBreakClass, LineBreakClass)] = [
            // U+3041 HIRAGANA LETTER SMALL A is CJ, resolving to NS.
            ("U+3041 CJ", 0x3041, .cj, .ns),
            // U+00A7 SECTION SIGN is AI, resolving to AL.
            ("U+00A7 AI", 0x00A7, .ai, .al),
            // A surrogate code point is SG, resolving to AL.
            ("U+D800 SG", 0xD800, .sg, .al),
            // U+05EB lies in the Hebrew block's unassigned gap, which no range
            // covers, so it takes the @missing XX default.
            ("U+05EB XX", 0x05EB, .xx, .al),
            // U+0E31 THAI CHARACTER MAI HAN-AKAT is SA with General_Category
            // Mn, so LB1 reads it as CM.
            ("U+0E31 SA Mn", 0x0E31, .sa, .cm),
            // U+0E01 THAI CHARACTER KO KAI is SA with category Lo, so LB1
            // reads it as AL.
            ("U+0E01 SA Lo", 0x0E01, .sa, .al),
        ]
        for (name, cp, raw, resolved) in cases {
            try expectEqual(rawLineBreakClass(cp), raw, "\(name): raw class")
            try expectEqual(
                resolvedLineBreakClass(cp), resolved, "\(name): LB1-resolved")
        }
    }

    /// LB30b reads the property from the one table in this module, which GB11
    /// reads as well.
    private static func testExtendedPictographic() throws {
        try expect(
            isExtendedPictographic(0x1F466),
            "U+1F466 BOY must be Extended_Pictographic")
        try expect(
            !isExtendedPictographic(0x0061),
            "U+0061 LATIN SMALL LETTER A must not be Extended_Pictographic")
    }
}
