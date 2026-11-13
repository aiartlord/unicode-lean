// ─────────────────────────────────────────────────────────────────────────────
//                              // contract-tests // segmentation-fixtures
// ─────────────────────────────────────────────────────────────────────────────
//
// The readers both segmentation suites judge their algorithm with: the shared
// vector fixture every port replays, and the published Unicode corpus that is
// the authority.
//
// Both corpora write the same alternating boundary markers and hex code points,
// and both fixtures carry the same schema, so the parsing lives here once and
// each suite names the file and the algorithm it wants. A reader per algorithm
// would be two chances for the two suites to drift on what a row means.

import Foundation
import UnicodeSecurity

/// The markers the published break corpora write at each boundary.
let breakMarker = "\u{00F7}"  // ÷ : break opportunity
let noBreakMarker = "\u{00D7}"  // × : no break

/// One case of the shared vector fixture: a rule, the sequence it exercises,
/// and the boundary mask the rule requires.
struct VectorCase {
    /// The UAX rule this case names.
    let rule: String
    /// What the case establishes, in words.
    let name: String
    /// The code point sequence.
    let input: [UInt32]
    /// One flag per boundary, so `input.count + 1` of them.
    let breaks: [Bool]
}

/// The shared vector fixture: one case per UAX rule, the same bytes in every
/// port, so each port's segmentation tests ask the same questions rather than a
/// per-port selection of them.
struct VectorFixture {
    /// How many rows the fixture's generator counted in the published corpus.
    let publishedRowCount: Int
    /// One case per rule.
    let cases: [VectorCase]
}

/// Decode a shared fixture and check it is the one the caller asked for.
///
/// A fixture of the wrong schema or the wrong algorithm would otherwise decode
/// into zero cases and pass every assertion over them.
func loadVectorFixture(
    _ name: String, algorithm: String
) throws -> VectorFixture {
    let document = try loadFixture(name)
    guard let schema = document["schema"] as? Int else {
        throw TestError.message("\(name): carries no schema")
    }
    try expect(schema == 1, "\(name): carries schema \(schema), expected 1")
    let carried = try string(document, "algorithm")
    try expect(
        carried == algorithm,
        "\(name): is for \(carried), expected \(algorithm)")
    guard let published = document["published_row_count"] as? Int else {
        throw TestError.message("\(name): carries no published_row_count")
    }
    var cases: [VectorCase] = []
    for entry in try array(document, "cases") {
        guard let breaks = entry["breaks"] as? [Bool] else {
            throw TestError.message("\(name): a case carries no breaks")
        }
        cases.append(VectorCase(
            rule: try string(entry, "rule"),
            name: try string(entry, "name"),
            input: try intArray(entry, "input").map { UInt32($0) },
            breaks: breaks))
    }
    try expect(!cases.isEmpty, "\(name): carries no cases")
    return VectorFixture(publishedRowCount: published, cases: cases)
}

/// One published case: where it sits in the file, its code points, and the
/// boundary mask the standard publishes for it.
struct CorpusRow {
    /// The 1-based line of the vendored corpus this row came from.
    let line: Int
    /// The code point sequence.
    let codepoints: [UInt32]
    /// One published flag per boundary.
    let expected: [Bool]
}

/// Split one data line into its code points and expected boundary mask.
///
/// A line is a sequence of alternating boundary markers and hex code points,
/// beginning and ending with a marker: `× 0061 ÷ 0062 ÷`. The markers form the
/// expected mask (÷ is true, × is false) of length `codepoints.count + 1`; the
/// hex tokens are the code points.
func parseCorpusLine(
    _ body: String, _ where_: String
) throws -> ([UInt32], [Bool]) {
    var codepoints: [UInt32] = []
    var mask: [Bool] = []
    for token in body.split(whereSeparator: { $0 == " " || $0 == "\t" }) {
        if token == breakMarker {
            mask.append(true)
        } else if token == noBreakMarker {
            mask.append(false)
        } else {
            guard let value = UInt32(token, radix: 16) else {
                throw TestError.message(
                    "\(where_): unparseable token \(token)")
            }
            codepoints.append(value)
        }
    }
    return (codepoints, mask)
}

/// Every data row of a vendored published corpus, read from the test bundle.
///
/// The resource is resolved by base name, which is how the bundle lays a
/// processed resource directory down flat.
func loadCorpus(_ name: String) throws -> [CorpusRow] {
    let resourceName = URL(fileURLWithPath: name).lastPathComponent
    guard let url = Bundle.module.url(
        forResource: resourceName, withExtension: nil) else {
        throw TestError.message("missing corpus: \(name)")
    }
    let payload = try Data(contentsOf: url)
    guard let text = String(data: payload, encoding: .utf8) else {
        throw TestError.message("corpus is not UTF-8: \(name)")
    }
    var rows: [CorpusRow] = []
    var line = 0
    for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
        line += 1
        var body = raw
        if let hash = body.firstIndex(of: "#") {
            body = body[body.startIndex..<hash]
        }
        let trimmed = body.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { continue }
        let (codepoints, expected) = try parseCorpusLine(
            trimmed, "\(name) line \(line)")
        rows.append(CorpusRow(
            line: line, codepoints: codepoints, expected: expected))
    }
    return rows
}

/// A code point sequence as the corpora write it: upper-case hex, space
/// separated.
func formatCodepoints(_ cps: [UInt32]) -> String {
    cps.map { String(format: "%04X", $0) }.joined(separator: " ")
}

/// Check a produced mask against a published one, naming the row and both masks
/// when they disagree. A conformance red is only actionable if it says which row
/// disagreed and how.
func expectMask(
    _ produced: [Bool], _ published: [Bool], _ label: String
) throws {
    if produced != published {
        throw TestError.message(
            "\(label):\n  published: \(published)\n  produced:  \(produced)")
    }
}

/// Both corpus gates every segmentation suite runs, over one vendored corpus:
/// every row carries one more flag than code points, and the vendored copy
/// carries every row the canonical file did.
///
/// Without the second check a row lost between the two would shrink the
/// denominator instead of failing.
func expectCorpusIsWellFormed(
    _ rows: [CorpusRow], _ publishedRowCount: Int, _ corpus: String
) throws {
    var ragged = 0
    for row in rows where row.expected.count != row.codepoints.count + 1 {
        ragged += 1
    }
    try expect(ragged == 0, "\(corpus): \(ragged) row(s) carry a wrong flag count")
    try expect(
        rows.count == publishedRowCount,
        "\(corpus): the vendored copy carries \(rows.count) rows, the "
            + "canonical file carried \(publishedRowCount)")
}
