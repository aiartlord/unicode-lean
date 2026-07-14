import Foundation
import UnicodeSecurity

@main
struct SecurityContractRunner {
    static func main() throws {
        try testPolicyContract()
        try testVerdictContract()
        try testUtf8DecodeContract()
        try testMultiEncodingDecodeContract()
        try testDetectorFixtures()
        print("clean: Swift contract tests pass")
    }

    private static func testPolicyContract() throws {
        let contract = try loadFixture("policy_contract.json")
        try expectEqual(contract["schema"] as? Int, 1, "policy schema")
        try expectEqual(contract["contract"] as? String, "unicode-security-policy-v0", "policy contract")
        for entry in try array(contract, "cases") {
            let verdict = scan(
                profile: try string(entry, "profile"),
                mode: try string(entry, "mode"),
                input: try intArray(entry, "input")
            )
            try expectEqual(verdict.action, try string(entry, "action"), try string(entry, "name"))
            for required in try stringArray(entry, "required_findings") {
                try expect(hasFinding(verdict.findings, required), "\(try string(entry, "name")): missing \(required)")
            }
        }
    }

    private static func testVerdictContract() throws {
        let contract = try loadFixture("verdict_contract.json")
        try expectEqual(contract["schema"] as? Int, 1, "verdict schema")
        try expectEqual(contract["contract"] as? String, "unicode-security-verdict-v0", "verdict contract")
        for entry in try array(contract, "cases") {
            let verdict = scan(
                profile: try string(entry, "profile"),
                mode: try string(entry, "mode"),
                input: try intArray(entry, "input")
            )
            let expected = try canonicalJson(try dictionary(entry, "verdict"))
            try expectEqual(verdictJson(verdict), expected, try string(entry, "name"))
        }
    }

    private static func testUtf8DecodeContract() throws {
        let contract = try loadFixture("decode_contract.json")
        try expectEqual(contract["schema"] as? Int, 1, "decode schema")
        try expectEqual(contract["contract"] as? String, "unicode-security-decode-v0", "decode contract")
        for entry in try array(contract, "cases") {
            let verdict = scanUtf8(
                profile: try string(entry, "profile"),
                mode: try string(entry, "mode"),
                input: try intArray(entry, "input_bytes")
            )
            try assertDecodeEntry(entry, verdict)
        }
    }

    private static func testMultiEncodingDecodeContract() throws {
        let contract = try loadFixture("decode_multiencoding_contract.json")
        try expectEqual(contract["schema"] as? Int, 1, "multi-encoding schema")
        try expectEqual(contract["contract"] as? String, "unicode-security-multiencoding-decode-v0", "multi-encoding contract")
        for entry in try array(contract, "cases") {
            let bytes = try intArray(entry, "input_bytes")
            let verdict: Verdict
            switch try string(entry, "encoding") {
            case "utf-8": verdict = scanUtf8(profile: try string(entry, "profile"), mode: try string(entry, "mode"), input: bytes)
            case "utf-16be": verdict = scanUtf16BE(profile: try string(entry, "profile"), mode: try string(entry, "mode"), input: bytes)
            case "utf-16le": verdict = scanUtf16LE(profile: try string(entry, "profile"), mode: try string(entry, "mode"), input: bytes)
            case "utf-32be": verdict = scanUtf32BE(profile: try string(entry, "profile"), mode: try string(entry, "mode"), input: bytes)
            case "utf-32le": verdict = scanUtf32LE(profile: try string(entry, "profile"), mode: try string(entry, "mode"), input: bytes)
            default: throw TestError.message("unknown encoding")
            }
            try assertDecodeEntry(entry, verdict)
        }
    }

    private static func testDetectorFixtures() throws {
        for fixture in [
            "detectors/tag_block_payload.json",
            "detectors/variation_selector_payload.json",
            "detectors/zero_width_payload.json",
            "detectors/bidi_control_balance.json",
            "detectors/noncharacter_control.json",
            "detectors/homoglyph_confusable.json",
            "detectors/mixed_script_admissibility.json",
        ] {
            let detector = try loadFixture(fixture)
            try expectEqual(detector["schema"] as? Int, 1, "\(fixture) schema")
            let family = try string(detector, "family")
            for entry in try array(detector, "cases") {
                let verdict = scan(profile: Profile.gatewayHeader, mode: Mode.observe, input: try intArray(entry, "input"))
                let requiredFindings = try stringArray(entry, "required_findings")
                for required in requiredFindings {
                    try expect(hasFinding(verdict.findings, required), "\(fixture):\(try string(entry, "name")): missing \(required)")
                }
                if requiredFindings.isEmpty {
                    try expect(!verdict.findings.contains { $0.family == family }, "\(fixture):\(try string(entry, "name"))")
                }
            }
        }
    }

    private static func assertDecodeEntry(_ entry: [String: Any], _ verdict: Verdict) throws {
        try expectEqual(verdict.action, try string(entry, "action"), try string(entry, "name"))
        try expectEqual(verdict.input, try intArray(entry, "input"), try string(entry, "name"))
        for required in try stringArray(entry, "required_findings") {
            try expect(hasFinding(verdict.findings, required), "\(try string(entry, "name")): missing \(required)")
        }
        for expected in try array(entry, "required_positions") {
            let code = try string(expected, "code")
            let positions = try intArray(expected, "positions")
            let finding = verdict.findings.first { $0.code == code }
            try expect(finding != nil, "\(try string(entry, "name")): missing positions for \(code)")
            try expectEqual(finding?.positions, positions, "\(try string(entry, "name")): \(code)")
        }
    }
}

private enum TestError: Error {
    case message(String)
}

private func loadFixture(_ name: String) throws -> [String: Any] {
    let resourceName = URL(fileURLWithPath: name).lastPathComponent
    guard let url = Bundle.module.url(forResource: resourceName, withExtension: nil) else {
        throw TestError.message("missing fixture: \(name)")
    }
    let data = try Data(contentsOf: url)
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw TestError.message("fixture is not an object: \(name)")
    }
    return object
}

private func array(_ object: [String: Any], _ key: String) throws -> [[String: Any]] {
    guard let value = object[key] as? [[String: Any]] else { throw TestError.message("missing array: \(key)") }
    return value
}

private func dictionary(_ object: [String: Any], _ key: String) throws -> [String: Any] {
    guard let value = object[key] as? [String: Any] else { throw TestError.message("missing object: \(key)") }
    return value
}

private func string(_ object: [String: Any], _ key: String) throws -> String {
    guard let value = object[key] as? String else { throw TestError.message("missing string: \(key)") }
    return value
}

private func intArray(_ object: [String: Any], _ key: String) throws -> [Int] {
    guard let value = object[key] as? [Int] else { throw TestError.message("missing int array: \(key)") }
    return value
}

private func stringArray(_ object: [String: Any], _ key: String) throws -> [String] {
    guard let value = object[key] as? [String] else { throw TestError.message("missing string array: \(key)") }
    return value
}

private func hasFinding(_ findings: [Finding], _ code: String) -> Bool {
    findings.contains { $0.code == code }
}

private func canonicalJson(_ object: [String: Any]) throws -> String {
    var out = "{"
    out += "\"action\":\"\(try string(object, "action"))\""
    out += ",\"profile\":\"\(try string(object, "profile"))\""
    out += ",\"mode\":\"\(try string(object, "mode"))\""
    out += ",\"input\":\(try intArray(object, "input").description.replacingOccurrences(of: " ", with: ""))"
    let findings = (object["findings"] as? [[String: Any]]) ?? []
    out += ",\"findings\":["
    out += try findings.map { finding in
        "{"
            + "\"code\":\"\(try string(finding, "code"))\","
            + "\"family\":\"\(try string(finding, "family"))\","
            + "\"severity\":\(finding["severity"] as? Int ?? 0),"
            + "\"positions\":\(try intArray(finding, "positions").description.replacingOccurrences(of: " ", with: "")),"
            + "\"sub_threat\":\"\(try string(finding, "sub_threat"))\","
            + "\"detail\":\"\(try string(finding, "detail"))\""
            + "}"
    }.joined(separator: ",")
    out += "]"
    if let normalized = object["normalized"] as? [Int] {
        out += ",\"normalized\":\(normalized.description.replacingOccurrences(of: " ", with: ""))"
    } else {
        out += ",\"normalized\":null"
    }
    out += "}"
    return out
}

private func expect(_ condition: Bool, _ message: String) throws {
    if !condition { throw TestError.message(message) }
}

private func expectEqual<T: Equatable>(_ actual: T, _ expected: T, _ message: String) throws {
    if actual != expected {
        throw TestError.message("\(message): actual=\(actual) expected=\(expected)")
    }
}
