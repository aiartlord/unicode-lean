import Foundation

public enum Action {
    public static let allow = "allow"
    public static let reject = "reject"
    public static let quarantine = "quarantine"
    public static let rewrite = "rewrite"
    public static let observe = "observe"
}

public enum Mode {
    public static let observe = "observe"
    public static let warn = "warn"
    public static let enforce = "enforce"
    public static let strict = "strict"
}

public enum Profile {
    public static let gatewayHeader = "gateway-header"
    public static let domainName = "domain-name"
    public static let dnsLabel = "dns-label"
    public static let url = "url"
    public static let username = "username"
    public static let displayName = "display-name"
    public static let chatMessage = "chat-message"
    public static let sourceCode = "source-code"
    public static let opaqueSecret = "opaque-secret"
    public static let binaryBlob = "binary-blob"
}

public enum Family {
    public static let malformedUtf8 = "malformed-utf8"
    public static let malformedUtf16 = "malformed-utf16"
    public static let malformedUtf32 = "malformed-utf32"
    public static let tagBlockPayload = "tag-block-payload"
    public static let variationSelectorPayload = "variation-selector-payload"
    public static let zeroWidthPayload = "zero-width-payload"
    public static let bidiControlBalance = "bidi-control-balance"
    public static let noncharacterControl = "noncharacter-control"
    public static let homoglyphConfusable = "homoglyph-confusable"
    public static let mixedScriptAdmissibility = "mixed-script-admissibility"
}

public struct Finding: Equatable {
    public let code: String
    public let family: String
    public let severity: Int
    public let positions: [Int]
    public let subThreat: String
    public let detail: String
}

public struct Verdict: Equatable {
    public let action: String
    public let profile: String
    public let mode: String
    public let input: [Int]
    public let findings: [Finding]
    public let normalized: [Int]?
}

private enum PolicyLevel { case restrictive, moderate, minimal }
private enum ByteOrder { case big, little }
private struct ProfilePolicy { let level: PolicyLevel; let quarantine: Bool }
private struct DecodeFailure { let subThreat: String; let offset: Int }
private struct DecodeResult { let codepoints: [Int]; let failure: DecodeFailure? }
private struct Utf8State { let inSequence: Bool; let remaining: Int; let accum: Int; let minCp: Int }
private struct Utf8Step { let state: Utf8State; let emitted: Int; let kind: String; let rejected: Bool }

private var confusablesMapCache: [Int: [Int]]?
private var attackTargetsCache: [String]?
private var legalVariationPairsCache: Set<String>?

public func scan(profile: String, mode: String, input: [Int]) -> Verdict {
    let codepoints = input.map(ensureCodepoint)
    let findings = detect(codepoints)
    return Verdict(
        action: decide(profile: profile, mode: mode, findings: findings),
        profile: profile,
        mode: mode,
        input: codepoints,
        findings: findings,
        normalized: nil
    )
}

public func scanUtf8(profile: String, mode: String, input: [UInt8]) -> Verdict {
    if let failure = firstInvalidUtf8(input) {
        return malformedDecodeVerdict(profile: profile, mode: mode, family: Family.malformedUtf8, subThreat: failure.subThreat, offset: failure.offset)
    }
    return scan(profile: profile, mode: mode, input: decodeUtf8ToCodepoints(input))
}

public func scanUtf8(profile: String, mode: String, input: [Int]) -> Verdict {
    scanUtf8(profile: profile, mode: mode, input: input.map(ensureByte))
}

public func scanUtf16BE(profile: String, mode: String, input: [Int]) -> Verdict {
    scanUtf16(profile: profile, mode: mode, bytes: input.map(ensureByte), order: .big)
}

public func scanUtf16LE(profile: String, mode: String, input: [Int]) -> Verdict {
    scanUtf16(profile: profile, mode: mode, bytes: input.map(ensureByte), order: .little)
}

public func scanUtf32BE(profile: String, mode: String, input: [Int]) -> Verdict {
    scanUtf32(profile: profile, mode: mode, bytes: input.map(ensureByte), order: .big)
}

public func scanUtf32LE(profile: String, mode: String, input: [Int]) -> Verdict {
    scanUtf32(profile: profile, mode: mode, bytes: input.map(ensureByte), order: .little)
}

public func verdictToWire(_ verdict: Verdict) -> [String: Any] {
    [
        "action": verdict.action,
        "profile": verdict.profile,
        "mode": verdict.mode,
        "input": verdict.input,
        "findings": verdict.findings.map(findingToWire),
        "normalized": verdict.normalized as Any,
    ]
}

public func verdictJson(_ verdict: Verdict) -> String {
    var out = "{"
    out += jsonField("action", verdict.action)
    out += "," + jsonField("profile", verdict.profile)
    out += "," + jsonField("mode", verdict.mode)
    out += ",\"input\":" + intArrayJson(verdict.input)
    out += ",\"findings\":[" + verdict.findings.map(findingJson).joined(separator: ",") + "]"
    if let normalized = verdict.normalized {
        out += ",\"normalized\":" + intArrayJson(normalized)
    } else {
        out += ",\"normalized\":null"
    }
    out += "}"
    return out
}

private func detect(_ input: [Int]) -> [Finding] {
    var findings: [Finding] = []
    let tagPositions = positionsWhere(input, isTagBlockAsciiPayload)
    if !tagPositions.isEmpty {
        findings.append(makeFinding(family: Family.tagBlockPayload, subThreat: "DirectAscii", positions: tagPositions))
    }
    if let variation = variationSelectorFinding(input) {
        findings.append(variation)
    }
    let zeroWidth = positionsWhere(input, isZeroWidthPayload)
    if !zeroWidth.isEmpty {
        findings.append(makeFinding(family: Family.zeroWidthPayload, subThreat: "BareZeroWidth", positions: zeroWidth))
    }
    let bidi = positionsWhere(input, isBidiEmbeddingControl)
    if !bidi.isEmpty {
        findings.append(makeFinding(family: Family.bidiControlBalance, subThreat: "UnbalancedEmbedding", positions: bidi))
    }
    findings.append(contentsOf: noncharacterControlFindings(input))
    if let homoglyph = homoglyphConfusableFinding(input) {
        findings.append(homoglyph)
    }
    if let mixedScript = mixedScriptAdmissibilityFinding(input) {
        findings.append(mixedScript)
    }
    return findings
}

private func decide(profile: String, mode: String, findings: [Finding]) -> String {
    if findings.isEmpty { return Action.allow }
    if mode == Mode.observe || mode == Mode.warn { return Action.observe }
    if mode == Mode.strict { return Action.reject }
    let policy = policyOfProfile(profile)
    for finding in findings {
        if blocks(policy.level, finding.family) {
            return policy.quarantine ? Action.quarantine : Action.reject
        }
    }
    return Action.allow
}

private func policyOfProfile(_ profile: String) -> ProfilePolicy {
    switch profile {
    case Profile.gatewayHeader, Profile.domainName, Profile.dnsLabel, Profile.sourceCode:
        return ProfilePolicy(level: .restrictive, quarantine: false)
    case Profile.url:
        return ProfilePolicy(level: .moderate, quarantine: false)
    case Profile.username:
        return ProfilePolicy(level: .moderate, quarantine: true)
    case Profile.displayName, Profile.chatMessage:
        return ProfilePolicy(level: .minimal, quarantine: true)
    case Profile.opaqueSecret, Profile.binaryBlob:
        return ProfilePolicy(level: .minimal, quarantine: false)
    default:
        return ProfilePolicy(level: .restrictive, quarantine: false)
    }
}

private func blocks(_ level: PolicyLevel, _ family: String) -> Bool {
    if level == .minimal {
        return family == Family.malformedUtf8 || family == Family.malformedUtf16 ||
            family == Family.malformedUtf32 || family == Family.bidiControlBalance ||
            family == Family.noncharacterControl
    }
    return family == Family.malformedUtf8 || family == Family.malformedUtf16 ||
        family == Family.malformedUtf32 || family == Family.tagBlockPayload ||
        family == Family.variationSelectorPayload || family == Family.zeroWidthPayload ||
        family == Family.bidiControlBalance || family == Family.noncharacterControl ||
        family == Family.homoglyphConfusable || family == Family.mixedScriptAdmissibility
}

private func malformedDecodeVerdict(profile: String, mode: String, family: String, subThreat: String, offset: Int) -> Verdict {
    let findings = [makeFinding(family: family, subThreat: subThreat, positions: [offset])]
    return Verdict(
        action: decide(profile: profile, mode: mode, findings: findings),
        profile: profile,
        mode: mode,
        input: [],
        findings: findings,
        normalized: nil
    )
}

private func makeFinding(family: String, subThreat: String, positions: [Int]) -> Finding {
    Finding(
        code: reasonCode(family: family, subThreat: subThreat),
        family: family,
        severity: 2,
        positions: positions,
        subThreat: subThreat,
        detail: family
    )
}

private func reasonCode(family: String, subThreat: String) -> String {
    "unicode.security.\(layer(family)).\(family).\(subThreat)"
}

private func layer(_ family: String) -> String {
    family == Family.homoglyphConfusable || family == Family.mixedScriptAdmissibility ? "I" : "C"
}

private func positionsWhere(_ input: [Int], _ predicate: (Int) -> Bool) -> [Int] {
    input.indices.filter { predicate(input[$0]) }
}

private func isTagBlockAsciiPayload(_ cp: Int) -> Bool {
    cp >= 0xe0020 && cp <= 0xe007e
}

private func variationSelectorFinding(_ input: [Int]) -> Finding? {
    let positions = positionsWhere(input, isVariationSelector)
    if positions.isEmpty { return nil }
    if positions.count == 1 && isRegisteredVariationPosition(input, positions[0]) { return nil }
    var subThreat = "IllegalTarget"
    if positions.count >= 4 && allSameAt(input, positions) {
        subThreat = "RepeatedBase"
    } else if !decodeVariationSelectorRun(input, positions).isEmpty {
        subThreat = "DirectPayload"
    }
    return makeFinding(family: Family.variationSelectorPayload, subThreat: subThreat, positions: positions)
}

private func isVariationSelector(_ cp: Int) -> Bool {
    (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef) || (cp >= 0x180b && cp <= 0x180d)
}

private func isRegisteredVariationPosition(_ input: [Int], _ position: Int) -> Bool {
    position > 0 && legalVariationPairs().contains(variationPairKey(input[position - 1], input[position]))
}

private func variationSelectorNibble(_ cp: Int) -> Int? {
    if cp >= 0xfe00 && cp <= 0xfe0f { return cp - 0xfe00 }
    if cp >= 0xe0100 && cp <= 0xe01ef { return cp - 0xe0100 + 16 }
    return nil
}

private func decodeVariationSelectorRun(_ input: [Int], _ positions: [Int]) -> [Int] {
    var out: [Int] = []
    var high = 0
    var haveHigh = false
    for position in positions {
        guard let nibble = variationSelectorNibble(input[position]) else { continue }
        if !haveHigh {
            high = nibble
            haveHigh = true
        } else {
            out.append((high << 4) | nibble)
            haveHigh = false
        }
    }
    return out
}

private func allSameAt(_ input: [Int], _ positions: [Int]) -> Bool {
    guard let firstPosition = positions.first else { return true }
    let first = input[firstPosition]
    return positions.allSatisfy { input[$0] == first }
}

private func isZeroWidthPayload(_ cp: Int) -> Bool {
    cp == 0x200b || cp == 0x200c || cp == 0x200d || cp == 0x2060 || cp == 0xfeff
}

private func isBidiEmbeddingControl(_ cp: Int) -> Bool {
    cp >= 0x202a && cp <= 0x202e
}

private func noncharacterControlFindings(_ input: [Int]) -> [Finding] {
    var findings: [Finding] = []
    let noncharacters = positionsWhere(input, isNoncharacter)
    if !noncharacters.isEmpty {
        findings.append(makeFinding(family: Family.noncharacterControl, subThreat: "Noncharacter", positions: noncharacters))
    }
    let c0 = positionsWhere(input, isC0Control)
    if !c0.isEmpty {
        findings.append(makeFinding(family: Family.noncharacterControl, subThreat: "C0Control", positions: c0))
    }
    let c1 = positionsWhere(input, isC1Control)
    if !c1.isEmpty {
        findings.append(makeFinding(family: Family.noncharacterControl, subThreat: "C1Control", positions: c1))
    }
    return findings
}

private func homoglyphConfusableFinding(_ input: [Int]) -> Finding? {
    let subThreat: String
    if homoglyphTargetMatch(input) != nil {
        subThreat = "TargetMatch"
    } else if input.contains(where: isMathAlphanumeric) {
        subThreat = "MathAlpha"
    } else if input.contains(where: isFullwidthHalfwidth) {
        subThreat = "WidthClass"
    } else if hasDecompositionSwap(input) {
        subThreat = "DecompositionSwap"
    } else {
        return nil
    }
    return makeFinding(family: Family.homoglyphConfusable, subThreat: subThreat, positions: fullSpanPositions(input))
}

private func mixedScriptAdmissibilityFinding(_ input: [Int]) -> Finding? {
    guard hasCrossScriptMix(input) else { return nil }
    return makeFinding(family: Family.mixedScriptAdmissibility, subThreat: "CrossScriptMix", positions: fullSpanPositions(input))
}

private func homoglyphTargetMatch(_ input: [Int]) -> String? {
    let inputLetters = letterSkeleton(input)
    for target in knownAttackTargets() {
        let targetCps = codepointsFromString(target)
        let targetLetters = letterSkeleton(targetCps)
        if !sameNumbers(targetCps, input) && sameNumbers(targetLetters, inputLetters) {
            return target
        }
    }
    return nil
}

private func letterSkeleton(_ input: [Int]) -> [Int] {
    iteratedSkeleton(input).filter {
        !isCombiningMark($0) && !isDefaultIgnorableCodepoint($0) && !isWhiteSpaceCodepoint($0)
    }
}

private func iteratedSkeleton(_ input: [Int]) -> [Int] {
    var current = input
    for _ in 0..<8 {
        let next = skeleton(current)
        if sameNumbers(next, current) { return current }
        current = next
    }
    return current
}

private func skeleton(_ input: [Int]) -> [Int] {
    let step1 = toNfdCodepoints(input)
    let step2 = caseFoldCodepoints(step1)
    let step3 = substituteConfusables(step2)
    let step4 = caseFoldCodepoints(step3)
    return toNfdCodepoints(step4)
}

private func substituteConfusables(_ input: [Int]) -> [Int] {
    let table = confusablesMap()
    var out: [Int] = []
    for cp in input {
        if let replacement = table[cp] {
            out.append(contentsOf: replacement)
        } else {
            out.append(cp)
        }
    }
    return out
}

private func caseFoldCodepoints(_ input: [Int]) -> [Int] {
    input.flatMap(caseFoldCodepoint)
}

private func caseFoldCodepoint(_ cp: Int) -> [Int] {
    guard let scalar = UnicodeScalar(cp) else { return [cp] }
    return codepointsFromString(String(scalar).lowercased())
}

private func toNfdCodepoints(_ input: [Int]) -> [Int] {
    codepointsFromString(stringFromCodepoints(input).decomposedStringWithCanonicalMapping)
}

private func stringFromCodepoints(_ input: [Int]) -> String {
    String(String.UnicodeScalarView(input.compactMap(UnicodeScalar.init)))
}

private func confusablesMap() -> [Int: [Int]] {
    if let cached = confusablesMapCache { return cached }
    let parsed = parseConfusables(readDataFile("confusables.txt"))
    confusablesMapCache = parsed
    return parsed
}

private func knownAttackTargets() -> [String] {
    if let cached = attackTargetsCache { return cached }
    let parsed = parseKnownAttackTargets(readDataFile("KnownAttackTargets.txt"))
    attackTargetsCache = parsed
    return parsed
}

private func legalVariationPairs() -> Set<String> {
    if let cached = legalVariationPairsCache { return cached }
    var parsed = parseLegalVariationPairs(readDataFile("StandardizedVariants.txt"))
    parsed.formUnion(parseLegalVariationPairs(readDataFile("emoji-variation-sequences.txt")))
    legalVariationPairsCache = parsed
    return parsed
}

private func parseConfusables(_ raw: String) -> [Int: [Int]] {
    var out: [Int: [Int]] = [:]
    for rawLine in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        let body = rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0].trimmingCharacters(in: .whitespaces)
        if body.isEmpty { continue }
        let fields = body.split(separator: ";", omittingEmptySubsequences: false)
        if fields.count < 2 { continue }
        if let src = parseHex(String(fields[0])) {
            let target = parseCodepointField(String(fields[1]))
            if !target.isEmpty { out[src] = target }
        }
    }
    return out
}

private func parseKnownAttackTargets(_ raw: String) -> [String] {
    raw.split(separator: "\n", omittingEmptySubsequences: false)
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty && !$0.hasPrefix("#") }
}

private func parseLegalVariationPairs(_ raw: String) -> Set<String> {
    var out: Set<String> = []
    for rawLine in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        let pairPart = rawLine
            .split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
            .split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)[0]
            .trimmingCharacters(in: .whitespaces)
        if pairPart.isEmpty { continue }
        let fields = pairPart.split(whereSeparator: { $0 == " " || $0 == "\t" })
        if fields.count != 2 { continue }
        if let base = parseHex(String(fields[0])), let vs = parseHex(String(fields[1])) {
            out.insert(variationPairKey(base, vs))
        }
    }
    return out
}

private func variationPairKey(_ base: Int, _ vs: Int) -> String {
    "\(base):\(vs)"
}

private func parseCodepointField(_ field: String) -> [Int] {
    field.split(whereSeparator: { $0 == " " || $0 == "\t" }).compactMap { parseHex(String($0)) }
}

private func parseHex(_ field: String) -> Int? {
    Int(field.trimmingCharacters(in: .whitespacesAndNewlines), radix: 16)
}

private func readDataFile(_ name: String) -> String {
    guard let url = Bundle.module.url(forResource: name, withExtension: nil) else {
        fatalError("missing Swift runtime data file: \(name)")
    }
    guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
        fatalError("cannot read Swift runtime data file: \(name)")
    }
    return contents
}

private func fullSpanPositions(_ input: [Int]) -> [Int] {
    Array(input.indices)
}

private func isMathAlphanumeric(_ cp: Int) -> Bool {
    cp >= 0x1d400 && cp <= 0x1d7ff
}

private func isFullwidthHalfwidth(_ cp: Int) -> Bool {
    cp >= 0xff01 && cp <= 0xffef
}

private func isNoncharacter(_ cp: Int) -> Bool {
    if cp >= 0xfdd0 && cp <= 0xfdef { return true }
    if cp > 0x10ffff { return false }
    let low16 = cp & 0xffff
    return low16 == 0xfffe || low16 == 0xffff
}

private func isC0Control(_ cp: Int) -> Bool {
    (cp <= 0x1f && cp != 0x09 && cp != 0x0a && cp != 0x0d) || cp == 0x7f
}

private func isC1Control(_ cp: Int) -> Bool {
    cp >= 0x80 && cp <= 0x9f
}

private func isCombiningMark(_ cp: Int) -> Bool {
    (cp >= 0x0300 && cp <= 0x036f) ||
        (cp >= 0x1ab0 && cp <= 0x1aff) ||
        (cp >= 0x1dc0 && cp <= 0x1dff) ||
        (cp >= 0x20d0 && cp <= 0x20ff) ||
        (cp >= 0xfe20 && cp <= 0xfe2f)
}

private func hasDecompositionSwap(_ input: [Int]) -> Bool {
    if input.count < 2 { return false }
    for index in 1..<input.count {
        let previous = input[index - 1]
        let current = input[index]
        if isCombiningMark(current) && !isCombiningMark(previous) { return true }
        if isCombiningMark(previous) && isCombiningMark(current) && previous > current { return true }
        if composeHangulPair(previous, current) { return true }
    }
    return false
}

private func composeHangulPair(_ first: Int, _ second: Int) -> Bool {
    let sBase = 0xac00
    let lBase = 0x1100
    let vBase = 0x1161
    let tBase = 0x11a7
    let lCount = 19
    let vCount = 21
    let tCount = 28
    let nCount = vCount * tCount
    let sCount = lCount * nCount
    let isL = first >= lBase && first < lBase + lCount
    let isV = second >= vBase && second < vBase + vCount
    if isL && isV { return true }
    let isLV = first >= sBase && first < sBase + sCount && (first - sBase) % tCount == 0
    let isT = second > tBase && second < tBase + tCount
    return isLV && isT
}

private func hasCrossScriptMix(_ input: [Int]) -> Bool {
    Set(input.compactMap(scriptClass)).count >= 2
}

private func scriptClass(_ cp: Int) -> String? {
    if (cp >= 0x0041 && cp <= 0x005a) || (cp >= 0x0061 && cp <= 0x007a) || (cp >= 0x00c0 && cp <= 0x024f) {
        return "Latn"
    }
    if (cp >= 0x0370 && cp <= 0x03ff) || (cp >= 0x1f00 && cp <= 0x1fff) {
        return "Grek"
    }
    if cp >= 0x0400 && cp <= 0x052f {
        return "Cyrl"
    }
    return nil
}

private func isDefaultIgnorableCodepoint(_ cp: Int) -> Bool {
    cp == 0x00ad || cp == 0x034f || cp == 0x061c ||
        (cp >= 0x115f && cp <= 0x1160) ||
        (cp >= 0x17b4 && cp <= 0x17b5) ||
        (cp >= 0x180b && cp <= 0x180f) ||
        (cp >= 0x200b && cp <= 0x200f) ||
        (cp >= 0x202a && cp <= 0x202e) ||
        (cp >= 0x2060 && cp <= 0x206f) ||
        (cp >= 0xfe00 && cp <= 0xfe0f) ||
        cp == 0xfeff ||
        (cp >= 0xfff0 && cp <= 0xfff8) ||
        (cp >= 0xe0000 && cp <= 0xe0fff)
}

private func isWhiteSpaceCodepoint(_ cp: Int) -> Bool {
    cp == 0x0009 || cp == 0x000a || cp == 0x000b || cp == 0x000c ||
        cp == 0x000d || cp == 0x0020 || cp == 0x0085 || cp == 0x00a0 ||
        cp == 0x1680 || (cp >= 0x2000 && cp <= 0x200a) ||
        cp == 0x2028 || cp == 0x2029 || cp == 0x202f || cp == 0x205f ||
        cp == 0x3000
}

private func scanUtf16(profile: String, mode: String, bytes: [UInt8], order: ByteOrder) -> Verdict {
    let decoded = decodeUtf16ToCodepoints(bytes, order: order)
    if let failure = decoded.failure {
        return malformedDecodeVerdict(profile: profile, mode: mode, family: Family.malformedUtf16, subThreat: failure.subThreat, offset: failure.offset)
    }
    return scan(profile: profile, mode: mode, input: decoded.codepoints)
}

private func decodeUtf16ToCodepoints(_ input: [UInt8], order: ByteOrder) -> DecodeResult {
    var out: [Int] = []
    var offset = 0
    while offset < input.count {
        if offset + 2 > input.count {
            return DecodeResult(codepoints: [], failure: DecodeFailure(subThreat: "TruncatedCodeUnit", offset: input.count))
        }
        let unitOffset = offset
        let unit = readUint16(input, offset, order)
        offset += 2
        if unit >= 0xd800 && unit <= 0xdbff {
            if offset + 2 > input.count {
                return DecodeResult(codepoints: [], failure: DecodeFailure(subThreat: "TruncatedSurrogatePair", offset: input.count))
            }
            let low = readUint16(input, offset, order)
            if low < 0xdc00 || low > 0xdfff {
                return DecodeResult(codepoints: [], failure: DecodeFailure(subThreat: "InvalidSurrogatePair", offset: offset))
            }
            out.append(0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00))
            offset += 2
        } else if unit >= 0xdc00 && unit <= 0xdfff {
            return DecodeResult(codepoints: [], failure: DecodeFailure(subThreat: "LoneSurrogate", offset: unitOffset))
        } else {
            out.append(unit)
        }
    }
    return DecodeResult(codepoints: out, failure: nil)
}

private func scanUtf32(profile: String, mode: String, bytes: [UInt8], order: ByteOrder) -> Verdict {
    let decoded = decodeUtf32ToCodepoints(bytes, order: order)
    if let failure = decoded.failure {
        return malformedDecodeVerdict(profile: profile, mode: mode, family: Family.malformedUtf32, subThreat: failure.subThreat, offset: failure.offset)
    }
    return scan(profile: profile, mode: mode, input: decoded.codepoints)
}

private func decodeUtf32ToCodepoints(_ input: [UInt8], order: ByteOrder) -> DecodeResult {
    if input.count % 4 != 0 {
        return DecodeResult(codepoints: [], failure: DecodeFailure(subThreat: "TruncatedCodeUnit", offset: input.count))
    }
    var out: [Int] = []
    var offset = 0
    while offset < input.count {
        let cp = readUint32(input, offset, order)
        if cp >= 0xd800 && cp <= 0xdfff {
            return DecodeResult(codepoints: [], failure: DecodeFailure(subThreat: "SurrogateCodepoint", offset: offset))
        }
        if cp > 0x10ffff {
            return DecodeResult(codepoints: [], failure: DecodeFailure(subThreat: "CodepointBeyondMax", offset: offset))
        }
        out.append(cp)
        offset += 4
    }
    return DecodeResult(codepoints: out, failure: nil)
}

private func readUint16(_ input: [UInt8], _ offset: Int, _ order: ByteOrder) -> Int {
    if order == .big {
        return (Int(input[offset]) << 8) | Int(input[offset + 1])
    }
    return Int(input[offset]) | (Int(input[offset + 1]) << 8)
}

private func readUint32(_ input: [UInt8], _ offset: Int, _ order: ByteOrder) -> Int {
    if order == .big {
        return (Int(input[offset]) << 24) | (Int(input[offset + 1]) << 16) | (Int(input[offset + 2]) << 8) | Int(input[offset + 3])
    }
    return Int(input[offset]) | (Int(input[offset + 1]) << 8) | (Int(input[offset + 2]) << 16) | (Int(input[offset + 3]) << 24)
}

private func firstInvalidUtf8(_ input: [UInt8]) -> DecodeFailure? {
    var state = Utf8State(inSequence: false, remaining: 0, accum: 0, minCp: 0)
    var seqStart = 0
    for index in input.indices {
        if !state.inSequence { seqStart = index }
        let step = utf8DecodeStep(state, input[index])
        if step.rejected {
            return DecodeFailure(subThreat: step.kind, offset: step.kind == "OverlongEncoding" ? seqStart : index)
        }
        state = step.state
    }
    if state.inSequence {
        return DecodeFailure(subThreat: "TruncatedSequence", offset: input.count)
    }
    return nil
}

private func decodeUtf8ToCodepoints(_ input: [UInt8]) -> [Int] {
    var out: [Int] = []
    var state = Utf8State(inSequence: false, remaining: 0, accum: 0, minCp: 0)
    for byte in input {
        let step = utf8DecodeStep(state, byte)
        if step.rejected { return out }
        if !step.state.inSequence && (state.inSequence || byte < 0x80) {
            out.append(step.emitted)
        }
        state = step.state
    }
    return out
}

private func utf8DecodeStep(_ state: Utf8State, _ byte: UInt8) -> Utf8Step {
    let n = Int(byte)
    if !state.inSequence {
        if n < 0x80 {
            return Utf8Step(state: Utf8State(inSequence: false, remaining: 0, accum: 0, minCp: 0), emitted: n, kind: "", rejected: false)
        }
        if n < 0xc2 {
            return Utf8Step(state: state, emitted: 0, kind: "InvalidStartByte", rejected: true)
        }
        if n < 0xe0 {
            return Utf8Step(state: Utf8State(inSequence: true, remaining: 1, accum: n & 0x1f, minCp: 0x80), emitted: 0, kind: "", rejected: false)
        }
        if n < 0xf0 {
            return Utf8Step(state: Utf8State(inSequence: true, remaining: 2, accum: n & 0x0f, minCp: 0x800), emitted: 0, kind: "", rejected: false)
        }
        if n < 0xf5 {
            return Utf8Step(state: Utf8State(inSequence: true, remaining: 3, accum: n & 0x07, minCp: 0x10000), emitted: 0, kind: "", rejected: false)
        }
        return Utf8Step(state: state, emitted: 0, kind: "InvalidStartByte", rejected: true)
    }

    if n < 0x80 || n >= 0xc0 {
        return Utf8Step(state: state, emitted: 0, kind: "InvalidContinuationByte", rejected: true)
    }
    let next = (state.accum << 6) | (n & 0x3f)
    if state.remaining == 1 {
        if next < state.minCp {
            return Utf8Step(state: state, emitted: 0, kind: "OverlongEncoding", rejected: true)
        }
        if next >= 0xd800 && next <= 0xdfff {
            return Utf8Step(state: state, emitted: 0, kind: "SurrogateCodepoint", rejected: true)
        }
        if next > 0x10ffff {
            return Utf8Step(state: state, emitted: 0, kind: "CodepointBeyondMax", rejected: true)
        }
        return Utf8Step(state: Utf8State(inSequence: false, remaining: 0, accum: 0, minCp: 0), emitted: next, kind: "", rejected: false)
    }
    return Utf8Step(
        state: Utf8State(inSequence: true, remaining: state.remaining - 1, accum: next, minCp: state.minCp),
        emitted: 0,
        kind: "",
        rejected: false
    )
}

private func codepointsFromString(_ value: String) -> [Int] {
    value.unicodeScalars.map { Int($0.value) }
}

private func sameNumbers(_ a: [Int], _ b: [Int]) -> Bool {
    a == b
}

private func ensureCodepoint(_ value: Int) -> Int {
    precondition(value >= 0 && value <= 0x10ffff, "invalid codepoint: \(value)")
    return value
}

private func ensureByte(_ value: Int) -> UInt8 {
    precondition(value >= 0 && value <= 255, "invalid byte: \(value)")
    return UInt8(value)
}

private func jsonField(_ name: String, _ value: String) -> String {
    "\"\(name)\":\"\(escapeJson(value))\""
}

private func findingJson(_ finding: Finding) -> String {
    var out = "{"
    out += jsonField("code", finding.code)
    out += "," + jsonField("family", finding.family)
    out += ",\"severity\":\(finding.severity)"
    out += ",\"positions\":" + intArrayJson(finding.positions)
    out += "," + jsonField("sub_threat", finding.subThreat)
    out += "," + jsonField("detail", finding.detail)
    out += "}"
    return out
}

private func findingToWire(_ finding: Finding) -> [String: Any] {
    [
        "code": finding.code,
        "family": finding.family,
        "severity": finding.severity,
        "positions": finding.positions,
        "sub_threat": finding.subThreat,
        "detail": finding.detail,
    ]
}

private func intArrayJson(_ values: [Int]) -> String {
    "[" + values.map(String.init).joined(separator: ",") + "]"
}

private func escapeJson(_ value: String) -> String {
    var out = ""
    for scalar in value.unicodeScalars {
        switch scalar {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\u{08}": out += "\\b"
        case "\u{0c}": out += "\\f"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if scalar.value < 0x20 {
                out += String(format: "\\u%04X", scalar.value)
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
    }
    return out
}
