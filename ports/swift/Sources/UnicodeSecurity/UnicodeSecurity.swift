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
    public static let surrogateReassembly = "surrogate-reassembly"
    public static let bidiControlBalance = "bidi-control-balance"
    public static let noncharacterControl = "noncharacter-control"
    public static let homoglyphConfusable = "homoglyph-confusable"
    public static let mixedScriptAdmissibility = "mixed-script-admissibility"
    public static let rtlInjection = "rtl-injection"
    public static let confusableBidiCompound = "confusable-bidi-compound"
    public static let covertDisplayCompound = "covert-display-compound"
    public static let hashInputStability = "hash-input-stability"
    public static let aiWatermarkDetectability = "ai-watermark-detectability"
    public static let streamSafeViolation = "stream-safe-violation"
    public static let emojiZwjIntegrity = "emoji-zwj-integrity"
    public static let rendererDivergence = "renderer-divergence"
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
private var caseFoldingCache: [Int: [Int]]?
private var attackTargetsCache: [String]?
private var legalVariationPairsCache: Set<String>?
private var bidiTableCache: BidiTable?
private var unicodeDataCache: [Int: NormEntry]?
private var compositionExclusionsCache: Set<Int>?
private var compositionTableCache: [Int: Int]?
private var specialCasingCache: [Int: [CasingRow]]?
private var simpleLowerCache: [Int: Int]?
private var casedRangesCache: [(Int, Int)]?
private var softDottedRangesCache: [(Int, Int)]?
private var bip39WordlistCache: [String: Set<[Int]>]?
private var emojiRangesCache: [(Int, Int)]?
private var emojiZwjSequencesCache: [[Int]]?
private var emojiZwjAlphabetCache: Set<Int>?
private var graphemeExtendRangesCache: [(Int, Int)]?

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
    if let surrogate = surrogateReassemblyFinding(input) {
        findings.append(surrogate)
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
    if let rtl = rtlInjectionFinding(input) {
        findings.append(rtl)
    }
    if let compound = confusableBidiCompoundFinding(input) {
        findings.append(compound)
    }
    if let covert = covertDisplayCompoundFinding(input) {
        findings.append(covert)
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
            family == Family.malformedUtf32 || family == Family.surrogateReassembly ||
            family == Family.bidiControlBalance ||
            family == Family.noncharacterControl
    }
    return family == Family.malformedUtf8 || family == Family.malformedUtf16 ||
        family == Family.malformedUtf32 || family == Family.tagBlockPayload ||
        family == Family.variationSelectorPayload || family == Family.zeroWidthPayload ||
        family == Family.surrogateReassembly ||
        family == Family.bidiControlBalance || family == Family.noncharacterControl ||
        family == Family.homoglyphConfusable || family == Family.mixedScriptAdmissibility ||
        family == Family.confusableBidiCompound || family == Family.covertDisplayCompound
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
    if family == Family.homoglyphConfusable || family == Family.mixedScriptAdmissibility
        || family == Family.emojiZwjIntegrity
    {
        return "I"
    }
    if family == Family.rtlInjection || family == Family.rendererDivergence {
        return "D"
    }
    if family == Family.confusableBidiCompound || family == Family.covertDisplayCompound {
        return "X"
    }
    if family == Family.hashInputStability || family == Family.aiWatermarkDetectability {
        return "K"
    }
    if family == Family.streamSafeViolation {
        return "F"
    }
    return "C"
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
    return makeFinding(family: Family.mixedScriptAdmissibility, subThreat: mixedScriptSubThreat(input), positions: fullSpanPositions(input))
}

/// Sub-threat and offending positions of an RTL-injection scan; nil sub-threat means clear.
public struct RtlInjectionResult: Equatable {
    public let subThreat: String?
    public let positions: [Int]
}

// Right-to-left injection detection for LTR-declared fields — a direct
// port of Unicode.Security.Display.RtlInjection. Exposed for direct
// spot-check testing, mirroring the Rust/Python/C++ detectors.
public func rtlInjectionDetect(_ input: [Int]) -> RtlInjectionResult {
    var strongRtl = 0
    for cp in input where isStrongRtl(cp) { strongRtl += 1 }
    let (runLen, runStart) = longestRtlRun(input)

    // Phase 1: bidi format-control trumps all.
    for (index, cp) in input.enumerated() where isBidiFormatControl(cp) {
        return RtlInjectionResult(subThreat: "RloInLTRField", positions: [index])
    }

    // Phase 2: leading-RTL field-direction takeover.
    for (index, cp) in input.enumerated() {
        if isStrongRtl(cp) { return RtlInjectionResult(subThreat: "FieldTakeover", positions: [index]) }
        if isStrongLtr(cp) { break }
    }

    // Phase 3: mid-stream strong-RTL.
    if strongRtl == 0 { return RtlInjectionResult(subThreat: nil, positions: []) }
    if runLen >= 4 { return RtlInjectionResult(subThreat: "MixedOverflow", positions: [runStart]) }
    for (index, cp) in input.enumerated() where isStrongRtl(cp) {
        return RtlInjectionResult(subThreat: "StrongRTLInLTR", positions: [index])
    }
    return RtlInjectionResult(subThreat: nil, positions: [])
}

private func rtlInjectionFinding(_ input: [Int]) -> Finding? {
    let result = rtlInjectionDetect(input)
    guard let subThreat = result.subThreat else { return nil }
    return makeFinding(family: Family.rtlInjection, subThreat: subThreat, positions: result.positions)
}

/// Sub-threat and offending positions of a confusable-bidi-compound scan; nil
/// sub-threat means clear. Positions carry [confusablePos, bidiPos].
public struct ConfusableBidiCompoundResult: Equatable {
    public let subThreat: String?
    public let positions: [Int]
}

// Confusable-in-bidi-context compound detection (layer X, CVE-2021-42574
// class) — a direct port of Unicode.Security.Boundary.ConfusableBidiCompound.
// A confusable (homoglyph) codepoint co-located with a bidi format-control is
// materially more dangerous than either alone: the homoglyph disguises an
// identifier while the bidi control reorders how a reviewer reads it. The
// detector fires only when both are present. Priority mirrors the spec: with a
// confusable present, an override-class control (LRE/RLE/LRO/RLO/PDF) fires
// ConfusableInOverride; otherwise an isolate-class control (LRI/RLI/FSI/PDI)
// fires ConfusableInIsolate; otherwise clear. Exposed for direct spot-check
// testing, mirroring the Rust/Python/C++ detectors.
public func confusableBidiCompoundDetect(_ input: [Int]) -> ConfusableBidiCompoundResult {
    guard let confusablePos = input.firstIndex(where: isConfusableSource) else {
        return ConfusableBidiCompoundResult(subThreat: nil, positions: [])
    }
    if let overridePos = input.firstIndex(where: isConfusableBidiOverride) {
        return ConfusableBidiCompoundResult(subThreat: "ConfusableInOverride", positions: [confusablePos, overridePos])
    }
    if let isolatePos = input.firstIndex(where: isConfusableBidiIsolate) {
        return ConfusableBidiCompoundResult(subThreat: "ConfusableInIsolate", positions: [confusablePos, isolatePos])
    }
    return ConfusableBidiCompoundResult(subThreat: nil, positions: [])
}

private func confusableBidiCompoundFinding(_ input: [Int]) -> Finding? {
    let result = confusableBidiCompoundDetect(input)
    guard let subThreat = result.subThreat else { return nil }
    return makeFinding(family: Family.confusableBidiCompound, subThreat: subThreat, positions: result.positions)
}

/// True iff `cp` is a confusable source per UTS #39 §4 — it has a row in
/// confusables.txt mapping it to a different skeleton sequence. Mirrors
/// Unicode.Confusables.lookupConfusable?(cp).isSome. Reuses the shared
/// confusables map that backs the homoglyph detector's skeleton substitution.
public func isConfusableSource(_ cp: Int) -> Bool {
    confusablesMap()[cp] != nil
}

/// True iff `cp` is an override-class bidi control (LRE, RLE, LRO, RLO, PDF).
private func isConfusableBidiOverride(_ cp: Int) -> Bool {
    cp >= 0x202a && cp <= 0x202e
}

/// True iff `cp` is an isolate-class bidi control (LRI, RLI, FSI, PDI).
private func isConfusableBidiIsolate(_ cp: Int) -> Bool {
    cp >= 0x2066 && cp <= 0x2069
}

private func isBidiFormatControl(_ cp: Int) -> Bool {
    (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)
}

/// Sub-threat and offending positions of a covert-display-compound scan; nil
/// sub-threat means clear. Positions carry [bidiPos, covertPos].
public struct CovertDisplayCompoundResult: Equatable {
    public let subThreat: String?
    public let positions: [Int]
}

// Covert-display compound detection (layer X) — a direct port of
// Unicode.Security.Boundary.CovertDisplayCompound. A bidi format-control
// that reorders the visible glyphs is materially more dangerous when the same
// input also carries a covert channel — an unregistered variation selector or a
// tag-block character — because the reorder hides where the covert payload sits.
// The detector fires only when a bidi control coincides with one of those
// covert classes. Priority mirrors the spec: with a bidi control present, a
// suspicious variation selector fires BidiPlusUnregisteredVs; otherwise a
// tag-block character fires BidiPlusTagBlock; otherwise clear. Exposed for
// direct spot-check testing, mirroring the Rust/Python/C++ detectors.
public func covertDisplayCompoundDetect(_ input: [Int]) -> CovertDisplayCompoundResult {
    guard let bidiPos = input.firstIndex(where: isBidiFormatControl) else {
        return CovertDisplayCompoundResult(subThreat: nil, positions: [])
    }
    if let vsPos = firstSuspiciousVariationSelector(input) {
        return CovertDisplayCompoundResult(subThreat: "BidiPlusUnregisteredVs", positions: [bidiPos, vsPos])
    }
    if let tagPos = input.firstIndex(where: isCovertTagBlockChar) {
        return CovertDisplayCompoundResult(subThreat: "BidiPlusTagBlock", positions: [bidiPos, tagPos])
    }
    return CovertDisplayCompoundResult(subThreat: nil, positions: [])
}

private func covertDisplayCompoundFinding(_ input: [Int]) -> Finding? {
    let result = covertDisplayCompoundDetect(input)
    guard let subThreat = result.subThreat else { return nil }
    return makeFinding(family: Family.covertDisplayCompound, subThreat: subThreat, positions: result.positions)
}

/// True iff `cp` is in the tag-block range U+E0000..U+E007F.
private func isCovertTagBlockChar(_ cp: Int) -> Bool {
    cp >= 0xE0000 && cp <= 0xE007F
}

/// First position holding a suspicious variation selector — a VS that does not
/// form a registered (base, VS) pair with its predecessor. Mirrors the
/// `.suspicious` case of the Lean `classifyPositions`.
private func firstSuspiciousVariationSelector(_ input: [Int]) -> Int? {
    input.indices.first { index in
        isVariationSelector(input[index]) && !isRegisteredVariationPosition(input, index)
    }
}

// Longest consecutive run of strong-RTL codepoints and its start;
// (0, 0) when there are none.
private func longestRtlRun(_ input: [Int]) -> (Int, Int) {
    var longest = 0
    var longestStart = 0
    var current = 0
    var currentStart = 0
    for (index, cp) in input.enumerated() {
        if isStrongRtl(cp) {
            let newStart = current == 0 ? index : currentStart
            current += 1
            currentStart = newStart
            if current > longest {
                longest = current
                longestStart = newStart
            }
        } else {
            current = 0
        }
    }
    return (longest, longestStart)
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
    let table = caseFoldingMap()
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

// ── Canonical / compatibility normalization from the pinned UCD tables ──────
// NFD/NFKD/NFKC are computed from UnicodeData.txt (field-3 CCC, field-5
// decompositions) and CompositionExclusions.txt, mirroring
// Unicode.Normalization.{Decompose,Reorder,Compose,NFKD,NFKC} and the verified
// from-tables ports. Independent of Foundation's decomposed/precomposed string
// APIs, whose Unicode version tracks the OS ICU rather than the pinned UCD.

private let hangulSBase = 0xAC00
private let hangulLBase = 0x1100
private let hangulVBase = 0x1161
private let hangulTBase = 0x11A7
private let hangulLCount = 19
private let hangulVCount = 21
private let hangulTCount = 28
private let hangulNCount = 21 * 28
private let hangulSCount = 19 * 21 * 28

// One UnicodeData row's normalization fields: CCC and the canonical /
// compatibility decompositions (nil when absent). A field-5 mapping with a
// <tag> prefix is a compatibility mapping; without a tag it is canonical.
private struct NormEntry {
    let ccc: Int
    let canonical: [Int]?
    let compat: [Int]?
}

private func parseUnicodeData(_ raw: String) -> [Int: NormEntry] {
    var out: [Int: NormEntry] = [:]
    for line in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        if line.isEmpty { continue }
        let f = line.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
        if f.count < 6 { continue }
        guard let cp = parseHex(f[0]) else { continue }
        let ccc = Int(f[3].trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        let decomp = f[5].trimmingCharacters(in: .whitespacesAndNewlines)
        var canonical: [Int]? = nil
        var compat: [Int]? = nil
        if !decomp.isEmpty {
            if decomp.hasPrefix("<") {
                if let gt = decomp.firstIndex(of: ">") {
                    compat = parseCodepointField(String(decomp[decomp.index(after: gt)...]))
                }
            } else {
                canonical = parseCodepointField(decomp)
            }
        }
        out[cp] = NormEntry(ccc: ccc, canonical: canonical, compat: compat)
    }
    return out
}

private func parseCompositionExclusions(_ raw: String) -> Set<Int> {
    var out: Set<Int> = []
    for line in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        let body = String(line.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if body.isEmpty { continue }
        if let cp = parseHex(body) { out.insert(cp) }
    }
    return out
}

private func unicodeDataMap() -> [Int: NormEntry] {
    if let cached = unicodeDataCache { return cached }
    let parsed = parseUnicodeData(readDataFile("UnicodeData.txt"))
    unicodeDataCache = parsed
    return parsed
}

private func compositionExclusions() -> Set<Int> {
    if let cached = compositionExclusionsCache { return cached }
    let parsed = parseCompositionExclusions(readDataFile("CompositionExclusions.txt"))
    compositionExclusionsCache = parsed
    return parsed
}

private func canonicalCombiningClass(_ cp: Int) -> Int {
    unicodeDataMap()[cp]?.ccc ?? 0
}

private func composeKey(_ d: Int, _ c: Int) -> Int { (d << 21) | c }

// Canonical composition table: inverse of the two-codepoint canonical
// decompositions, excluding singleton decompositions, Composition-Exclusion
// codepoints, and pairs whose first element is a non-starter (CCC != 0).
private func compositionTable() -> [Int: Int] {
    if let cached = compositionTableCache { return cached }
    var table: [Int: Int] = [:]
    let exclusions = compositionExclusions()
    for (cp, entry) in unicodeDataMap() {
        guard let decomp = entry.canonical, decomp.count == 2 else { continue }
        if exclusions.contains(cp) { continue }
        if canonicalCombiningClass(decomp[0]) != 0 { continue }
        table[composeKey(decomp[0], decomp[1])] = cp
    }
    compositionTableCache = table
    return table
}

private func hangulDecompose(_ cp: Int, _ out: inout [Int]) -> Bool {
    if cp < hangulSBase || cp >= hangulSBase + hangulSCount { return false }
    let sIndex = cp - hangulSBase
    out.append(hangulLBase + sIndex / hangulNCount)
    out.append(hangulVBase + (sIndex % hangulNCount) / hangulTCount)
    let tIndex = sIndex % hangulTCount
    if tIndex != 0 { out.append(hangulTBase + tIndex) }
    return true
}

private func hangulCompose(_ a: Int, _ b: Int) -> Int? {
    if a >= hangulLBase && a < hangulLBase + hangulLCount
        && b >= hangulVBase && b < hangulVBase + hangulVCount {
        let lIndex = a - hangulLBase
        let vIndex = b - hangulVBase
        return hangulSBase + (lIndex * hangulVCount + vIndex) * hangulTCount
    }
    if a >= hangulSBase && a < hangulSBase + hangulSCount
        && (a - hangulSBase) % hangulTCount == 0
        && b > hangulTBase && b < hangulTBase + hangulTCount {
        return a + (b - hangulTBase)
    }
    return nil
}

private func decomposeOne(_ cp: Int, _ out: inout [Int]) {
    if hangulDecompose(cp, &out) { return }
    if let entry = unicodeDataMap()[cp], let canonical = entry.canonical {
        for child in canonical { decomposeOne(child, &out) }
        return
    }
    out.append(cp)
}

private func compatDecomposeOne(_ cp: Int, _ out: inout [Int]) {
    if hangulDecompose(cp, &out) { return }
    if let entry = unicodeDataMap()[cp] {
        if let compat = entry.compat {
            for child in compat { compatDecomposeOne(child, &out) }
            return
        }
        if let canonical = entry.canonical {
            for child in canonical { compatDecomposeOne(child, &out) }
            return
        }
    }
    out.append(cp)
}

// Stable canonical ordering: sort each non-starter run by CCC, preserving the
// relative order of equal-CCC codepoints (insertion sort that swaps only on a
// strict CCC decrease and never crosses a starter).
private func canonicalOrder(_ values: inout [Int]) {
    var index = 1
    while index < values.count {
        let currentCcc = canonicalCombiningClass(values[index])
        if currentCcc != 0 {
            var j = index
            while j > 0 {
                let previousCcc = canonicalCombiningClass(values[j - 1])
                if previousCcc == 0 || previousCcc <= currentCcc { break }
                values.swapAt(j - 1, j)
                j -= 1
            }
        }
        index += 1
    }
}

// Canonical composition (UAX #15 D115), mirroring Unicode.Normalization.Compose
// and the D115-corrected blocked rule shared by the from-tables ports.
private func canonicalCompose(_ seq: [Int]) -> [Int] {
    if seq.isEmpty { return [] }
    let table = compositionTable()
    var out: [Int] = []
    var starterIndex = -1
    var lastCcc = -1
    for cp in seq {
        let cpCcc = canonicalCombiningClass(cp)
        if starterIndex >= 0 {
            let starter = out[starterIndex]
            var composed = hangulCompose(starter, cp)
            if composed == nil { composed = table[composeKey(starter, cp)] }
            // Blocked check (UAX #15 D115): lastCcc != 0 means a combiner is
            // buffered between the active starter and this candidate. A starter
            // candidate (cpCcc == 0) is blocked outright by any buffered combiner;
            // a non-starter is blocked when the buffered combiner has CCC >= its own.
            let blocked = lastCcc != 0 && (cpCcc == 0 || lastCcc >= cpCcc)
            if !blocked, let composedValue = composed {
                out[starterIndex] = composedValue
                continue
            }
        }
        out.append(cp)
        if cpCcc == 0 {
            starterIndex = out.count - 1
            lastCcc = 0
        } else {
            lastCcc = cpCcc
        }
    }
    return out
}

private func toNfdCodepoints(_ input: [Int]) -> [Int] {
    var out: [Int] = []
    for cp in input { decomposeOne(cp, &out) }
    canonicalOrder(&out)
    return out
}

// Compatibility decomposition (NFKD), mirroring Unicode.Normalization.NFKD.
public func toNfkd(_ input: [Int]) -> [Int] {
    var out: [Int] = []
    for cp in input { compatDecomposeOne(ensureCodepoint(cp), &out) }
    canonicalOrder(&out)
    return out
}

// NFKD followed by canonical composition, mirroring Unicode.Normalization.NFKC.
public func toNfkc(_ input: [Int]) -> [Int] {
    canonicalCompose(toNfkd(input))
}

// NFD followed by canonical composition, mirroring Unicode.Normalization.NFC.
private func toNfc(_ input: [Int]) -> [Int] {
    canonicalCompose(toNfdCodepoints(input))
}

// ─────────────────────────────────────────────────────────────────────
// UAX #21 case mapping (toLower), mirroring Unicode.Casing.
//
// Full case mappings come from SpecialCasing.txt (one-to-many and
// context/locale-dependent rows); the simple lowercase fallback is
// UnicodeData.txt field 13. The context predicates (Final_Sigma,
// After_Soft_Dotted, More_Above, Not_Before_Dot, After_I) read canonical
// combining class plus the Cased and Soft_Dotted properties from
// DerivedCoreProperties.txt. This is the shared primitive the bip39-canonical
// detector lowercases through.
// ─────────────────────────────────────────────────────────────────────

/// The locales SpecialCasing.txt distinguishes. `default` covers everything not
/// tagged Turkish / Azeri / Lithuanian.
public enum CasingLocale: Equatable {
    case `default`
    case turkish
    case azeri
    case lithuanian
}

private struct CasingRow {
    let lower: [Int]
    let conditions: [String]
}

private let casingLocaleConditions: Set<String> = ["tr", "az", "lt"]

private func parseSpecialCasing(_ raw: String) -> [Int: [CasingRow]] {
    var rows: [Int: [CasingRow]] = [:]
    for rawLine in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        let line = String(rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if line.isEmpty { continue }
        let fields = line.split(separator: ";", omittingEmptySubsequences: false).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if fields.count < 4 { continue }
        guard let code = parseHex(fields[0]) else { continue }
        let lower = fields[1].split(separator: " ").compactMap { parseHex(String($0)) }
        let conditions = fields.count > 4 && !fields[4].isEmpty
            ? fields[4].split(separator: " ").map(String.init)
            : []
        rows[code, default: []].append(CasingRow(lower: lower, conditions: conditions))
    }
    return rows
}

private func specialCasingRows() -> [Int: [CasingRow]] {
    if let cached = specialCasingCache { return cached }
    let parsed = parseSpecialCasing(readDataFile("SpecialCasing.txt"))
    specialCasingCache = parsed
    return parsed
}

private func parseSimpleLowercase(_ raw: String) -> [Int: Int] {
    var out: [Int: Int] = [:]
    for line in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        if line.isEmpty { continue }
        let f = line.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
        if f.count < 14 { continue }
        guard let cp = parseHex(f[0]) else { continue }
        let lowerField = f[13].trimmingCharacters(in: .whitespacesAndNewlines)
        if lowerField.isEmpty { continue }
        if let lower = parseHex(lowerField) { out[cp] = lower }
    }
    return out
}

private func simpleLowerMap() -> [Int: Int] {
    if let cached = simpleLowerCache { return cached }
    let parsed = parseSimpleLowercase(readDataFile("UnicodeData.txt"))
    simpleLowerCache = parsed
    return parsed
}

private func simpleLowercase(_ cp: Int) -> Int {
    simpleLowerMap()[cp] ?? cp
}

private func parseDerivedProperty(_ raw: String, _ name: String) -> [(Int, Int)] {
    var out: [(Int, Int)] = []
    for rawLine in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        let line = String(rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if line.isEmpty { continue }
        let parts = line.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if parts.count < 2 || parts[1] != name { continue }
        let field = parts[0]
        if let dots = field.range(of: "..") {
            if let lo = parseHex(String(field[field.startIndex..<dots.lowerBound])),
                let hi = parseHex(String(field[dots.upperBound...])) {
                out.append((lo, hi))
            }
        } else if let cp = parseHex(field) {
            out.append((cp, cp))
        }
    }
    return out.sorted { $0.0 < $1.0 }
}

private func casedRanges() -> [(Int, Int)] {
    if let cached = casedRangesCache { return cached }
    let parsed = parseDerivedProperty(readDataFile("DerivedCoreProperties.txt"), "Cased")
    casedRangesCache = parsed
    return parsed
}

private func softDottedRanges() -> [(Int, Int)] {
    if let cached = softDottedRangesCache { return cached }
    let parsed = parseDerivedProperty(readDataFile("DerivedCoreProperties.txt"), "Soft_Dotted")
    softDottedRangesCache = parsed
    return parsed
}

private func inCasingRanges(_ ranges: [(Int, Int)], _ cp: Int) -> Bool {
    ranges.contains { cp >= $0.0 && cp <= $0.1 }
}

private func isCased(_ cp: Int) -> Bool { inCasingRanges(casedRanges(), cp) }
private func isSoftDotted(_ cp: Int) -> Bool { inCasingRanges(softDottedRanges(), cp) }

// Context predicates (UAX #21). `revPrefix` is the preceding codepoints
// nearest-first; `suffix` the strictly-following ones.

private func moreAboveAfter(_ suffix: [Int]) -> Bool {
    for cp in suffix {
        let c = canonicalCombiningClass(cp)
        if c == 230 { return true }
        if c == 0 { return false }
    }
    return false
}

private func afterSoftDotted(_ revPrefix: [Int]) -> Bool {
    for cp in revPrefix {
        if isSoftDotted(cp) { return true }
        let c = canonicalCombiningClass(cp)
        if c == 0 || c == 230 { return false }
    }
    return false
}

private func afterI(_ revPrefix: [Int]) -> Bool {
    for cp in revPrefix {
        if cp == 0x0049 { return true }
        let c = canonicalCombiningClass(cp)
        if c == 0 || c == 230 { return false }
    }
    return false
}

private func beforeDot(_ suffix: [Int]) -> Bool {
    for cp in suffix {
        if cp == 0x0307 { return true }
        if canonicalCombiningClass(cp) == 0 { return false }
    }
    return false
}

private func hasCasedBefore(_ revPrefix: [Int]) -> Bool {
    for cp in revPrefix {
        if isCased(cp) { return true }
        if canonicalCombiningClass(cp) == 0 { return false }
    }
    return false
}

private func hasCasedAfter(_ suffix: [Int]) -> Bool {
    for cp in suffix {
        if isCased(cp) { return true }
        if canonicalCombiningClass(cp) == 0 { return false }
    }
    return false
}

private func finalSigma(_ revPrefix: [Int], _ suffix: [Int]) -> Bool {
    hasCasedBefore(revPrefix) && !hasCasedAfter(suffix)
}

private func casingLocaleMatches(_ locale: CasingLocale, _ conds: [String]) -> Bool {
    if !conds.contains(where: { casingLocaleConditions.contains($0) }) { return true }
    return conds.contains { cond in
        (cond == "tr" && locale == .turkish)
            || (cond == "az" && locale == .azeri)
            || (cond == "lt" && locale == .lithuanian)
    }
}

private func casingConditionsHold(
    _ locale: CasingLocale, _ revPrefix: [Int], _ suffix: [Int], _ conds: [String]
) -> Bool {
    if !casingLocaleMatches(locale, conds) { return false }
    for cond in conds {
        if casingLocaleConditions.contains(cond) { continue }
        let ok: Bool
        switch cond {
        case "Final_Sigma": ok = finalSigma(revPrefix, suffix)
        case "Not_Final_Sigma": ok = !finalSigma(revPrefix, suffix)
        case "After_Soft_Dotted": ok = afterSoftDotted(revPrefix)
        case "More_Above": ok = moreAboveAfter(suffix)
        case "Not_Before_Dot": ok = !beforeDot(suffix)
        case "After_I": ok = afterI(revPrefix)
        default: ok = false
        }
        if !ok { return false }
    }
    return true
}

// UAX #21: a conditional row whose conditions hold outranks the unconditional
// row for the same codepoint; absent any special row, the simple lowercase
// mapping applies.
private func findSpecialCasingRow(
    _ locale: CasingLocale, _ revPrefix: [Int], _ suffix: [Int], _ cp: Int
) -> CasingRow? {
    guard let candidates = specialCasingRows()[cp] else { return nil }
    for row in candidates where !row.conditions.isEmpty {
        if casingConditionsHold(locale, revPrefix, suffix, row.conditions) { return row }
    }
    for row in candidates where row.conditions.isEmpty {
        return row
    }
    return nil
}

private func lowerCodepoint(
    _ locale: CasingLocale, _ revPrefix: [Int], _ suffix: [Int], _ cp: Int
) -> [Int] {
    if let row = findSpecialCasingRow(locale, revPrefix, suffix, cp) {
        return row.lower
    }
    return [simpleLowercase(cp)]
}

/// Lowercase a codepoint sequence under `locale` (UAX #21 full mapping),
/// mirroring `Unicode.Casing.toLower`.
public func toLower(_ locale: CasingLocale, _ cps: [Int]) -> [Int] {
    var out: [Int] = []
    var revPrefix: [Int] = []
    for index in cps.indices {
        let suffix = Array(cps[(index + 1)...])
        out.append(contentsOf: lowerCodepoint(locale, revPrefix, suffix, cps[index]))
        revPrefix.insert(cps[index], at: 0)
    }
    return out
}

// ─────────────────────────────────────────────────────────────────────
// Locale-case-inversion detector (UAX #21 / Tier A2), mirroring
// Unicode.Security.Form.LocaleCaseInversion. Inputs whose lowercase fold
// inverts across locales — the homograph-via-locale attack (CVE-2007-6692,
// CVE-2021-30245, the Spotify "İSTANBUL" / "iSTANBUL" incident class).
//
// Detection compares per-position lowerCodepoint under each locale against
// the default, rather than diffing whole-string toLower, because
// lowerCodepoint evaluates the SpecialCasing context predicates with full
// surrounding context. Turkish divergence takes priority over Lithuanian
// (SpecialCasing has no az-only codepoint, so Turkish covers Azeri).
// ─────────────────────────────────────────────────────────────────────

public struct LocaleCaseInversionResult: Equatable {
    public let subThreat: String?
    public let positions: [Int]
}

/// First input position whose `lowerCodepoint` under `locale` differs from
/// the default-locale result, or `nil` when the folds agree everywhere.
private func firstLocaleDivergence(_ locale: CasingLocale, _ input: [Int]) -> Int? {
    var revPrefix: [Int] = []
    for index in input.indices {
        let suffix = Array(input[(index + 1)...])
        let defaultLower = lowerCodepoint(.default, revPrefix, suffix, input[index])
        let localeLower = lowerCodepoint(locale, revPrefix, suffix, input[index])
        if defaultLower != localeLower { return index }
        revPrefix.insert(input[index], at: 0)
    }
    return nil
}

/// Detect an input whose lowercase fold inverts across locales. Turkish
/// divergence takes priority; Lithuanian is reached only when no Turkish
/// divergence is found.
public func localeCaseInversionDetect(_ input: [Int]) -> LocaleCaseInversionResult {
    if let pos = firstLocaleDivergence(.turkish, input) {
        return LocaleCaseInversionResult(subThreat: "TurkishCaseDivergence", positions: [pos])
    }
    if let pos = firstLocaleDivergence(.lithuanian, input) {
        return LocaleCaseInversionResult(subThreat: "LithuanianCaseDivergence", positions: [pos])
    }
    return LocaleCaseInversionResult(subThreat: nil, positions: [])
}

// ─────────────────────────────────────────────────────────────────────
// BIP-39 canonical-form detector (crypto layer), mirroring
// Unicode.Security.Crypto.Bip39Canonical.
//
// Canonical form = NFKD -> toLower(default) -> collapse BIP-39 whitespace runs
// to a single U+0020 -> trim leading/trailing U+0020. The detector runs six
// probes in priority order (first hit wins): trailing whitespace, mixed case,
// whitespace anomaly, non-NFKD input, wordlist mismatch, then language
// resolution over the ten 2,048-word BIP-39 wordlists.
// ─────────────────────────────────────────────────────────────────────

public struct Bip39CanonicalResult: Equatable {
    public let subThreat: String?
    public let positions: [Int]
    public let language: String
    public let canonical: [Int]
    public let wordCount: Int
}

// Declaration order matching Unicode.Generated.BIP39.allLanguages; English is
// first, so a mnemonic several wordlists could cover resolves to English exactly
// as the Lean findSome? over allLanguages does.
private let bip39Languages: [String] = [
    "english", "japanese", "korean", "spanish", "chinese_simplified",
    "chinese_traditional", "french", "italian", "czech", "portuguese",
]

private func bip39Wordlist(_ lang: String) -> Set<[Int]> {
    if bip39WordlistCache == nil { bip39WordlistCache = [:] }
    if let cached = bip39WordlistCache?[lang] { return cached }
    var entries: Set<[Int]> = []
    for line in readDataFile("bip39/\(lang).txt").split(separator: "\n", omittingEmptySubsequences: false) {
        if line.isEmpty { continue }
        entries.insert(codepointsFromString(String(line)))
    }
    bip39WordlistCache?[lang] = entries
    return entries
}

private func bip39IsInWordlist(_ lang: String, _ word: [Int]) -> Bool {
    bip39Wordlist(lang).contains(word)
}

private func bip39WordlistsContaining(_ word: [Int]) -> [String] {
    bip39Languages.filter { bip39IsInWordlist($0, word) }
}

private func bip39UniqueLanguage(_ words: [[Int]]) -> String? {
    for lang in bip39Languages {
        if words.allSatisfy({ bip39IsInWordlist(lang, $0) }) { return lang }
    }
    return nil
}

private func bip39SplitWords(_ canonical: [Int]) -> [[Int]] {
    var words: [[Int]] = []
    var current: [Int] = []
    for cp in canonical {
        if cp == 0x0020 {
            if !current.isEmpty { words.append(current); current = [] }
        } else {
            current.append(cp)
        }
    }
    if !current.isEmpty { words.append(current) }
    return words
}

private func isBip39Whitespace(_ cp: Int) -> Bool { cp == 0x0020 || cp == 0x3000 }

private func collapseBip39Whitespace(_ cps: [Int]) -> [Int] {
    var out: [Int] = []
    var inWs = false
    for cp in cps {
        if isBip39Whitespace(cp) {
            if !inWs { out.append(0x0020) }
            inWs = true
        } else {
            out.append(cp)
            inWs = false
        }
    }
    return out
}

private func trimBip39(_ cps: [Int]) -> [Int] {
    var start = 0
    var end = cps.count
    while start < end && cps[start] == 0x0020 { start += 1 }
    while end > start && cps[end - 1] == 0x0020 { end -= 1 }
    return Array(cps[start..<end])
}

private func bip39CanonicalForm(_ cps: [Int]) -> [Int] {
    trimBip39(collapseBip39Whitespace(toLower(.default, toNfkd(cps))))
}

private func bip39CountTrailingWhitespace(_ cps: [Int]) -> Int {
    var count = 0
    for cp in cps.reversed() {
        if isBip39Whitespace(cp) { count += 1 } else { break }
    }
    return count
}

private func bip39FirstUppercasePos(_ cps: [Int]) -> Int? {
    cps.firstIndex { $0 >= 0x41 && $0 <= 0x5A }
}

private func bip39FirstWhitespaceRunPos(_ cps: [Int]) -> Int? {
    for index in cps.indices where isBip39Whitespace(cps[index]) {
        if index == 0 { return index }
        if index + 1 < cps.count && isBip39Whitespace(cps[index + 1]) { return index }
    }
    return nil
}

private func bip39FirstArrayDivergence(_ a: [Int], _ b: [Int]) -> Int? {
    let n = min(a.count, b.count)
    for index in 0..<n where a[index] != b[index] {
        return index
    }
    if a.count != b.count { return n }
    return nil
}

/// Detect a non-canonical or wordlist-mismatched BIP-39 mnemonic, mirroring
/// `Unicode.Security.Crypto.Bip39Canonical.detect`.
public func bip39CanonicalDetect(_ input: [Int]) -> Bip39CanonicalResult {
    let canonical = bip39CanonicalForm(input)
    let words = bip39SplitWords(canonical)

    let trailingCount = bip39CountTrailingWhitespace(input)
    let uppercasePos = bip39FirstUppercasePos(input)
    let whitespacePos = bip39FirstWhitespaceRunPos(input)

    let nfkd = toNfkd(input)
    let nonNfkdPos = input == nfkd ? nil : bip39FirstArrayDivergence(input, nfkd)

    let wordlistsPerWord = words.map { bip39WordlistsContaining($0) }
    let firstUnknownIdx = wordlistsPerWord.firstIndex { $0.isEmpty }

    let subThreat: String?
    let positions: [Int]
    var language = "english"

    if trailingCount > 0 {
        subThreat = "TrailingWhitespace"
        positions = [input.count - trailingCount]
    } else if let uppercasePos {
        subThreat = "MixedCase"
        positions = [uppercasePos]
    } else if let whitespacePos {
        subThreat = "WhitespaceAnomaly"
        positions = [whitespacePos]
    } else if let nonNfkdPos {
        subThreat = "NonNFKD"
        positions = [nonNfkdPos]
    } else if let firstUnknownIdx {
        subThreat = "WordlistMismatch"
        positions = [firstUnknownIdx]
    } else if let unique = bip39UniqueLanguage(words) {
        subThreat = nil
        positions = []
        language = unique
    } else {
        subThreat = "LanguageAmbiguous"
        positions = []
    }

    return Bip39CanonicalResult(
        subThreat: subThreat,
        positions: positions,
        language: language,
        canonical: canonical,
        wordCount: words.count
    )
}

private func confusablesMap() -> [Int: [Int]] {
    if let cached = confusablesMapCache { return cached }
    let parsed = parseConfusables(readDataFile("confusables.txt"))
    confusablesMapCache = parsed
    return parsed
}

private func caseFoldingMap() -> [Int: [Int]] {
    if let cached = caseFoldingCache { return cached }
    let parsed = parseCaseFolding(readDataFile("CaseFolding.txt"))
    caseFoldingCache = parsed
    return parsed
}

// Strong Bidi_Class lookup, mirroring Unicode.Generated.DerivedBidiClass.lookup:
// an explicit range wins; otherwise the last matching @missing default range
// wins; otherwise the codepoint is L. Only the strong distinction (R, AL, L) is
// retained — every other Bidi_Class collapses to Other.
private enum BidiStrong: Equatable {
    case r
    case al
    case l
    case other
}

private struct BidiRange {
    let lo: Int
    let hi: Int
    let cls: BidiStrong
}

// Explicit ranges (sorted by lower bound) and @missing default ranges (in file
// order; the last match wins), parsed from DerivedBidiClass.txt.
private struct BidiTable {
    let explicit: [BidiRange]
    let defaults: [BidiRange]
}

private func strongOfShort(_ token: String) -> BidiStrong {
    switch token {
    case "R": return .r
    case "AL": return .al
    case "L": return .l
    default: return .other
    }
}

private func strongOfLong(_ token: String) -> BidiStrong {
    switch token {
    case "Right_To_Left": return .r
    case "Arabic_Letter": return .al
    case "Left_To_Right": return .l
    default: return .other
    }
}

// Parse "LO..HI" or a single "CP" into an inclusive (lo, hi) pair.
private func parseBidiRangeField(_ field: String) -> (Int, Int)? {
    let s = field.trimmingCharacters(in: .whitespaces)
    if let dots = s.range(of: "..") {
        guard let a = parseHex(String(s[s.startIndex..<dots.lowerBound])),
              let b = parseHex(String(s[dots.upperBound...])) else { return nil }
        return (a, b)
    }
    guard let a = parseHex(s) else { return nil }
    return (a, a)
}

// Explicit ranges come from DATA lines "LO..HI ; SHORT # ..." or "CP ; SHORT #
// ..."; default ranges come from comment lines "# @missing: LO..HI; Long_Name".
private func parseDerivedBidi(_ raw: String) -> BidiTable {
    let missingPrefix = "# @missing:"
    var explicit: [BidiRange] = []
    var defaults: [BidiRange] = []
    for line in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        if line.hasPrefix(missingPrefix) {
            let rest = line.dropFirst(missingPrefix.count)
            let parts = rest.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)
            if parts.count == 2, let (lo, hi) = parseBidiRangeField(String(parts[0])) {
                defaults.append(BidiRange(lo: lo, hi: hi, cls: strongOfLong(parts[1].trimmingCharacters(in: .whitespaces))))
            }
            continue
        }
        let body = line.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0].trimmingCharacters(in: .whitespaces)
        if body.isEmpty { continue }
        let fields = body.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)
        if fields.count == 2, let (lo, hi) = parseBidiRangeField(String(fields[0])) {
            explicit.append(BidiRange(lo: lo, hi: hi, cls: strongOfShort(fields[1].trimmingCharacters(in: .whitespaces))))
        }
    }
    explicit.sort { $0.lo < $1.lo }
    return BidiTable(explicit: explicit, defaults: defaults)
}

private func bidiTable() -> BidiTable {
    if let cached = bidiTableCache { return cached }
    let parsed = parseDerivedBidi(readDataFile("DerivedBidiClass.txt"))
    bidiTableCache = parsed
    return parsed
}

// Full Bidi_Class lookup (strong distinction only): binary-search the sorted
// explicit ranges first, then the last matching @missing default, then L.
private func bidiStrong(_ cp: Int) -> BidiStrong {
    let table = bidiTable()
    var lo = 0
    var hi = table.explicit.count
    while lo < hi {
        let mid = lo + (hi - lo) / 2
        let range = table.explicit[mid]
        if cp < range.lo {
            hi = mid
        } else if cp > range.hi {
            lo = mid + 1
        } else {
            return range.cls
        }
    }
    var result: BidiStrong = .l
    for range in table.defaults where range.lo <= cp && cp <= range.hi {
        result = range.cls
    }
    return result
}

private func isStrongRtl(_ cp: Int) -> Bool {
    let strong = bidiStrong(cp)
    return strong == .r || strong == .al
}

private func isStrongLtr(_ cp: Int) -> Bool {
    bidiStrong(cp) == .l
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

private func parseCaseFolding(_ raw: String) -> [Int: [Int]] {
    var out: [Int: [Int]] = [:]
    for rawLine in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        let body = rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0].trimmingCharacters(in: .whitespaces)
        if body.isEmpty { continue }
        let fields = body.split(separator: ";", omittingEmptySubsequences: false)
        if fields.count < 3 { continue }
        let status = fields[1].trimmingCharacters(in: .whitespaces)
        if status != "C" && status != "F" { continue }
        if let cp = parseHex(String(fields[0])) {
            let mapping = parseCodepointField(String(fields[2]))
            if !mapping.isEmpty { out[cp] = mapping }
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

// Self-contained SHA-256 (FIPS 180-4). The Swift port ships without an external
// crypto dependency (CryptoKit is Apple-only; the port must stay self-contained),
// so integrity verification uses this pure implementation. Correctness is
// self-checking: a wrong implementation would not reproduce the pinned digest of
// the shipped data and the port's own test would fail closed.
private enum Sha256 {
    private static let k: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    private static func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }

    static func hexDigest(_ message: [UInt8]) -> String {
        var h: [UInt32] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ]
        var msg = message
        let bitLen = UInt64(message.count) &* 8
        msg.append(0x80)
        while msg.count % 64 != 56 { msg.append(0) }
        for i in (0..<8).reversed() {
            msg.append(UInt8((bitLen >> (UInt64(i) &* 8)) & 0xff))
        }
        var w = [UInt32](repeating: 0, count: 64)
        var chunkStart = 0
        while chunkStart < msg.count {
            for i in 0..<16 {
                let j = chunkStart + i * 4
                w[i] = (UInt32(msg[j]) << 24) | (UInt32(msg[j + 1]) << 16)
                    | (UInt32(msg[j + 2]) << 8) | UInt32(msg[j + 3])
            }
            for i in 16..<64 {
                let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
                let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
                w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
            }
            var a = h[0], b = h[1], c = h[2], d = h[3]
            var e = h[4], f = h[5], g = h[6], hh = h[7]
            for i in 0..<64 {
                let bigS1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
                let ch = (e & f) ^ (~e & g)
                let temp1 = hh &+ bigS1 &+ ch &+ k[i] &+ w[i]
                let bigS0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let temp2 = bigS0 &+ maj
                hh = g; g = f; f = e; e = d &+ temp1
                d = c; c = b; b = a; a = temp1 &+ temp2
            }
            h[0] = h[0] &+ a; h[1] = h[1] &+ b; h[2] = h[2] &+ c; h[3] = h[3] &+ d
            h[4] = h[4] &+ e; h[5] = h[5] &+ f; h[6] = h[6] &+ g; h[7] = h[7] &+ hh
            chunkStart += 64
        }
        return h.map { String(format: "%08x", $0) }.joined()
    }
}

// Pinned SHA-256 digests of the vendored UCD-derived tables, embedded as code
// constants so the code — not the co-located, swappable SHA256SUMS — is the trust
// anchor. readDataFile hashes each table's raw bytes at load and refuses to serve
// (aborts) on any mismatch or unpinned table, so a rolled-back, corrupted, or
// tampered resource on a deployed node fails closed instead of silently
// mis-classifying. Keep in sync with the port resources' SHA256SUMS and the
// canonical data/SHA256SUMS.
private let pinnedTableDigests: [String: String] = [
    "CaseFolding.txt": "ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183",
    "confusables.txt": "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a",
    "KnownAttackTargets.txt": "47acf87f48e23c2e3ddfb5aed877965fbe29142e61f6f85c4ee7db90c0684947",
    "StandardizedVariants.txt": "f55100b2fb11d3d75a37b8c1ab752192dbd1c4b12328c5ec6b38e3807c0ca597",
    "emoji-variation-sequences.txt": "bb3d09ef03f206012c7532dd52dc0a21c9efddba0135ea4cf0d9201b8b9bba7e",
    "DerivedBidiClass.txt": "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4",
    "UnicodeData.txt": "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c",
    "CompositionExclusions.txt": "2f239196ef3b5b61db5cc476e9bd80f534d15aa1b74e1be1dea5d042a344c85f",
    "DerivedCoreProperties.txt": "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08",
    "SpecialCasing.txt": "efc25faf19de21b92c1194c111c932e03d2a5eaf18194e33f1156e96de4c9588",
    "emoji-data.txt": "2cb2bb9455cda83e8481541ecf5b6dfda66a3bb89efa3fa7c5297eccf607b72b",
    "emoji-zwj-sequences.txt": "5b25441daed2322b068c5e70cda522946a4f0274df864445a1965a92e5fc5cad",
    "bip39/chinese_simplified.txt": "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726",
    "bip39/chinese_traditional.txt": "417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f",
    "bip39/czech.txt": "7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc",
    "bip39/english.txt": "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
    "bip39/french.txt": "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59",
    "bip39/italian.txt": "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2",
    "bip39/japanese.txt": "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd",
    "bip39/korean.txt": "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60",
    "bip39/portuguese.txt": "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f",
    "bip39/spanish.txt": "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b",
]

// Resolve a pinned data table inside the module bundle. A subdirectory-qualified
// pinned name (e.g. "bip39/english.txt") is looked up by its basename, which
// covers a flattened resource layout; the recursive scan fallback covers a layout
// that instead preserves the Data/… subtree. Basenames are unique across the
// pinned set, so a basename match is unambiguous.
private func locateDataResource(_ name: String) -> URL? {
    let resourceName = name.split(separator: "/").last.map(String.init) ?? name
    if let url = Bundle.module.url(forResource: resourceName, withExtension: nil) {
        return url
    }
    guard let root = Bundle.module.resourceURL,
        let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)
    else {
        return nil
    }
    for case let candidate as URL in walker where candidate.lastPathComponent == resourceName {
        return candidate
    }
    return nil
}

private func readDataFile(_ name: String) -> String {
    guard let expected = pinnedTableDigests[name] else {
        fatalError("refusing to load unpinned data table: \(name) (fail closed)")
    }
    guard let url = locateDataResource(name) else {
        fatalError("missing Swift runtime data file: \(name)")
    }
    guard let bytes = try? Data(contentsOf: url) else {
        fatalError("cannot read Swift runtime data file: \(name)")
    }
    let actual = Sha256.hexDigest([UInt8](bytes))
    guard actual == expected else {
        fatalError(
            "data table \(name) failed integrity check (expected \(expected), got \(actual)); "
                + "refusing to load (fail closed)")
    }
    guard let contents = String(data: bytes, encoding: .utf8) else {
        fatalError("cannot decode Swift runtime data file: \(name)")
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

// The specific script-collision sub-threat, matching the Lean source of truth:
// Latin/Cyrillic and Latin/Greek are named explicitly (Cyrillic before Greek);
// every other multi-script mix is ScriptMixOther.
private func mixedScriptSubThreat(_ input: [Int]) -> String {
    let seen = Set(input.compactMap(scriptClass))
    if seen.contains("Latn") && seen.contains("Cyrl") {
        return "LatinCyrillic"
    }
    if seen.contains("Latn") && seen.contains("Grek") {
        return "LatinGreek"
    }
    return "ScriptMixOther"
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

// Surrogate-reassembly / malformed-byte-stream detection (layer C). A direct
// port of Unicode.Security.Covert.SurrogateReassembly. The codepoint list
// is treated as a byte stream, one octet per entry; the family only applies when
// every entry is a byte (< 0x100), matching the looksLikeByteStream gate. When
// the stream is not well-formed UTF-8 under the shared strict decoder, the first
// violation is projected onto a covert-layer sub-threat at its byte offset. An
// adversary hides intent in a byte stream that is not valid UTF-8 — an overlong
// encoding, a CESU-8 / surrogate codepoint, a truncated sequence, an invalid
// start or continuation byte, or a value beyond U+10FFFF — betting a lenient
// decoder will "reassemble" it into something the scanner never saw in codepoint
// form.
// Module-faithful detect, mirroring the Lean module
// SurrogateReassembly.detect. Any value > 0xFF is clamped to 0xFF (never a valid
// UTF-8 start byte), exactly as the Lean toBytes helper does, so out-of-range
// values surface as a malformed stream rather than being dropped. The
// byte-stream gate lives in the scan orchestrator (looksLikeByteStream),
// mirroring runAll.
private func surrogateReassemblyDetect(_ input: [Int]) -> (sub: String, positions: [Int])? {
    let bytes = input.map { UInt8($0 > 0xFF ? 0xFF : $0) }
    guard let failure = firstInvalidUtf8(bytes) else { return nil }
    return (surrogateReassemblySubThreat(failure.subThreat), [failure.offset])
}

// The looksLikeByteStream gate from Unicode.Security.RunAll: a
// codepoint-array input containing any value >= 0x100 is not a byte stream; the
// scan orchestrator uses this to skip the family on such inputs, exactly as
// runAll does.
private func looksLikeByteStream(_ input: [Int]) -> Bool {
    input.allSatisfy { $0 < 0x100 }
}

// Scan-orchestrator wrapper. Mirrors runAll: SurrogateReassembly only applies to
// byte-stream input (every codepoint <= 0xFF); on codepoint-array input the
// family is clear.
private func surrogateReassemblyFinding(_ input: [Int]) -> Finding? {
    guard looksLikeByteStream(input) else { return nil }
    guard let detection = surrogateReassemblyDetect(input) else { return nil }
    return makeFinding(
        family: Family.surrogateReassembly,
        subThreat: detection.sub,
        positions: detection.positions
    )
}

// Project a strict UTF-8 reject kind onto its surrogate-reassembly sub-threat,
// mirroring subThreatOfRejectKind in the Lean spec. These tags are deliberately
// distinct from the malformed-utf8 decode tags carried by firstInvalidUtf8.
private func surrogateReassemblySubThreat(_ rejectKind: String) -> String {
    switch rejectKind {
    case "OverlongEncoding": return "Overlong"
    case "SurrogateCodepoint": return "Cesu8"
    case "TruncatedSequence": return "Truncated"
    case "InvalidStartByte": return "InvalidStartByte"
    case "InvalidContinuationByte": return "InvalidContinuation"
    case "CodepointBeyondMax": return "CodepointBeyondMax"
    default: return rejectKind
    }
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

// ─────────────────────────────────────────────────────────────────────
// Normalization-bomb detector (form layer), mirroring
// Unicode.Security.Form.NormalizationBomb.
//
// Inputs whose NFD or NFKD expansion exceeds documented bounds — the
// classic normalization-expansion DoS, where a small input expands to a
// very large normalized form (Arabic ligature U+FDFA -> 18 codepoints
// under NFKD). Three priority-ordered checks: a per-codepoint blow-up
// scan, an overall NFKD ratio, an overall NFD ratio. Ratios are expressed
// in hundredths to avoid floats.
// ─────────────────────────────────────────────────────────────────────

/// Maximum allowed NFKD expansion per single codepoint. Hangul <= 3, Greek
/// extended forms 4, the largest non-FDFA Arabic ligature (FDFB) 8;
/// anything greater than 8 is flagged.
private let maxNfkdPerCp = 8

/// Overall-sequence NFD expansion ratio threshold, in hundredths (300 =
/// 3x). Pure Hangul sits at exactly 300 and stays clear under strict `>`.
private let nfdRatioThresholdPct = 300

/// Overall-sequence NFKD expansion ratio threshold, in hundredths (400 =
/// 4x).
private let nfkdRatioThresholdPct = 400

public struct NormalizationBombResult: Equatable {
    public let subThreat: String?
    public let positions: [Int]
}

/// First input position whose single-codepoint NFKD expansion exceeds
/// `maxNfkdPerCp`, or `nil` when no codepoint blows up.
private func firstBlowupCp(_ input: [Int]) -> Int? {
    for index in input.indices {
        if toNfkd([input[index]]).count > maxNfkdPerCp { return index }
    }
    return nil
}

/// NFD ratio percentage (`100 * nfdLen / inputLen`); 0 on empty input.
private func nfdRatioPct(_ input: [Int]) -> Int {
    if input.isEmpty { return 0 }
    return toNfdCodepoints(input).count * 100 / input.count
}

/// NFKD ratio percentage (`100 * nfkdLen / inputLen`); 0 on empty input.
private func nfkdRatioPct(_ input: [Int]) -> Int {
    if input.isEmpty { return 0 }
    return toNfkd(input).count * 100 / input.count
}

/// Detect a normalization-expansion bomb. Priority: per-codepoint blow-up,
/// then overall NFKD ratio, then overall NFD ratio.
public func normalizationBombDetect(_ input: [Int]) -> NormalizationBombResult {
    if let pos = firstBlowupCp(input) {
        return NormalizationBombResult(subThreat: "SingleCpBlowup", positions: [pos])
    }
    if nfkdRatioPct(input) > nfkdRatioThresholdPct {
        return NormalizationBombResult(subThreat: "NfkdHighExpansion", positions: [])
    }
    if nfdRatioPct(input) > nfdRatioThresholdPct {
        return NormalizationBombResult(subThreat: "NfdHighExpansion", positions: [])
    }
    return NormalizationBombResult(subThreat: nil, positions: [])
}

// ─────────────────────────────────────────────────────────────────────
// NFC-idempotence-witness detection — inputs that are not already in NFC
// (or, failing that, not in NFKC), the silent normalization-drift class
// where a signer and verifier pick different canonical forms and their
// hashes diverge.
//
// Direct port of `Unicode/Security/Form/NfcIdempotenceWitness.lean`.
// Compares `input` element-wise against `toNfc(input)` and `toNfkc(input)`,
// reporting the first divergent position: a mismatch against NFC is
// `NonNfcForm`; a sequence already in NFC but not NFKC is
// `NonNfkcCompatForm`.
// ─────────────────────────────────────────────────────────────────────

/// One NFC-idempotence-witness scan result. `subThreat` is `nil` for a clear
/// input (already in NFC and NFKC), else the divergence tag with its first
/// position.
public struct NfcIdempotenceWitnessResult: Equatable {
    /// The sub-threat tag, or `nil` when the input is already NFC- and NFKC-stable.
    public let subThreat: String?
    /// The first divergent position (empty when clear).
    public let positions: [Int]
}

/// First index at which two sequences diverge (in element, or one ends);
/// `nil` when identical.
private func firstDivergence(_ a: [Int], _ b: [Int]) -> Int? {
    let common = min(a.count, b.count)
    for i in 0..<common {
        if a[i] != b[i] { return i }
    }
    if a.count != b.count { return common }
    return nil
}

/// Detect an input that is not in canonical (NFC), or not in compatibility
/// (NFKC), form. NFC divergence takes priority over NFKC.
public func nfcIdempotenceWitnessDetect(_ input: [Int]) -> NfcIdempotenceWitnessResult {
    let nfc = toNfc(input)
    if let pos = firstDivergence(input, nfc) {
        return NfcIdempotenceWitnessResult(subThreat: "NonNfcForm", positions: [pos])
    }
    let nfkc = toNfkc(input)
    if let pos = firstDivergence(input, nfkc) {
        return NfcIdempotenceWitnessResult(subThreat: "NonNfkcCompatForm", positions: [pos])
    }
    return NfcIdempotenceWitnessResult(subThreat: nil, positions: [])
}

// MARK: - Byte-layer refinements

/// Opaque-blob predicate: structurally valid UTF-8. Named so the "blob" framing
/// — no character-class hardening — is explicit at the call site.
public func isUtf8Blob(_ data: [UInt8]) -> Bool {
    return firstInvalidUtf8(data) == nil
}

/// A byte sequence carrying its size bound and UTF-8 validity claim. Construct
/// via `Utf8Blob.of(_:maxBytes:)`. No character-class filtering beyond UTF-8
/// validity; hardened profiles layer on top of this predicate.
public struct Utf8Blob {
    public let value: [UInt8]
    public let maxBytes: Int

    private init(value: [UInt8], maxBytes: Int) {
        self.value = value
        self.maxBytes = maxBytes
    }

    /// Build a `Utf8Blob` under the size bound `maxBytes`. Returns `nil` when
    /// either the bound or UTF-8 validity is violated.
    public static func of(_ data: [UInt8], maxBytes: Int) -> Utf8Blob? {
        if data.count > maxBytes {
            return nil
        }
        if !isUtf8Blob(data) {
            return nil
        }
        return Utf8Blob(value: data, maxBytes: maxBytes)
    }
}

/// Refinement type for bytes validated as strict RFC 3629 UTF-8. The validity
/// claim is pinned at the module boundary: the only way to build one is via
/// `validate(_:)`, which routes through the strict decoder. A consumer that
/// wants the raw bytes calls `unwrap(_:)`.
public struct ValidatedUtf8 {
    private let bytes: [UInt8]

    private init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    /// Validate `data` and, on success, return a `ValidatedUtf8` carrying the
    /// RFC 3629 validity claim. Returns `nil` when the bytes fail the strict
    /// state machine.
    public static func validate(_ data: [UInt8]) -> ValidatedUtf8? {
        if firstInvalidUtf8(data) != nil {
            return nil
        }
        return ValidatedUtf8(bytes: data)
    }

    /// Borrow the validated bytes.
    public func asBytes() -> [UInt8] {
        return bytes
    }

    /// Consume the validity claim, returning the underlying bytes.
    public static func unwrap(_ validated: ValidatedUtf8) -> [UInt8] {
        return validated.bytes
    }
}

// ─────────────────────────────────────────────────────────────────────
// hash-input-stability — detection of inputs that are not in canonical
// hash-input form. Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an input
// hashed by a signer must be byte-identical to the input hashed by the
// verifier; if the two ends pick different canonical forms (NFC vs NFD, trim
// policy, line-ending convention) the resulting hashes diverge silently while
// both sides believe they signed the same content.
//
// Direct port of `Unicode/Security/Crypto/HashInputStability.lean`, mirroring
// the verified Rust reference. The canonical (hash-stable) form is
// `trimTrailing(toNfc(input))`, where `trimTrailing` strips only ASCII
// whitespace {U+0020, U+0009, U+000A, U+000D}; Unicode whitespace (U+00A0,
// U+2000..U+200A, U+3000) is content and is not stripped. NFC is the port's
// `toNfc`, never a host normaliser.
//
// Six probes run in strict priority order (first hit wins):
//
//   1. encodingMismatch         (context: declaredEncoding)
//   2. webhookSignatureDrift    (context: serverBytes)
//   3. auditLogReinterpretation (context: asWritten)
//   4. signedMessageRule        (context: rfcRule)
//   5. trailingWhitespace       (bare input)
//   6. normalizationDrift       (bare input)
//   7. clear
//
// Context-specific probes fire first because they carry more precise threat
// information than the generic probes. `hashInputStabilityDetect` is the
// convenience wrapper `hashInputStabilityDetectWithContext(.default, input)`
// that leaves the four context-bearing probes silent.
// ─────────────────────────────────────────────────────────────────────

/// RFC canonicalisation profiles that the `signedMessageRule` probe checks
/// against. Each case names a specific canonicalisation rule from a published
/// RFC; callers pass one as `Context.rfcRule` to opt the probe in.
public enum RfcRule: Equatable {
    /// RFC 4880 §5.2.4 — detached signatures normalise trailing whitespace.
    case pgp4880TrailingWhitespace
    /// RFC 9580 (current OpenPGP) — line-endings normalise to CRLF before signing.
    case pgp9580LineEnding
    /// RFC 8785 §3.2.5 — JSON Canonicalization Scheme requires NFC strings.
    case rfc8785NfcRequirement
    /// RFC 8259 §7 — JSON strings must escape control characters (U+0000..U+001F).
    case rfc8259ControlChar
    /// RFC 7515 §2 — JWS Base64URL; any char outside `[A-Za-z0-9_-]` violates.
    case rfc7515JwsBase64Url
    /// RFC 6376 §3.4.4 — DKIM relaxed body canonicalization collapses whitespace runs.
    case rfc6376DkimRelaxed
    /// RFC 5751 §3.1.1 — S/MIME canonical text; a bare LF or bare CR violates.
    case rfc5751SmimeLineEnding

    /// Fixture-string identifier for an `RfcRule` — used by the conformance
    /// harness's attribution parser to round-trip rule selections.
    public var tag: String {
        switch self {
        case .pgp4880TrailingWhitespace: return "pgp4880TrailingWhitespace"
        case .pgp9580LineEnding: return "pgp9580LineEnding"
        case .rfc8785NfcRequirement: return "rfc8785NfcRequirement"
        case .rfc8259ControlChar: return "rfc8259ControlChar"
        case .rfc7515JwsBase64Url: return "rfc7515JwsBase64Url"
        case .rfc6376DkimRelaxed: return "rfc6376DkimRelaxed"
        case .rfc5751SmimeLineEnding: return "rfc5751SmimeLineEnding"
        }
    }

    /// Inverse of `tag`. Returns `nil` for unrecognised strings.
    public static func fromTag(_ tag: String) -> RfcRule? {
        switch tag {
        case "pgp4880TrailingWhitespace": return .pgp4880TrailingWhitespace
        case "pgp9580LineEnding": return .pgp9580LineEnding
        case "rfc8785NfcRequirement": return .rfc8785NfcRequirement
        case "rfc8259ControlChar": return .rfc8259ControlChar
        case "rfc7515JwsBase64Url": return .rfc7515JwsBase64Url
        case "rfc6376DkimRelaxed": return .rfc6376DkimRelaxed
        case "rfc5751SmimeLineEnding": return .rfc5751SmimeLineEnding
        default: return nil
        }
    }
}

/// Sub-threats this detector can fire. Two probes fire from the raw input alone
/// (`trailingWhitespace`, `normalizationDrift`); the other four require the
/// corresponding `Context` field to be set.
public enum HashInputStabilitySubThreat: Equatable {
    /// Input diverges from its NFC form at `firstDivergentPos`.
    case normalizationDrift(firstDivergentPos: Int)
    /// Input has `count` trailing ASCII-whitespace codepoints.
    case trailingWhitespace(count: Int)
    /// Declared encoding disagrees with the codepoint array (or the array holds
    /// an invalid scalar).
    case encodingMismatch(declaredEnc: String, detectedEnc: String)
    /// Input violates the named RFC's canonicalisation rule at `firstPos`.
    case signedMessageRule(rfcRule: String, firstPos: Int)
    /// The re-read input differs from `Context.asWritten` at `firstDivergentPos`.
    case auditLogReinterpretation(firstDivergentPos: Int)
    /// The client input differs from `Context.serverBytes` at `firstPos`.
    case webhookSignatureDrift(firstPos: Int)

    /// Human-facing classification tag for this sub-threat.
    public var tag: String {
        switch self {
        case .normalizationDrift: return "NormalizationDrift"
        case .trailingWhitespace: return "TrailingWhitespace"
        case .encodingMismatch: return "EncodingMismatch"
        case .signedMessageRule: return "SignedMessageRule"
        case .auditLogReinterpretation: return "AuditLogReinterpretation"
        case .webhookSignatureDrift: return "WebhookSignatureDrift"
        }
    }
}

/// Context passed to `hashInputStabilityDetectWithContext` to enable the four
/// context-bearing probes. Each field is `nil` by default — the empty context
/// is the identity case: `hashInputStabilityDetectWithContext(.default, input)`
/// equals `hashInputStabilityDetect(input)`.
public struct HashInputStabilityContext: Equatable {
    /// The encoding label the caller claims their input is in. When set and not
    /// (case-insensitively) UTF-8, fires `encodingMismatch` immediately.
    public var declaredEncoding: String?
    /// The RFC canonicalisation rule the caller is operating under. When set,
    /// scans `input` for violations and fires `signedMessageRule`.
    public var rfcRule: RfcRule?
    /// The original "as-written" form of an audit-log entry whose re-read is
    /// `input`. When set, fires `auditLogReinterpretation` on first divergence.
    public var asWritten: [Int]?
    /// The server-side recomputed bytes for a webhook signature. When set, fires
    /// `webhookSignatureDrift` on first divergence against `input`.
    public var serverBytes: [Int]?

    public init(
        declaredEncoding: String? = nil,
        rfcRule: RfcRule? = nil,
        asWritten: [Int]? = nil,
        serverBytes: [Int]? = nil
    ) {
        self.declaredEncoding = declaredEncoding
        self.rfcRule = rfcRule
        self.asWritten = asWritten
        self.serverBytes = serverBytes
    }

    /// The empty context: all probes silent.
    public static let `default` = HashInputStabilityContext()
}

/// Top-level classification.
public enum HashInputStabilityClassification: Equatable {
    /// The input is already hash-stable under every enabled probe.
    case clear
    /// A hazard was found: the sub-threat and its implicated positions.
    case hazard(sub: HashInputStabilitySubThreat, positions: [Int])

    /// True iff the input is clear.
    public var isClear: Bool {
        switch self {
        case .clear: return true
        case .hazard: return false
        }
    }

    /// Human-facing tag for a hazard, or `nil` when clear.
    public var tag: String? {
        switch self {
        case .clear: return nil
        case .hazard(let sub, _): return sub.tag
        }
    }

    /// Implicated positions (empty when clear).
    public var positions: [Int] {
        switch self {
        case .clear: return []
        case .hazard(_, let positions): return positions
        }
    }
}

/// Verdict — the structured output of `hashInputStabilityDetect`. `stableSize`
/// is the codepoint count of the hash-stable canonical form; downstream callers
/// compare it against `input.count` to size the byte-drift their hash sees.
public struct HashInputStabilityVerdict: Equatable {
    /// The scanned input codepoints.
    public let input: [Int]
    /// The classification verdict.
    public let classify: HashInputStabilityClassification
    /// The hash-stable canonical form of the input.
    public let stableForm: [Int]
    /// Codepoint count of `stableForm`.
    public let stableSize: Int
}

// §3 Canonicalisation pipeline.

/// True iff `cp` is an ASCII whitespace codepoint that line-oriented hash-input
/// protocols treat as framing rather than content: U+0020 SPACE, U+0009 TAB,
/// U+000A LF, U+000D CR.
private func hisIsAsciiWhitespace(_ cp: Int) -> Bool {
    cp == 0x0020 || cp == 0x0009 || cp == 0x000A || cp == 0x000D
}

/// Count of trailing ASCII whitespace codepoints in `input`.
private func hisCountTrailingWhitespace(_ input: [Int]) -> Int {
    var count = 0
    for cp in input.reversed() {
        if hisIsAsciiWhitespace(cp) { count += 1 } else { break }
    }
    return count
}

/// Strip trailing ASCII whitespace.
private func hisTrimTrailing(_ input: [Int]) -> [Int] {
    let keep = input.count - hisCountTrailingWhitespace(input)
    return Array(input[0..<keep])
}

/// The hash-stable form of an input: NFC then trim, in spec order. Reuses the
/// port's `toNfc`, never a host normaliser.
public func hashInputStabilityHashStable(_ input: [Int]) -> [Int] {
    hisTrimTrailing(toNfc(input))
}

// §5 Priority position-finder.

/// First position at which `a` and `b` diverge, or the length of the shared
/// prefix when one strictly extends the other. `nil` when identical.
private func hisFirstArrayDivergence(_ a: [Int], _ b: [Int]) -> Int? {
    let common = min(a.count, b.count)
    for i in 0..<common where a[i] != b[i] {
        return i
    }
    if a.count != b.count {
        return common
    }
    return nil
}

// §6 Context-bearing probes.

/// Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A).
private func hisAsciiLower(_ cp: Int) -> Int {
    (cp >= 0x41 && cp <= 0x5A) ? cp + 0x20 : cp
}

/// True iff `label` (after ASCII case-fold) names UTF-8: accepts "utf-8",
/// "UTF-8", "UTF8", "utf8". Non-ASCII characters pass through unchanged.
private func hisIsUtf8Label(_ label: String) -> Bool {
    var normalised = String.UnicodeScalarView()
    for scalar in label.unicodeScalars {
        if let lowered = UnicodeScalar(hisAsciiLower(Int(scalar.value))) {
            normalised.append(lowered)
        } else {
            normalised.append(scalar)
        }
    }
    let text = String(normalised)
    return text == "utf-8" || text == "utf8"
}

/// True iff `cp` is a valid Unicode scalar value: in `[0, 0x10FFFF]` and not a
/// surrogate `[0xD800, 0xDFFF]`.
private func hisIsValidScalar(_ cp: Int) -> Bool {
    cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF)
}

/// First position in `input` holding a codepoint that is not a valid Unicode
/// scalar, or `nil` if every codepoint is valid.
private func hisFirstInvalidScalar(_ input: [Int]) -> Int? {
    input.firstIndex { !hisIsValidScalar($0) }
}

/// Probe: `encodingMismatch`. Validity is dispatched first — an invalid scalar
/// fires with `detectedEnc = "invalid"` regardless of the declared label;
/// otherwise a non-UTF-8 label fires with `detectedEnc = "utf-8"` at position 0.
/// Returns `(declared, detected, firstPos)` when firing.
private func hisEncodingMismatchProbe(_ declared: String, _ input: [Int]) -> (String, String, Int)? {
    if let pos = hisFirstInvalidScalar(input) {
        return (declared, "invalid", pos)
    }
    if hisIsUtf8Label(declared) {
        return nil
    }
    return (declared, "utf-8", 0)
}

/// Probe: `signedMessageRule` for `pgp4880TrailingWhitespace`. Same condition as
/// `trailingWhitespace`; returns the first position of the trailing run.
private func hisPgp4880Violation(_ input: [Int]) -> Int? {
    let trailing = hisCountTrailingWhitespace(input)
    if trailing > 0 {
        return input.count - trailing
    }
    return nil
}

/// Probe: `signedMessageRule` for `pgp9580LineEnding`. First bare LF (U+000A not
/// preceded by CR) or bare CR (U+000D not followed by LF).
private func hisPgp9580Violation(_ input: [Int]) -> Int? {
    for i in input.indices {
        let cp = input[i]
        if cp == 0x000A {
            // LF: violating iff not preceded by CR.
            let precededByCr = i > 0 && input[i - 1] == 0x000D
            if !precededByCr { return i }
        } else if cp == 0x000D {
            // CR: violating iff not followed by LF.
            let followedByLf = i + 1 < input.count && input[i + 1] == 0x000A
            if !followedByLf { return i }
        }
    }
    return nil
}

/// Probe: `signedMessageRule` for `rfc8785NfcRequirement`. Same condition as
/// `normalizationDrift`; returns the first NFC divergence position.
private func hisRfc8785Violation(_ input: [Int]) -> Int? {
    let nfc = toNfc(input)
    if input == nfc {
        return nil
    }
    return hisFirstArrayDivergence(input, nfc)
}

/// Probe: `signedMessageRule` for `rfc8259ControlChar`. First C0 control
/// (U+0000..U+001F).
private func hisRfc8259Violation(_ input: [Int]) -> Int? {
    input.firstIndex { $0 <= 0x1F }
}

/// True iff `cp` is in the JWS Base64URL alphabet `[A-Za-z0-9_-]`.
private func hisIsBase64Url(_ cp: Int) -> Bool {
    (cp >= 0x41 && cp <= 0x5A)       // A-Z
        || (cp >= 0x61 && cp <= 0x7A) // a-z
        || (cp >= 0x30 && cp <= 0x39) // 0-9
        || cp == 0x2D                 // '-'
        || cp == 0x5F                 // LOW LINE
}

/// Probe: `signedMessageRule` for `rfc7515JwsBase64Url`. First codepoint outside
/// `[A-Za-z0-9_-]`.
private func hisRfc7515Violation(_ input: [Int]) -> Int? {
    input.firstIndex { !hisIsBase64Url($0) }
}

/// True iff `cp` is DKIM whitespace: U+0020 SPACE or U+0009 HTAB.
private func hisIsDkimWhitespace(_ cp: Int) -> Bool {
    cp == 0x20 || cp == 0x09
}

/// Probe: `signedMessageRule` for `rfc6376DkimRelaxed`. Position of the second
/// whitespace codepoint in the first internal whitespace run longer than one.
private func hisRfc6376Violation(_ input: [Int]) -> Int? {
    for i in input.indices {
        let cp = input[i]
        if hisIsDkimWhitespace(cp) && i > 0 && hisIsDkimWhitespace(input[i - 1]) {
            return i
        }
    }
    return nil
}

/// Probe: `signedMessageRule` for `rfc5751SmimeLineEnding`. Reuses the PGP 9580
/// bare-line-ending rule.
private func hisRfc5751Violation(_ input: [Int]) -> Int? {
    hisPgp9580Violation(input)
}

/// Dispatch the RFC-rule probe. First violation position, or `nil` if clean.
private func hisRfcRuleViolation(_ rule: RfcRule, _ input: [Int]) -> Int? {
    switch rule {
    case .pgp4880TrailingWhitespace: return hisPgp4880Violation(input)
    case .pgp9580LineEnding: return hisPgp9580Violation(input)
    case .rfc8785NfcRequirement: return hisRfc8785Violation(input)
    case .rfc8259ControlChar: return hisRfc8259Violation(input)
    case .rfc7515JwsBase64Url: return hisRfc7515Violation(input)
    case .rfc6376DkimRelaxed: return hisRfc6376Violation(input)
    case .rfc5751SmimeLineEnding: return hisRfc5751Violation(input)
    }
}

// §7 Top-level detection.

/// The priority resolver: first hit wins, in the spec's fixed order.
private func hisClassify(
    _ encodingHit: (String, String, Int)?,
    _ webhookHit: Int?,
    _ auditHit: Int?,
    _ rfcHit: (RfcRule, Int)?,
    _ trailingCount: Int,
    _ inputLen: Int,
    _ nonNfcPos: Int?
) -> HashInputStabilityClassification {
    if let (declared, detected, pos) = encodingHit {
        return .hazard(
            sub: .encodingMismatch(declaredEnc: declared, detectedEnc: detected),
            positions: [pos]
        )
    }
    if let pos = webhookHit {
        return .hazard(sub: .webhookSignatureDrift(firstPos: pos), positions: [pos])
    }
    if let pos = auditHit {
        return .hazard(sub: .auditLogReinterpretation(firstDivergentPos: pos), positions: [pos])
    }
    if let (rule, pos) = rfcHit {
        return .hazard(sub: .signedMessageRule(rfcRule: rule.tag, firstPos: pos), positions: [pos])
    }
    if trailingCount > 0 {
        let p = inputLen - trailingCount
        return .hazard(sub: .trailingWhitespace(count: trailingCount), positions: [p])
    }
    if let p = nonNfcPos {
        return .hazard(sub: .normalizationDrift(firstDivergentPos: p), positions: [p])
    }
    return .clear
}

/// The full detection function. Runs all six probes in priority order, with the
/// context-bearing probes ahead of the generic ones. Mirrors
/// `Unicode.Security.Crypto.HashInputStability.detectWithContext`.
public func hashInputStabilityDetectWithContext(
    _ ctx: HashInputStabilityContext,
    _ input: [Int]
) -> HashInputStabilityVerdict {
    let stable = hashInputStabilityHashStable(input)

    // Probe 1: encodingMismatch.
    let encodingHit: (String, String, Int)? = ctx.declaredEncoding.flatMap {
        hisEncodingMismatchProbe($0, input)
    }

    // Probe 2: webhookSignatureDrift.
    let webhookHit: Int? = ctx.serverBytes.flatMap { hisFirstArrayDivergence(input, $0) }

    // Probe 3: auditLogReinterpretation.
    let auditHit: Int? = ctx.asWritten.flatMap { hisFirstArrayDivergence($0, input) }

    // Probe 4: signedMessageRule.
    let rfcHit: (RfcRule, Int)? = ctx.rfcRule.flatMap { rule in
        hisRfcRuleViolation(rule, input).map { (rule, $0) }
    }

    // Probe 5: trailingWhitespace.
    let trailingCount = hisCountTrailingWhitespace(input)

    // Probe 6: normalizationDrift.
    let nfc = toNfc(input)
    let nonNfcPos: Int? = input == nfc ? nil : hisFirstArrayDivergence(input, nfc)

    let classification = hisClassify(
        encodingHit,
        webhookHit,
        auditHit,
        rfcHit,
        trailingCount,
        input.count,
        nonNfcPos
    )

    return HashInputStabilityVerdict(
        input: input,
        classify: classification,
        stableForm: stable,
        stableSize: stable.count
    )
}

/// Convenience wrapper over `hashInputStabilityDetectWithContext` with the empty
/// context — equivalent to running only the two bare-input probes
/// (`trailingWhitespace`, `normalizationDrift`). Mirrors
/// `Unicode.Security.Crypto.HashInputStability.detect`.
public func hashInputStabilityDetect(_ input: [Int]) -> HashInputStabilityVerdict {
    hashInputStabilityDetectWithContext(.default, input)
}

/// Stable reason code for a hash-input-stability sub-threat tag, routed through
/// the shared reason-code builder: `unicode.security.K.hash-input-stability.<tag>`.
public func hashInputStabilityReasonCode(_ subThreat: String) -> String {
    reasonCode(family: Family.hashInputStability, subThreat: subThreat)
}

// ─────────────────────────────────────────────────────────────────────
// ai-watermark-detectability — character-level detector for inputs carrying
// codepoint patterns consistent with a known AI watermark scheme. Answers the
// question: does this input contain markers attributable to a watermarking
// protocol?
//
// Direct port of `Unicode/Security/Crypto/AiWatermarkDetectability.lean`,
// mirroring the verified Rust reference. Threat model: a provenance-attribution
// attacker. An input either carries an AI provider's watermark codepoints (a
// legitimate provenance marker) or carries injected markers that impersonate a
// provider's scheme to discredit the content as AI-generated. Character-level
// detection alone cannot distinguish the two; the detector reports the matched
// scheme and leaves provider-specific authentication to downstream code.
//
// Probe inventory (priority order, first match wins):
//   1. adversarial              — NNBSP count >= 3 at arithmetic-progression positions.
//   2. gpt5ZwspModulo           — ZWSP count >= 3 at arithmetic-progression positions.
//   3. unknown                  — invisible markers from >= 2 distinct categories.
//   4. nnbspBoundary            — single-category NNBSP.
//   5. variationSelectorCarrier — VS NOT adjacent to an emoji codepoint.
//   6. zwjNonEmoji              — ZWJ NOT adjacent to an emoji codepoint.
//   7. smartQuoteAlternation    — paired curly quotes, no ASCII straight quotes.
//   8. emDashPattern            — em-dashes, no ASCII hyphen-minus.
//   9. statisticalTokenChoice   — input contains an AI-favored lexical pattern.
//  10. defaultIgnorableCarrier  — single-category residual Default_Ignorable.
//
// The Emoji property table is bundled in the port's own Resources/Data/emoji-data.txt
// (byte-identical to the UCD source the Lean spec cites); the adjacency probe
// parses the `Emoji` rows from it, never a host emoji library. The residual
// default-ignorable probe reuses the port's own `isDefaultIgnorableCodepoint`.
// ─────────────────────────────────────────────────────────────────────

// §1 Types.

/// The conceptual watermark cue class a sub-threat probes for. A codepoint-frequency
/// bias toward a pinned "green list" of tokens is `greenListBias`; a fixed-period or
/// carrier-byte channel surfacing a pseudorandom function is `pseudorandomSeq`; a
/// stylistic-distribution drift away from natural human writing is `semanticDrift`.
public enum AiWatermarkDetectabilityCueClass: Equatable {
    /// A codepoint-frequency bias toward a pinned "green list" of tokens.
    case greenListBias
    /// A fixed-period or carrier-byte channel surfacing a pseudorandom function.
    case pseudorandomSeq
    /// A stylistic-distribution drift away from natural human writing.
    case semanticDrift
}

/// Sub-threats this detector can fire. Each case has a corresponding probe in
/// `aiWatermarkDetectabilityDetectWithContext`; the payload carries the position
/// information the conformance harness's attribution column reads back.
public enum AiWatermarkDetectabilitySubThreat: Equatable {
    /// Single-category NNBSP (U+202F) markers; `markerCount` is how many.
    case nnbspBoundary(markerCount: Int)
    /// Variation selector(s) not adjacent to an emoji; `markerCount` is how many.
    case variationSelectorCarrier(markerCount: Int)
    /// ZWJ(s) not adjacent to an emoji; `markerCount` is how many.
    case zwjNonEmoji(markerCount: Int)
    /// Residual Default_Ignorable markers; `markerCount` is how many.
    case defaultIgnorableCarrier(markerCount: Int)
    /// ZWSP (U+200B) markers at arithmetic-progression positions; `firstPos`
    /// is the first ZWSP position.
    case gpt5ZwspModulo(firstPos: Int)
    /// Em-dash (U+2014) stylistic signature; `firstPos` is the first em-dash.
    case emDashPattern(firstPos: Int)
    /// Paired curly-quote stylistic signature; `firstPos` is the first quote.
    case smartQuoteAlternation(firstPos: Int)
    /// AI-favored lexical pattern hit; `firstPos` is the match start.
    case statisticalTokenChoice(firstPos: Int)
    /// Over-regular marker placement impersonating a scheme; `impersonatedScheme`
    /// names the surfaced scheme, `firstPos` the first marker position.
    case adversarial(impersonatedScheme: String, firstPos: Int)
    /// Multi-category invisible-marker mixing; `anomalyMarker` is the total
    /// invisible-marker count (attribution to a single scheme fails).
    case unknown(anomalyMarker: Int)

    /// Human-facing classification tag for this sub-threat.
    public var tag: String {
        switch self {
        case .nnbspBoundary: return "NnbspBoundary"
        case .variationSelectorCarrier: return "VariationSelectorCarrier"
        case .zwjNonEmoji: return "ZwjNonEmoji"
        case .defaultIgnorableCarrier: return "DefaultIgnorableCarrier"
        case .gpt5ZwspModulo: return "Gpt5ZwspModulo"
        case .emDashPattern: return "EmDashPattern"
        case .smartQuoteAlternation: return "SmartQuoteAlternation"
        case .statisticalTokenChoice: return "StatisticalTokenChoice"
        case .adversarial: return "Adversarial"
        case .unknown: return "Unknown"
        }
    }

    /// The conceptual watermark cue class this sub-threat probes for. Marker-encoded
    /// sub-threats route to `pseudorandomSeq`; vocabulary-bias to `greenListBias`;
    /// stylistic-distribution to `semanticDrift`; `unknown` (multi-category mixing)
    /// implicates no single scheme.
    public var cueClass: AiWatermarkDetectabilityCueClass? {
        switch self {
        case .nnbspBoundary, .variationSelectorCarrier, .zwjNonEmoji, .defaultIgnorableCarrier:
            return .pseudorandomSeq
        case .gpt5ZwspModulo: return .pseudorandomSeq
        case .emDashPattern: return .semanticDrift
        case .smartQuoteAlternation: return .semanticDrift
        case .statisticalTokenChoice: return .greenListBias
        case .adversarial: return .pseudorandomSeq
        case .unknown: return nil
        }
    }
}

/// Top-level AiWatermarkDetectability classification.
public enum AiWatermarkDetectabilityClassification: Equatable {
    /// No watermark marker detected (semantically `noWatermark`).
    case clear
    /// A hazard: the fired sub-threat plus the implicated marker positions.
    case hazard(sub: AiWatermarkDetectabilitySubThreat, positions: [Int])

    /// True iff no watermark marker was detected.
    public var isClear: Bool {
        switch self {
        case .clear: return true
        case .hazard: return false
        }
    }

    /// Human-facing tag for a hazard, or `nil` when clear.
    public var tag: String? {
        switch self {
        case .clear: return nil
        case .hazard(let sub, _): return sub.tag
        }
    }

    /// Implicated positions (empty when clear).
    public var positions: [Int] {
        switch self {
        case .clear: return []
        case .hazard(_, let positions): return positions
        }
    }
}

/// AiWatermarkDetectability verdict — the structured output of the detector.
/// `markerCount` is the count of codepoints matching the fired scheme's probe
/// (0 when clear).
public struct AiWatermarkDetectabilityVerdict: Equatable {
    /// The scanned input codepoints.
    public let input: [Int]
    /// The classification verdict.
    public let classify: AiWatermarkDetectabilityClassification
    /// Count of codepoints matching the fired scheme (0 when clear).
    public let markerCount: Int
}

/// Optional context for the modulo-probe tolerances. Each field controls how
/// strictly the corresponding probe checks its arithmetic-progression condition;
/// the defaults of `0` require exact equality of consecutive gaps.
public struct AiWatermarkDetectabilityContext: Equatable {
    /// ZWSP-modulo tolerance. `0` requires the ZWSP-position arithmetic
    /// progression to be exact. `k > 0` accepts position gaps within +/- k of the
    /// first gap, catching modulo schedules with light jitter.
    public var zwspModuloTolerance: Int
    /// NNBSP-arithmetic tolerance (the `adversarial` probe). Same semantic as
    /// `zwspModuloTolerance` but for the NNBSP positions.
    public var adversarialTolerance: Int

    public init(zwspModuloTolerance: Int = 0, adversarialTolerance: Int = 0) {
        self.zwspModuloTolerance = zwspModuloTolerance
        self.adversarialTolerance = adversarialTolerance
    }

    /// The empty context: exact-arithmetic settings (both tolerances `0`).
    public static let `default` = AiWatermarkDetectabilityContext()
}

// §2 Emoji property table (bundled Resources/Data/emoji-data.txt, Emoji rows).

/// The `Emoji` (`Emoji=Yes`) closed intervals from emoji-data.txt, parsed via the
/// port's shared `<range> ; <property>` reader and cached. Only rows whose property
/// is exactly `Emoji` are kept.
private func aiwmEmojiRanges() -> [(Int, Int)] {
    if let cached = emojiRangesCache { return cached }
    let parsed = parseDerivedProperty(readDataFile("emoji-data.txt"), "Emoji")
    emojiRangesCache = parsed
    return parsed
}

/// True iff `cp` has the `Emoji = Yes` property per emoji-data.txt.
private func aiwmIsEmoji(_ cp: Int) -> Bool {
    aiwmEmojiRanges().contains { $0.0 <= cp && cp <= $0.1 }
}

// §3 Codepoint probes.

/// True iff `cp` is U+202F NARROW NO-BREAK SPACE.
private func aiwmIsNnbsp(_ cp: Int) -> Bool {
    cp == 0x202F
}

/// True iff `cp` is U+200D ZERO WIDTH JOINER.
private func aiwmIsZwj(_ cp: Int) -> Bool {
    cp == 0x200D
}

/// True iff `cp` is a Variation Selector — the basic block U+FE00..U+FE0F
/// (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
private func aiwmIsVariationSelector(_ cp: Int) -> Bool {
    (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF)
}

/// True iff `cp` is U+200B ZERO WIDTH SPACE.
private func aiwmIsZwsp(_ cp: Int) -> Bool {
    cp == 0x200B
}

/// True iff `cp` is U+2014 EM DASH.
private func aiwmIsEmDash(_ cp: Int) -> Bool {
    cp == 0x2014
}

/// True iff `cp` is U+002D HYPHEN-MINUS (ASCII).
private func aiwmIsHyphenMinus(_ cp: Int) -> Bool {
    cp == 0x002D
}

/// True iff `cp` is one of the four "curly" quotation marks: U+2018 / U+2019
/// (single open/close) and U+201C / U+201D (double open/close).
private func aiwmIsCurlyQuote(_ cp: Int) -> Bool {
    cp == 0x2018 || cp == 0x2019 || cp == 0x201C || cp == 0x201D
}

/// True iff `cp` is an ASCII straight quote — U+0022 (double) or U+0027 (single).
private func aiwmIsStraightQuote(_ cp: Int) -> Bool {
    cp == 0x0022 || cp == 0x0027
}

/// True iff `input[i]` is adjacent (immediate predecessor OR immediate successor)
/// to an emoji codepoint. Two-sided check. Used by the VS and ZWJ probes to
/// exclude legitimate emoji-context occurrences.
private func aiwmIsAdjacentToEmoji(_ input: [Int], _ i: Int) -> Bool {
    let prevIsEmoji = (i > 0 && i - 1 < input.count) ? aiwmIsEmoji(input[i - 1]) : false
    let nextIsEmoji = (i + 1 < input.count) ? aiwmIsEmoji(input[i + 1]) : false
    return prevIsEmoji || nextIsEmoji
}

/// All positions in `input` matching predicate `p`.
private func aiwmAllPositions(_ p: (Int) -> Bool, _ input: [Int]) -> [Int] {
    input.indices.filter { p(input[$0]) }
}

/// True iff `positions` forms an arithmetic progression with all consecutive gaps
/// within `tolerance` of the first gap. Empty and singleton lists are vacuously
/// arithmetic. `positions` is assumed ascending (produced by `aiwmAllPositions`),
/// so gaps are non-negative.
private func aiwmPositionsAreArithmeticWithin(_ positions: [Int], _ tolerance: Int) -> Bool {
    if positions.count < 2 { return true }
    let firstGap = positions[1] - positions[0]
    for i in 0..<(positions.count - 1) {
        let gap = positions[i + 1] - positions[i]
        if !(gap <= firstGap + tolerance && firstGap <= gap + tolerance) { return false }
    }
    return true
}

/// First start-position at which `pattern` appears as a contiguous sub-slice of
/// `input`, or `nil` if absent.
private func aiwmContainsSublist(_ pattern: [Int], _ input: [Int]) -> Int? {
    if pattern.isEmpty || pattern.count > input.count { return nil }
    let maxStart = input.count - pattern.count
    for start in 0...maxStart where Array(input[start..<start + pattern.count]) == pattern {
        return start
    }
    return nil
}

/// The "AI-favored" lexical-pattern catalog (each word as its codepoint sequence),
/// transcribed verbatim from the pinned `aiFavoredVocabulary` literal in the Lean
/// spec (parsed from `Ucd/Security/AiFavoredVocabulary.txt` and drift-gated there
/// against a fresh parse).
private func aiwmAiFavoredVocabulary() -> [[Int]] {
    [
        [100, 101, 108, 118, 101],
        [100, 101, 108, 118, 105, 110, 103],
        [116, 97, 112, 101, 115, 116, 114, 121],
        [105, 110, 116, 114, 105, 99, 97, 116, 101],
        [110, 117, 97, 110, 99, 101, 100],
        [109, 111, 114, 101, 111, 118, 101, 114],
        [102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101],
        [114, 101, 97, 108, 109],
        [101, 108, 117, 99, 105, 100, 97, 116, 101],
        [115, 104, 111, 119, 99, 97, 115, 105, 110, 103],
        [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115],
        [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100],
        [112, 105, 118, 111, 116, 97, 108],
        [98, 111, 108, 115, 116, 101, 114],
        [109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100],
        [116, 101, 115, 116, 97, 109, 101, 110, 116],
        [102, 111, 115, 116, 101, 114],
        [104, 111, 108, 105, 115, 116, 105, 99],
        [112, 97, 114, 97, 100, 105, 103, 109],
        [116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101],
        [115, 112, 101, 97, 114, 104, 101, 97, 100],
        [109, 101, 116, 105, 99, 117, 108, 111, 117, 115],
        [109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121],
        [101, 109, 112, 111, 119, 101, 114],
        [101, 109, 112, 111, 119, 101, 114, 105, 110, 103],
        [112, 114, 111, 102, 111, 117, 110, 100],
        [112, 114, 111, 102, 111, 117, 110, 100, 108, 121],
        [99, 111, 109, 112, 101, 108, 108, 105, 110, 103],
        [99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101],
        [99, 114, 117, 99, 105, 97, 108],
        [100, 97, 117, 110, 116, 105, 110, 103],
        [114, 111, 98, 117, 115, 116],
        [115, 116, 114, 101, 97, 109, 108, 105, 110, 101],
        [101, 110, 114, 105, 99, 104],
        [101, 120, 101, 109, 112, 108, 105, 102, 121],
        [99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103],
        [100, 105, 115, 99, 101, 114, 110, 105, 110, 103],
        [109, 101, 115, 109, 101, 114, 105, 122, 101],
        [105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121],
        [105, 109, 98, 117, 101],
        [112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108, 101],
        [112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111, 108, 101],
        [105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111, 32, 110, 111, 116, 101],
        [105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103],
        [105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110],
        [105, 110, 32, 101, 115, 115, 101, 110, 99, 101],
        [100, 101, 108, 118, 101, 32, 105, 110, 116, 111],
        [100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111],
        [116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102],
        [114, 101, 97, 108, 109, 32, 111, 102],
    ]
}

// §4 Top-level detection.

/// The detection function. Runs every probe in the fixed priority order
/// (most-specific first); the first hit wins. See the module header for the probe
/// inventory and the ordering rationale. Mirrors
/// `Unicode.Security.Crypto.AiWatermarkDetectability.detectWithContext`.
public func aiWatermarkDetectabilityDetectWithContext(
    _ ctx: AiWatermarkDetectabilityContext,
    _ input: [Int]
) -> AiWatermarkDetectabilityVerdict {
    let nnbspPositions = aiwmAllPositions(aiwmIsNnbsp, input)
    let nnbspCount = nnbspPositions.count

    // Probe 1: adversarial — NNBSP too-regular.
    let adversarialFires = nnbspCount >= 3
        && aiwmPositionsAreArithmeticWithin(nnbspPositions, ctx.adversarialTolerance)

    // Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
    let zwspPositions = aiwmAllPositions(aiwmIsZwsp, input)
    let zwspCount = zwspPositions.count
    let zwspModuloFires = zwspCount >= 3
        && aiwmPositionsAreArithmeticWithin(zwspPositions, ctx.zwspModuloTolerance)

    let vsAllPos = aiwmAllPositions(aiwmIsVariationSelector, input)
    let vsNonEmojiPos = vsAllPos.filter { !aiwmIsAdjacentToEmoji(input, $0) }
    let vsNonEmojiCount = vsNonEmojiPos.count

    let zwjAllPos = aiwmAllPositions(aiwmIsZwj, input)
    let zwjNonEmojiPos = zwjAllPos.filter { !aiwmIsAdjacentToEmoji(input, $0) }
    let zwjNonEmojiCount = zwjNonEmojiPos.count

    // Probe 7: smartQuoteAlternation — curly quotes only.
    let curlyPositions = aiwmAllPositions(aiwmIsCurlyQuote, input)
    let curlyCount = curlyPositions.count
    let hasStraightQuote = input.contains { aiwmIsStraightQuote($0) }
    let smartQuoteFires = curlyCount >= 2 && !hasStraightQuote

    // Probe 8: emDashPattern — em-dashes without hyphen-minus.
    let emDashPositions = aiwmAllPositions(aiwmIsEmDash, input)
    let emDashCount = emDashPositions.count
    let hasHyphenMinus = input.contains { aiwmIsHyphenMinus($0) }
    let emDashFires = emDashCount >= 2 && !hasHyphenMinus

    // Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word is
    // compared as a contiguous sub-slice of the input.
    let vocabHit = aiwmAiFavoredVocabulary().lazy
        .compactMap { aiwmContainsSublist($0, input) }
        .first

    // Residual default-ignorables (excluding VS and ZWJ, handled above).
    let isResidualDi: (Int) -> Bool = { cp in
        isDefaultIgnorableCodepoint(cp) && !aiwmIsVariationSelector(cp) && !aiwmIsZwj(cp)
    }
    let diPositions = aiwmAllPositions(isResidualDi, input)
    let diCount = diPositions.count

    // Probe 3: unknown — invisible markers from >= 2 distinct categories.
    let categoryCount = (nnbspCount > 0 ? 1 : 0)
        + (vsNonEmojiCount > 0 ? 1 : 0)
        + (zwjNonEmojiCount > 0 ? 1 : 0)
        + (diCount > 0 ? 1 : 0)
    let unknownFires = categoryCount >= 2
    let totalInvisibleCount = nnbspCount + vsNonEmojiCount + zwjNonEmojiCount + diCount

    let classification: AiWatermarkDetectabilityClassification
    let firedCount: Int
    if adversarialFires {
        let firstPos = nnbspPositions.first ?? 0
        classification = .hazard(
            sub: .adversarial(impersonatedScheme: "nnbspBoundary", firstPos: firstPos),
            positions: nnbspPositions)
        firedCount = nnbspCount
    } else if zwspModuloFires {
        let firstPos = zwspPositions.first ?? 0
        classification = .hazard(sub: .gpt5ZwspModulo(firstPos: firstPos), positions: zwspPositions)
        firedCount = zwspCount
    } else if unknownFires {
        let allInvisiblePos = input.indices.filter { idx in
            let cp = input[idx]
            return aiwmIsNnbsp(cp) || aiwmIsVariationSelector(cp) || aiwmIsZwj(cp)
                || isDefaultIgnorableCodepoint(cp)
        }
        classification = .hazard(
            sub: .unknown(anomalyMarker: totalInvisibleCount),
            positions: Array(allInvisiblePos))
        firedCount = totalInvisibleCount
    } else if nnbspCount > 0 {
        classification = .hazard(
            sub: .nnbspBoundary(markerCount: nnbspCount), positions: nnbspPositions)
        firedCount = nnbspCount
    } else if vsNonEmojiCount > 0 {
        classification = .hazard(
            sub: .variationSelectorCarrier(markerCount: vsNonEmojiCount), positions: vsNonEmojiPos)
        firedCount = vsNonEmojiCount
    } else if zwjNonEmojiCount > 0 {
        classification = .hazard(
            sub: .zwjNonEmoji(markerCount: zwjNonEmojiCount), positions: zwjNonEmojiPos)
        firedCount = zwjNonEmojiCount
    } else if smartQuoteFires {
        let firstPos = curlyPositions.first ?? 0
        classification = .hazard(
            sub: .smartQuoteAlternation(firstPos: firstPos), positions: curlyPositions)
        firedCount = curlyCount
    } else if emDashFires {
        let firstPos = emDashPositions.first ?? 0
        classification = .hazard(sub: .emDashPattern(firstPos: firstPos), positions: emDashPositions)
        firedCount = emDashCount
    } else if let pos = vocabHit {
        classification = .hazard(sub: .statisticalTokenChoice(firstPos: pos), positions: [pos])
        firedCount = 1
    } else if diCount > 0 {
        classification = .hazard(
            sub: .defaultIgnorableCarrier(markerCount: diCount), positions: diPositions)
        firedCount = diCount
    } else {
        classification = .clear
        firedCount = 0
    }

    return AiWatermarkDetectabilityVerdict(
        input: input, classify: classification, markerCount: firedCount)
}

/// Convenience wrapper over `aiWatermarkDetectabilityDetectWithContext` with the
/// empty context — exact-arithmetic settings (both tolerances `0`). Mirrors
/// `Unicode.Security.Crypto.AiWatermarkDetectability.detect`.
public func aiWatermarkDetectabilityDetect(_ input: [Int]) -> AiWatermarkDetectabilityVerdict {
    aiWatermarkDetectabilityDetectWithContext(.default, input)
}

/// Stable reason code for an ai-watermark-detectability sub-threat tag, routed
/// through the shared reason-code builder:
/// `unicode.security.K.ai-watermark-detectability.<tag>`.
public func aiWatermarkDetectabilityReasonCode(_ subThreat: String) -> String {
    reasonCode(family: Family.aiWatermarkDetectability, subThreat: subThreat)
}

// ─────────────────────────────────────────────────────────────────────
// stream-safe-violation — Stream-Safe-Text-Format-violation detection.
// Inputs whose consecutive non-starter run exceeds the UAX #15 §13
// streamSafeLimit of 30. Such an input (the canonical "Zalgo" shape, a
// single base codepoint followed by a long combining-mark run) forces
// unbounded combining-mark buffers in receiver-side streaming
// normalization (toNfc / toNfd / toNfkc / toNfkd) and is a known DoS
// vector.
//
// Direct port of Unicode/Security/Form/StreamSafeViolation.lean, mirroring
// the verified Rust reference. UAX #15 §13 defines Stream-Safe Text Format
// as the remediation: insert U+034F COMBINING GRAPHEME JOINER (a starter)
// after every 30 consecutive non-starters, which bounds the normalization
// buffer.
//
// A codepoint is a non-starter iff its Canonical_Combining_Class is
// non-zero (UAX #15 D49). This reads CCC from the port's own bundled UCD
// table via `canonicalCombiningClass`, never a host normaliser.
// ─────────────────────────────────────────────────────────────────────

/// UAX #15 §13 Stream-Safe limit: the maximum number of consecutive
/// non-starters permitted before a COMBINING GRAPHEME JOINER must be inserted.
public let streamSafeLimit = 30

/// True iff `cp` is a non-starter — a codepoint with non-zero
/// Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0. Reuses the
/// port's own `canonicalCombiningClass`, never a host normaliser.
private func streamSafeIsNonStarter(_ cp: Int) -> Bool {
    canonicalCombiningClass(cp) != 0
}

/// Inventory of `(startIndex, length)` for every maximal non-starter run in
/// `input`. Mirrors `collectRunsGo`: a run opens on the first non-starter, its
/// start index is fixed to that codepoint's absolute index, and it closes
/// (emitting its `(start, length)` pair) on the next starter or at end of input.
private func streamSafeNonStarterRuns(_ input: [Int]) -> [(Int, Int)] {
    var runs: [(Int, Int)] = []
    var curStart: Int? = nil
    var curLen = 0
    for i in input.indices {
        if streamSafeIsNonStarter(input[i]) {
            if curStart == nil { curStart = i }
            curLen += 1
        } else {
            if let s = curStart { runs.append((s, curLen)) }
            curStart = nil
            curLen = 0
        }
    }
    if let s = curStart { runs.append((s, curLen)) }
    return runs
}

/// First non-starter run whose length exceeds `streamSafeLimit`, as
/// `(startIndex, length)`.
private func streamSafeFirstOverrun(_ input: [Int]) -> (Int, Int)? {
    streamSafeNonStarterRuns(input).first { $0.1 > streamSafeLimit }
}

/// Longest non-starter run length in `input`.
private func streamSafeMaxRunLen(_ input: [Int]) -> Int {
    streamSafeNonStarterRuns(input).reduce(0) { acc, run in run.1 > acc ? run.1 : acc }
}

/// Number of distinct non-starter runs that exceed `streamSafeLimit`.
private func streamSafeOverrunCount(_ input: [Int]) -> Int {
    streamSafeNonStarterRuns(input).reduce(0) { acc, run in run.1 > streamSafeLimit ? acc + 1 : acc }
}

/// Total non-starter codepoints in `input` (sum of all run lengths).
private func streamSafeTotalNonStarters(_ input: [Int]) -> Int {
    streamSafeNonStarterRuns(input).reduce(0) { acc, run in acc + run.1 }
}

/// Sub-threats this detector can fire.
public enum StreamSafeViolationSubThreat: Equatable {
    /// The first non-starter run whose length exceeds `streamSafeLimit`.
    /// `basePos` is the index of the run's first non-starter codepoint;
    /// `runLen` is the run's length.
    case streamSafeOverrun(basePos: Int, runLen: Int)

    /// Human-facing classification tag for this sub-threat.
    public var tag: String {
        switch self {
        case .streamSafeOverrun: return "StreamSafeOverrun"
        }
    }
}

/// Top-level stream-safe-violation classification.
public enum StreamSafeViolationClassification: Equatable {
    /// No non-starter run exceeds the Stream-Safe limit.
    case clear
    /// A hazard was found: the sub-threat, its implicated positions, and any
    /// decoded bytes (always empty for this detector — the field mirrors the
    /// spec's `Classification.hazard` shape).
    case hazard(sub: StreamSafeViolationSubThreat, positions: [Int], decoded: [UInt8])

    /// True iff the input is clear.
    public var isClear: Bool {
        switch self {
        case .clear: return true
        case .hazard: return false
        }
    }

    /// Human-facing tag for a hazard, or `nil` when clear.
    public var tag: String? {
        switch self {
        case .clear: return nil
        case .hazard(let sub, _, _): return sub.tag
        }
    }

    /// Implicated positions (empty when clear).
    public var positions: [Int] {
        switch self {
        case .clear: return []
        case .hazard(_, let positions, _): return positions
        }
    }
}

/// Verdict — the structured output of `streamSafeViolationDetect`. The
/// run-inventory summaries (`maxRunLen`, `overrunCount`, `totalNonStarters`) are
/// exposed so downstream callers can size the buffer pressure a streaming
/// normaliser would see.
public struct StreamSafeViolationVerdict: Equatable {
    /// The scanned input codepoints.
    public let input: [Int]
    /// The classification verdict.
    public let classify: StreamSafeViolationClassification
    /// Longest non-starter run length in `input`.
    public let maxRunLen: Int
    /// Number of distinct non-starter runs exceeding the Stream-Safe limit.
    public let overrunCount: Int
    /// Total non-starter codepoints in `input`.
    public let totalNonStarters: Int
}

/// The stream-safe-violation detection function. Fires `StreamSafeOverrun` on
/// the first non-starter run whose length exceeds `streamSafeLimit`.
public func streamSafeViolationDetect(_ input: [Int]) -> StreamSafeViolationVerdict {
    let classification: StreamSafeViolationClassification
    if let (basePos, runLen) = streamSafeFirstOverrun(input) {
        classification = .hazard(
            sub: .streamSafeOverrun(basePos: basePos, runLen: runLen),
            positions: [basePos],
            decoded: [])
    } else {
        classification = .clear
    }
    return StreamSafeViolationVerdict(
        input: input,
        classify: classification,
        maxRunLen: streamSafeMaxRunLen(input),
        overrunCount: streamSafeOverrunCount(input),
        totalNonStarters: streamSafeTotalNonStarters(input))
}

/// Stable reason code for a stream-safe-violation sub-threat tag, routed
/// through the shared reason-code builder:
/// `unicode.security.F.stream-safe-violation.<tag>`.
public func streamSafeViolationReasonCode(_ subThreat: String) -> String {
    reasonCode(family: Family.streamSafeViolation, subThreat: subThreat)
}

// ─────────────────────────────────────────────────────────────────────
// emoji-zwj-integrity — malformed / unsanctioned emoji ZWJ-sequence
// detection per UTS #51 (the identity-layer detector I3).
//
// Direct port of Unicode/Security/Identity/EmojiZwjIntegrity.lean, mirroring
// the verified Rust reference. An adversary crafts an emoji-shaped codepoint
// sequence containing one or more U+200D ZERO WIDTH JOINERs but violating the
// sanctioned RGI ZWJ-sequence shape — exceeding the RGI length cap, joining a
// non-emoji codepoint, emitting adjacent ZWJ pairs, or overflowing the
// skin-tone count. Any non-RGI ZWJ-containing sequence is renderer-dependent,
// and that renderer divergence is the attack surface.
//
// Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
// emoji-zwj-sequences.txt, bundled in the port's own Resources/Data tree
// (never a host emoji library). The registered set gives both the exact-match
// membership test (emojiZwjIsRegisteredSequence) and the ZWJ alphabet — every
// distinct codepoint occurring at any position of any registered sequence,
// excluding the joiner — which is the canonical "what may flank a ZWJ?"
// predicate (emojiZwjIsEmojiTarget).
// ─────────────────────────────────────────────────────────────────────

/// Conservative cap on the length of a sanctioned RGI ZWJ sequence
/// (`maxRgiLength` in the Lean spec). The longest current entry (a four-person
/// family with skin tones) reaches ~13-14 codepoints; 16 is a safe upper bound.
public let emojiZwjMaxRgiLength: Int = 16

/// The ZERO WIDTH JOINER codepoint.
public let emojiZwjZwj: Int = 0x200D

/// Sub-threat enumeration for emoji-zwj-integrity, in priority order.
public enum EmojiZwjIntegritySubThreat: Equatable {
    /// ZWJ-ZWJ adjacency; `positions` are the first ZWJ of each adjacent pair.
    case doubleZwj(positions: [Int])
    /// A ZWJ flanked by a non-emoji codepoint (or sitting at an input edge).
    /// `nonEmojiCp` is the offending codepoint (0 for an edge ZWJ).
    case nonEmojiInjection(zwjPos: Int, nonEmojiCp: Int)
    /// The sequence is longer than `emojiZwjMaxRgiLength`.
    case overLength(length: Int, maxLength: Int)
    /// Five or more skin-tone modifiers (the family-emoji maximum is four).
    case skinToneOverflow(count: Int)
    /// ZWJs are present and no other sub-threat matched, but the sequence is
    /// not a registered RGI ZWJ sequence.
    case unregisteredSequence(chainLen: Int)

    /// Fixture-row tag string for this sub-threat (matches `SubThreat.tag`).
    public var tag: String {
        switch self {
        case .doubleZwj: return "DoubleZWJ"
        case .nonEmojiInjection: return "NonEmojiInjection"
        case .overLength: return "OverLength"
        case .skinToneOverflow: return "SkinToneOverflow"
        case .unregisteredSequence: return "UnregisteredSequence"
        }
    }
}

/// Top-level classification for emoji-zwj-integrity.
public enum EmojiZwjIntegrityClassification: Equatable {
    /// A well-formed or non-ZWJ input.
    case clear
    /// A hazard: the fired sub-threat, the implicated positions, and the
    /// (always-empty for this detector) decoded-byte projection, kept for shape
    /// parity with the Lean `Classification.hazard`.
    case hazard(sub: EmojiZwjIntegritySubThreat, positions: [Int], decoded: [UInt8])

    /// True iff the classification is `clear`.
    public var isClear: Bool {
        switch self {
        case .clear: return true
        case .hazard: return false
        }
    }

    /// Human-facing tag for a hazard, or `nil` when clear.
    public var tag: String? {
        switch self {
        case .clear: return nil
        case .hazard(let sub, _, _): return sub.tag
        }
    }

    /// Implicated positions (empty when clear).
    public var positions: [Int] {
        switch self {
        case .clear: return []
        case .hazard(_, let positions, _): return positions
        }
    }
}

/// The structured output of `emojiZwjIntegrityDetect` (mirrors the Lean `Verdict`).
public struct EmojiZwjIntegrityVerdict: Equatable {
    /// The scanned input codepoints.
    public let input: [Int]
    /// The classification verdict.
    public let classify: EmojiZwjIntegrityClassification
    /// Positions of every ZWJ in the input.
    public let zwjPositions: [Int]
    /// The chain length (0 when there are no ZWJs, else the input length).
    public let chainLength: Int
    /// True iff the input is exactly a registered RGI ZWJ sequence.
    public let isRegisteredRgi: Bool
    /// Count of skin-tone modifier codepoints (U+1F3FB..U+1F3FF).
    public let skinToneCount: Int
}

/// Parse the registered RGI ZWJ sequences from emoji-zwj-sequences.txt via the
/// port's own text-file reader (the same integrity-checked `readDataFile` the
/// AiWatermark emoji-data reader uses — never a host emoji/ICU library). Each
/// non-comment row is `<cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ; <desc> # <cmt>`;
/// the codepoint list is the whitespace-separated hex field before the first `;`.
private func emojiZwjSequences() -> [[Int]] {
    if let cached = emojiZwjSequencesCache { return cached }
    var out: [[Int]] = []
    let raw = readDataFile("emoji-zwj-sequences.txt")
    for rawLine in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        let body = String(
            rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
        let stripped = body.trimmingCharacters(in: .whitespacesAndNewlines)
        if stripped.isEmpty { continue }
        let seqField = String(
            stripped.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
        var seq: [Int] = []
        var parsedOk = true
        for token in seqField.split(separator: " ", omittingEmptySubsequences: true) {
            if let cp = parseHex(String(token)) {
                seq.append(cp)
            } else {
                parsedOk = false
                break
            }
        }
        if parsedOk && !seq.isEmpty {
            out.append(seq)
        }
    }
    emojiZwjSequencesCache = out
    return out
}

/// The ZWJ alphabet: every distinct codepoint occurring at any position of any
/// registered RGI ZWJ sequence, excluding the joiner U+200D itself.
private func emojiZwjAlphabet() -> Set<Int> {
    if let cached = emojiZwjAlphabetCache { return cached }
    var set: Set<Int> = []
    for seq in emojiZwjSequences() {
        for cp in seq where cp != emojiZwjZwj {
            set.insert(cp)
        }
    }
    emojiZwjAlphabetCache = set
    return set
}

/// True iff `cps` is exactly a registered RGI ZWJ sequence.
public func emojiZwjIsRegisteredSequence(_ cps: [Int]) -> Bool {
    emojiZwjSequences().contains { $0 == cps }
}

/// True iff `cp` appears at some position of a registered RGI ZWJ sequence
/// (the canonical "what may flank a ZWJ?" predicate).
public func emojiZwjIsEmojiTarget(_ cp: Int) -> Bool {
    emojiZwjAlphabet().contains(cp)
}

/// True iff `cp` is the ZWJ codepoint.
public func emojiZwjIsZwj(_ cp: Int) -> Bool {
    cp == emojiZwjZwj
}

/// True iff `cp` is an emoji skin-tone modifier (U+1F3FB..U+1F3FF).
public func emojiZwjIsEmojiModifier(_ cp: Int) -> Bool {
    cp >= 0x1F3FB && cp <= 0x1F3FF
}

/// Positions of every ZWJ in `input`.
private func emojiZwjPositions(_ input: [Int]) -> [Int] {
    input.indices.filter { emojiZwjIsZwj(input[$0]) }
}

/// Count of skin-tone modifier codepoints.
private func emojiZwjSkinToneCount(_ input: [Int]) -> Int {
    input.filter { emojiZwjIsEmojiModifier($0) }.count
}

/// Positions of the first ZWJ in each ZWJ-ZWJ adjacent pair.
private func emojiZwjDoublePositions(_ input: [Int]) -> [Int] {
    var out: [Int] = []
    for idx in input.indices {
        if idx + 1 < input.count {
            let cp = input[idx]
            let nextCp = input[idx + 1]
            if emojiZwjIsZwj(cp) && emojiZwjIsZwj(nextCp) {
                out.append(idx)
            }
        }
    }
    return out
}

/// The first ZWJ position where either neighbour is a non-emoji codepoint, as
/// `(zwjPos, offendingCp)`. A ZWJ at an input edge (no preceding or no following
/// codepoint) is itself an injection-class hazard, reported with offending
/// codepoint 0.
private func emojiZwjFirstNonEmojiInjection(_ input: [Int]) -> (Int, Int)? {
    for idx in input.indices {
        if !emojiZwjIsZwj(input[idx]) { continue }
        let prev: Int? = idx == 0 ? nil : input[idx - 1]
        let next: Int? = idx + 1 < input.count ? input[idx + 1] : nil
        switch (prev, next) {
        case (.some(let prevCp), .some(let nextCp)):
            if !emojiZwjIsEmojiTarget(prevCp) {
                return (idx, prevCp)
            } else if !emojiZwjIsEmojiTarget(nextCp) {
                return (idx, nextCp)
            }
        case (.none, .some), (.none, .none):
            return (idx, 0)
        case (.some, .none):
            return (idx, 0)
        }
    }
    return nil
}

/// The emoji-zwj-integrity detection function. Mirrors the Lean/Rust `detect`:
/// short-circuits `clear` when there are no ZWJs and the skin-tone count is at
/// most 1; a registered RGI sequence is always `clear`; otherwise the priority
/// ladder DoubleZWJ -> NonEmojiInjection -> OverLength -> SkinToneOverflow ->
/// UnregisteredSequence fires.
public func emojiZwjIntegrityDetect(_ input: [Int]) -> EmojiZwjIntegrityVerdict {
    let zwjs = emojiZwjPositions(input)
    let stCount = emojiZwjSkinToneCount(input)
    let isRgi = emojiZwjIsRegisteredSequence(input)
    let chainLen = zwjs.isEmpty ? 0 : input.count

    if zwjs.isEmpty && stCount <= 1 {
        return EmojiZwjIntegrityVerdict(
            input: input,
            classify: .clear,
            zwjPositions: [],
            chainLength: 0,
            isRegisteredRgi: isRgi,
            skinToneCount: stCount)
    }

    let classification: EmojiZwjIntegrityClassification
    if isRgi {
        // Phase 3: a registered RGI sequence is always clear.
        classification = .clear
    } else {
        // Phase 4.1: ZWJ-ZWJ adjacency.
        let dzwj = emojiZwjDoublePositions(input)
        if !dzwj.isEmpty {
            classification = .hazard(
                sub: .doubleZwj(positions: dzwj), positions: dzwj, decoded: [])
        } else if let (zwjPos, offendCp) = emojiZwjFirstNonEmojiInjection(input) {
            // Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
            classification = .hazard(
                sub: .nonEmojiInjection(zwjPos: zwjPos, nonEmojiCp: offendCp),
                positions: [zwjPos],
                decoded: [])
        } else if input.count > emojiZwjMaxRgiLength {
            // Phase 4.3: length cap.
            classification = .hazard(
                sub: .overLength(length: input.count, maxLength: emojiZwjMaxRgiLength),
                positions: [],
                decoded: [])
        } else if stCount >= 5 {
            // Phase 4.4: skin-tone overflow.
            classification = .hazard(
                sub: .skinToneOverflow(count: stCount), positions: [], decoded: [])
        } else if !zwjs.isEmpty {
            // Phase 4.5: catch-all for unregistered ZWJ sequences.
            classification = .hazard(
                sub: .unregisteredSequence(chainLen: input.count),
                positions: zwjs,
                decoded: [])
        } else {
            classification = .clear
        }
    }

    return EmojiZwjIntegrityVerdict(
        input: input,
        classify: classification,
        zwjPositions: zwjs,
        chainLength: chainLen,
        isRegisteredRgi: isRgi,
        skinToneCount: stCount)
}

/// Stable reason code for an emoji-zwj-integrity sub-threat tag, routed through
/// the shared reason-code builder:
/// `unicode.security.I.emoji-zwj-integrity.<tag>`.
public func emojiZwjIntegrityReasonCode(_ subThreat: String) -> String {
    reasonCode(family: Family.emojiZwjIntegrity, subThreat: subThreat)
}

// ─────────────────────────────────────────────────────────────────────
// RendererDivergence — detection of codepoint/sequence shapes known to render
// differently across font + terminal + browser stacks (display-layer detector,
// layer D).
//
// Direct port of Unicode/Security/Display/RendererDivergence.lean, mirroring the
// verified Rust reference. An adversary crafts content that renders one way in
// the auditor's renderer (a benign glyph or an empty span) and a different way
// in the consumer's renderer (a misleading glyph, a wider glyph, or a different
// sequence). This is the "fingerprint stability" family — clear inputs render
// the same across the renderer cohort the Standard documents as stable.
//
// The detector draws a heuristic three-value split: an input is clear when none
// of the documented variance triggers fire, and otherwise is classified by the
// first trigger in priority order — combining-mark stack overflow, variation-
// selector presence, an unregistered ZWJ shape, fullwidth/halfwidth display, or
// mixed direction. It reuses the port's own tables (the variation-selector set,
// the grapheme Extend class, the RGI ZWJ registry, and strong-bidi classes),
// never a host rendering or shaping library.
//
// Sub-threats (priority order):
//   1. CombiningStackOverflow    Zalgo-like combining-mark stack >= 4 on a base.
//   2. VariationSelectorVariance any variation selector present.
//   3. UnregisteredZwjVariance   ZWJ-containing input not in the RGI ZWJ set.
//   4. FullwidthVariance         a fullwidth/halfwidth codepoint present.
//   5. MixedDirectionVariance    both strong-LTR and strong-RTL codepoints.
// ─────────────────────────────────────────────────────────────────────

/// The combining-mark stack depth (on a single base) at or beyond which the
/// input is treated as a Zalgo-style rendering-variance hazard.
public let rendererDivergenceMinCombiningStack: Int = 4

/// The ZERO WIDTH JOINER codepoint.
public let rendererDivergenceZwj: Int = 0x200D

/// Sub-threat enumeration for renderer-divergence, in priority order.
public enum RendererDivergenceSubThreat: Equatable {
    /// A combining-mark stack of `stackLen` marks on the base at `basePos`.
    case combiningStackOverflow(basePos: Int, stackLen: Int)
    /// A variation selector at `firstVsPos` (codepoint `firstVsCp`).
    case variationSelectorVariance(firstVsPos: Int, firstVsCp: Int)
    /// A ZWJ-containing input not present in the registered RGI ZWJ set.
    case unregisteredZwjVariance(firstZwjPos: Int)
    /// A fullwidth/halfwidth codepoint at `firstFwPos` (codepoint `firstFwCp`).
    case fullwidthVariance(firstFwPos: Int, firstFwCp: Int)
    /// Both strong-LTR and strong-RTL codepoints in one input.
    case mixedDirectionVariance(ltrCount: Int, rtlCount: Int)

    /// Fixture-row tag string for this sub-threat (matches `SubThreat.tag`).
    public var tag: String {
        switch self {
        case .combiningStackOverflow: return "CombiningStackOverflow"
        case .variationSelectorVariance: return "VariationSelectorVariance"
        case .unregisteredZwjVariance: return "UnregisteredZwjVariance"
        case .fullwidthVariance: return "FullwidthVariance"
        case .mixedDirectionVariance: return "MixedDirectionVariance"
        }
    }
}

/// Top-level classification for renderer-divergence (stable = `clear`).
public enum RendererDivergenceClassification: Equatable {
    /// Rendering is consistent across the documented renderer cohort.
    case clear
    /// A documented variance mode fired: the sub-threat, the implicated
    /// positions, and the (always-empty for this detector) decoded-byte
    /// projection, kept for shape parity with the Lean `Classification.hazard`.
    case hazard(sub: RendererDivergenceSubThreat, positions: [Int], decoded: [UInt8])

    /// True iff the classification is `clear` (i.e. stable).
    public var isClear: Bool {
        switch self {
        case .clear: return true
        case .hazard: return false
        }
    }

    /// Human-facing tag for a hazard, or `nil` when clear.
    public var tag: String? {
        switch self {
        case .clear: return nil
        case .hazard(let sub, _, _): return sub.tag
        }
    }

    /// Implicated positions (empty when clear).
    public var positions: [Int] {
        switch self {
        case .clear: return []
        case .hazard(_, let positions, _): return positions
        }
    }
}

/// The structured output of `rendererDivergenceDetect` (mirrors the Lean `Verdict`).
public struct RendererDivergenceVerdict: Equatable {
    /// The scanned input codepoints.
    public let input: [Int]
    /// The classification verdict.
    public let classify: RendererDivergenceClassification
    /// Count of variation selectors.
    public let vsCount: Int
    /// Count of combining (Extend) marks.
    public let combiningCount: Int
    /// Count of fullwidth/halfwidth codepoints.
    public let fullwidthCount: Int
    /// Whether the input contains any ZWJ.
    public let hasZwj: Bool
    /// Count of strong-LTR codepoints.
    public let strongLtrCount: Int
    /// Count of strong-RTL codepoints.
    public let strongRtlCount: Int
}

/// The `Grapheme_Cluster_Break = Extend` ranges, derived from the bundled tables
/// the port already carries: the `Grapheme_Extend` property of
/// DerivedCoreProperties.txt (read through the same integrity-checked
/// `readDataFile` the casing predicates use) unioned with the emoji skin-tone
/// modifiers (U+1F3FB..U+1F3FF), which UAX #29 assigns `GCB = Extend`. This union
/// equals the canonical GCB=Extend class — never a host segmentation/ICU library.
private func graphemeExtendRanges() -> [(Int, Int)] {
    if let cached = graphemeExtendRangesCache { return cached }
    var parsed = parseDerivedProperty(readDataFile("DerivedCoreProperties.txt"), "Grapheme_Extend")
    parsed.append((0x1F3FB, 0x1F3FF))
    let sorted = parsed.sorted { $0.0 < $1.0 }
    graphemeExtendRangesCache = sorted
    return sorted
}

/// True iff `cp` is a variation selector (reuses the port's own predicate from
/// the variation-selector-payload detector: FE00-FE0F, E0100-E01EF, 180B-180D).
private func rendererDivergenceIsVariationSelector(_ cp: Int) -> Bool {
    isVariationSelector(cp)
}

/// True iff `cp` is the ZWJ codepoint.
private func rendererDivergenceIsZwj(_ cp: Int) -> Bool {
    cp == rendererDivergenceZwj
}

/// True iff `cp` is in the Halfwidth/Fullwidth Forms block.
private func rendererDivergenceIsFullwidthHalfwidth(_ cp: Int) -> Bool {
    cp >= 0xFF01 && cp <= 0xFFEF
}

/// True iff `cp` has `Grapheme_Cluster_Break = Extend` (reuses the port's tables).
private func rendererDivergenceIsGraphemeExtend(_ cp: Int) -> Bool {
    graphemeExtendRanges().contains { cp >= $0.0 && cp <= $0.1 }
}

private func rendererDivergenceCountVs(_ input: [Int]) -> Int {
    input.filter { rendererDivergenceIsVariationSelector($0) }.count
}

private func rendererDivergenceCountCombining(_ input: [Int]) -> Int {
    input.filter { rendererDivergenceIsGraphemeExtend($0) }.count
}

private func rendererDivergenceCountFullwidth(_ input: [Int]) -> Int {
    input.filter { rendererDivergenceIsFullwidthHalfwidth($0) }.count
}

private func rendererDivergenceInputHasZwj(_ input: [Int]) -> Bool {
    input.contains { rendererDivergenceIsZwj($0) }
}

private func rendererDivergenceCountStrongLtr(_ input: [Int]) -> Int {
    input.filter { isStrongLtr($0) }.count
}

private func rendererDivergenceCountStrongRtl(_ input: [Int]) -> Int {
    input.filter { isStrongRtl($0) }.count
}

/// Position and codepoint of the first variation selector.
private func rendererDivergenceFirstVsPos(_ input: [Int]) -> (Int, Int)? {
    for (idx, cp) in input.enumerated() where rendererDivergenceIsVariationSelector(cp) {
        return (idx, cp)
    }
    return nil
}

/// Position of the first ZWJ.
private func rendererDivergenceFirstZwjPos(_ input: [Int]) -> Int? {
    for (idx, cp) in input.enumerated() where rendererDivergenceIsZwj(cp) {
        return idx
    }
    return nil
}

/// Position and codepoint of the first fullwidth/halfwidth codepoint.
private func rendererDivergenceFirstFullwidthPos(_ input: [Int]) -> (Int, Int)? {
    for (idx, cp) in input.enumerated() where rendererDivergenceIsFullwidthHalfwidth(cp) {
        return (idx, cp)
    }
    return nil
}

/// The first base position (a non-Extend codepoint) immediately followed by
/// exactly `minStack` consecutive Extend codepoints. Returns `(basePos, minStack)`
/// on hit.
private func rendererDivergenceFirstCombiningStack(_ input: [Int], _ minStack: Int) -> (Int, Int)? {
    for (idx, cp) in input.enumerated() where !rendererDivergenceIsGraphemeExtend(cp) {
        let following = Array(input.dropFirst(idx + 1).prefix(minStack))
        if following.count == minStack && following.allSatisfy({ rendererDivergenceIsGraphemeExtend($0) }) {
            return (idx, minStack)
        }
    }
    return nil
}

/// The RendererDivergence detection function. Mirrors the Lean/Rust `detect`:
/// walks the priority ladder CombiningStackOverflow -> VariationSelectorVariance
/// -> UnregisteredZwjVariance -> FullwidthVariance -> MixedDirectionVariance,
/// returning the first trigger that fires (else `clear`).
public func rendererDivergenceDetect(_ input: [Int]) -> RendererDivergenceVerdict {
    let vsCount = rendererDivergenceCountVs(input)
    let combiningCount = rendererDivergenceCountCombining(input)
    let fullwidthCount = rendererDivergenceCountFullwidth(input)
    let hasZwj = rendererDivergenceInputHasZwj(input)
    let ltrCount = rendererDivergenceCountStrongLtr(input)
    let rtlCount = rendererDivergenceCountStrongRtl(input)

    let classification: RendererDivergenceClassification
    // Priority 1: combining-mark stack overflow (Zalgo).
    if let (basePos, stackLen) = rendererDivergenceFirstCombiningStack(input, rendererDivergenceMinCombiningStack) {
        classification = .hazard(
            sub: .combiningStackOverflow(basePos: basePos, stackLen: stackLen),
            positions: [basePos],
            decoded: [])
    } else if let (pos, cp) = rendererDivergenceFirstVsPos(input) {
        // Priority 2: any variation selector triggers presentation variance.
        classification = .hazard(
            sub: .variationSelectorVariance(firstVsPos: pos, firstVsCp: cp),
            positions: [pos],
            decoded: [])
    } else if hasZwj && !emojiZwjIsRegisteredSequence(input) {
        // Priority 3: ZWJ-containing input not in the registered RGI set.
        if let pos = rendererDivergenceFirstZwjPos(input) {
            classification = .hazard(
                sub: .unregisteredZwjVariance(firstZwjPos: pos),
                positions: [pos],
                decoded: [])
        } else {
            classification = .clear
        }
    } else if let (pos, cp) = rendererDivergenceFirstFullwidthPos(input) {
        // Priority 4: fullwidth/halfwidth.
        classification = .hazard(
            sub: .fullwidthVariance(firstFwPos: pos, firstFwCp: cp),
            positions: [pos],
            decoded: [])
    } else if ltrCount > 0 && rtlCount > 0 {
        // Priority 5: mixed direction.
        classification = .hazard(
            sub: .mixedDirectionVariance(ltrCount: ltrCount, rtlCount: rtlCount),
            positions: [],
            decoded: [])
    } else {
        classification = .clear
    }

    return RendererDivergenceVerdict(
        input: input,
        classify: classification,
        vsCount: vsCount,
        combiningCount: combiningCount,
        fullwidthCount: fullwidthCount,
        hasZwj: hasZwj,
        strongLtrCount: ltrCount,
        strongRtlCount: rtlCount)
}

/// Stable reason code for a renderer-divergence sub-threat tag, routed through
/// the shared reason-code builder:
/// `unicode.security.D.renderer-divergence.<tag>`.
public func rendererDivergenceReasonCode(_ subThreat: String) -> String {
    reasonCode(family: Family.rendererDivergence, subThreat: subThreat)
}
