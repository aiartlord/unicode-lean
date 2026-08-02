import Foundation
import UnicodeSecurity

@main
struct SecurityContractRunner {
    static func main() throws {
        try testCovertDisplayCompound()
        try testConfusableBidiCompound()
        try testSurrogateReassembly()
        try testRtlInjection()
        try testLocaleCaseInversion()
        try testNormalizationBomb()
        try testNfcIdempotenceWitness()
        try testPolicyContract()
        try testVerdictContract()
        try testUtf8DecodeContract()
        try testMultiEncodingDecodeContract()
        try testDetectorFixtures()
        try testCompatibilityNormalization()
        try testCasing()
        try testBip39Canonical()
        try testHashInputStability()
        try testAiWatermarkDetectability()
        try testStreamSafeViolation()
        try testEmojiZwjIntegrity()
        try testRendererDivergence()
        try testFilenameDisguise()
        try testIdentifierFormDrift()
        try testOpaqueBlob()
        print("clean: Swift contract tests pass")
    }

    // Pins toLower against the toLower_* ground-truth theorems in
    // Unicode/Casing.lean.
    private static func testCasing() throws {
        try expectEqual(toLower(.default, [0x48, 0x65, 0x6C, 0x6C, 0x6F]), [0x68, 0x65, 0x6C, 0x6C, 0x6F], "toLower hello")
        try expectEqual(toLower(.default, [0x0049]), [0x0069], "toLower I default")
        try expectEqual(toLower(.turkish, [0x0049]), [0x0131], "toLower I turkish")
        try expectEqual(toLower(.azeri, [0x0049]), [0x0131], "toLower I azeri")
        try expectEqual(toLower(.turkish, [0x0130]), [0x0069], "toLower dotted-I turkish")
        try expectEqual(toLower(.default, [0x0130]), [0x0069, 0x0307], "toLower dotted-I default")
    }

    // Pins bip39CanonicalDetect against the detect ground-truth theorems in
    // Unicode/Security/Crypto/Bip39Canonical.lean.
    private static func testBip39Canonical() throws {
        let abandon = [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
        let about = [0x61, 0x62, 0x6F, 0x75, 0x74]

        try expectEqual(bip39CanonicalDetect(abandon + [0x20]).subThreat, "TrailingWhitespace", "bip39 trailing")
        try expectEqual(bip39CanonicalDetect(abandon + [0x20]).positions, [7], "bip39 trailing pos")
        try expectEqual(bip39CanonicalDetect([0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]).subThreat, "MixedCase", "bip39 mixed")
        try expectEqual(bip39CanonicalDetect(abandon + [0x20, 0x20] + about).subThreat, "WhitespaceAnomaly", "bip39 double")
        try expectEqual(bip39CanonicalDetect([0x20] + abandon).subThreat, "WhitespaceAnomaly", "bip39 leading")
        try expectEqual(bip39CanonicalDetect([0xFB00]).subThreat, "NonNFKD", "bip39 ligature")
        try expectEqual(bip39CanonicalDetect([0x61, 0x00A0, 0x62]).subThreat, "NonNFKD", "bip39 nbsp")
        try expectEqual(bip39CanonicalDetect([0x71, 0x7A, 0x71, 0x7A]).subThreat, "WordlistMismatch", "bip39 mismatch")

        let empty = bip39CanonicalDetect([])
        try expectEqual(empty.subThreat, nil, "bip39 empty sub")
        try expectEqual(empty.language, "english", "bip39 empty lang")

        var mnemonic: [Int] = []
        for _ in 0..<11 { mnemonic += abandon + [0x20] }
        mnemonic += about
        let verdict = bip39CanonicalDetect(mnemonic)
        try expectEqual(verdict.subThreat, nil, "bip39 12word sub")
        try expectEqual(verdict.language, "english", "bip39 12word lang")
        try expectEqual(verdict.wordCount, 12, "bip39 12word count")
    }

    // Pins hashInputStabilityDetect against the ground-truth theorems in
    // Unicode/Security/Crypto/HashInputStability.lean: the shared context-free
    // fixture runs through detect; the Context-bearing vectors (which the shared
    // detector-fixture schema cannot express) are transcribed from the verbatim
    // comment block in the Rust reference's test module.
    private static func testHashInputStability() throws {
        // Shared context-free fixture through detect. required_findings carries
        // full reason codes (unicode.security.K.hash-input-stability.<SubThreat>);
        // an empty list means clear.
        let fixture = try loadFixture("detectors/hash_input_stability.json")
        try expectEqual(fixture["schema"] as? Int, 1, "hash-input-stability schema")
        try expectEqual(try string(fixture, "family"), "hash-input-stability", "hash-input-stability family")
        for entry in try array(fixture, "cases") {
            let name = try string(entry, "name")
            let input = try intArray(entry, "input")
            let required = try stringArray(entry, "required_findings")
            if let tag = hashInputStabilityDetect(input).classify.tag {
                let code = hashInputStabilityReasonCode(tag)
                try expect(required.contains(code), "hash-input-stability \(name): expected \(code) in \(required)")
            } else {
                try expect(required.isEmpty, "hash-input-stability \(name): expected clear, got \(required)")
            }
        }

        // ── Context-bearing probe vectors, transcribed from the Rust reference.
        // encodingMismatch.
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(declaredEncoding: "utf-16"), [0x61, 0x62, 0x63]).classify.tag,
            "EncodingMismatch", "his encoding utf-16 label")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(declaredEncoding: "utf-16"), [0x61, 0x62, 0x63]).classify.positions,
            [0], "his encoding utf-16 label pos")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(declaredEncoding: "utf-8"), [0x61, 0xD800, 0x62]).classify.tag,
            "EncodingMismatch", "his encoding invalid surrogate")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(declaredEncoding: "utf-8"), [0x61, 0xD800, 0x62]).classify.positions,
            [1], "his encoding invalid surrogate pos")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(declaredEncoding: "utf-8"), [0x61, 0x110000, 0x62]).classify.tag,
            "EncodingMismatch", "his encoding out of range")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(declaredEncoding: "utf-8"), [0x61, 0x110000, 0x62]).classify.positions,
            [1], "his encoding out of range pos")
        for label in ["UTF-8", "utf-8", "UTF8", "utf8"] {
            try expectEqual(
                hashInputStabilityDetectWithContext(HashInputStabilityContext(declaredEncoding: label), [0x61, 0x62, 0x63]).classify.tag,
                nil, "his encoding utf-8 label \(label) clear")
        }

        // signedMessageRule.
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .pgp4880TrailingWhitespace), [0x61, 0x20]).classify.tag,
            "SignedMessageRule", "his rfc pgp4880")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .pgp4880TrailingWhitespace), [0x61, 0x20]).classify.positions,
            [1], "his rfc pgp4880 pos")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .pgp9580LineEnding), [0x61, 0x0A, 0x62]).classify.tag,
            "SignedMessageRule", "his rfc pgp9580 bare lf")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .pgp9580LineEnding), [0x61, 0x0A, 0x62]).classify.positions,
            [1], "his rfc pgp9580 bare lf pos")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .pgp9580LineEnding), [0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66]).classify.tag,
            nil, "his rfc pgp9580 crlf clear")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc8785NfcRequirement), [0x0065, 0x0301]).classify.tag,
            "SignedMessageRule", "his rfc rfc8785 decomposed")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc8785NfcRequirement), [0x0065, 0x0301]).classify.positions,
            [0], "his rfc rfc8785 decomposed pos")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc8259ControlChar), [0x61, 0x01, 0x62]).classify.tag,
            "SignedMessageRule", "his rfc rfc8259 control")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc8259ControlChar), [0x61, 0x01, 0x62]).classify.positions,
            [1], "his rfc rfc8259 control pos")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc7515JwsBase64Url), [0x41, 0x2B, 0x42]).classify.tag,
            "SignedMessageRule", "his rfc rfc7515 plus")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc7515JwsBase64Url), [0x41, 0x2B, 0x42]).classify.positions,
            [1], "his rfc rfc7515 plus pos")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc7515JwsBase64Url), [0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39]).classify.tag,
            nil, "his rfc rfc7515 clean clear")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc6376DkimRelaxed), [0x61, 0x20, 0x20, 0x62]).classify.tag,
            "SignedMessageRule", "his rfc rfc6376 double space")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc6376DkimRelaxed), [0x61, 0x20, 0x20, 0x62]).classify.positions,
            [2], "his rfc rfc6376 double space pos")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc6376DkimRelaxed), [0x61, 0x20, 0x62]).classify.tag,
            nil, "his rfc rfc6376 single space clear")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc5751SmimeLineEnding), [0x61, 0x0A, 0x62]).classify.tag,
            "SignedMessageRule", "his rfc rfc5751 bare lf")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .rfc5751SmimeLineEnding), [0x61, 0x0A, 0x62]).classify.positions,
            [1], "his rfc rfc5751 bare lf pos")

        // auditLogReinterpretation.
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(asWritten: [0x61, 0x62, 0x63]), [0x61, 0x62, 0x64]).classify.tag,
            "AuditLogReinterpretation", "his audit divergence")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(asWritten: [0x61, 0x62, 0x63]), [0x61, 0x62, 0x64]).classify.positions,
            [2], "his audit divergence pos")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(asWritten: [0x61, 0x62, 0x63]), [0x61, 0x62, 0x63]).classify.tag,
            nil, "his audit identical clear")

        // webhookSignatureDrift.
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(serverBytes: [0x61, 0x62, 0x64]), [0x61, 0x62, 0x63]).classify.tag,
            "WebhookSignatureDrift", "his webhook drift")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(serverBytes: [0x61, 0x62, 0x64]), [0x61, 0x62, 0x63]).classify.positions,
            [2], "his webhook drift pos")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(serverBytes: [0x61, 0x62, 0x63]), [0x61, 0x62, 0x63]).classify.tag,
            nil, "his webhook match clear")

        // Priority ordering.
        try expectEqual(
            hashInputStabilityDetectWithContext(
                HashInputStabilityContext(declaredEncoding: "utf-16", rfcRule: .pgp9580LineEnding),
                [0x0065, 0x0301, 0x0A]).classify.tag,
            "EncodingMismatch", "his priority encoding over rfc")
        try expectEqual(
            hashInputStabilityDetectWithContext(
                HashInputStabilityContext(asWritten: [0x61, 0x62, 0x66], serverBytes: [0x61, 0x62, 0x65]),
                [0x61, 0x62, 0x63]).classify.tag,
            "WebhookSignatureDrift", "his priority webhook over audit")
        try expectEqual(
            hashInputStabilityDetectWithContext(HashInputStabilityContext(rfcRule: .pgp4880TrailingWhitespace), [0x61, 0x20]).classify.tag,
            "SignedMessageRule", "his priority rfc over trailing")

        // default context equals bare detect.
        try expectEqual(
            hashInputStabilityDetectWithContext(.default, [0x61, 0x62, 0x63]).classify,
            hashInputStabilityDetect([0x61, 0x62, 0x63]).classify, "his default matches detect")

        // RfcRule tag round-trip.
        for rule: RfcRule in [
            .pgp4880TrailingWhitespace, .pgp9580LineEnding, .rfc8785NfcRequirement,
            .rfc8259ControlChar, .rfc7515JwsBase64Url, .rfc6376DkimRelaxed, .rfc5751SmimeLineEnding,
        ] {
            try expectEqual(RfcRule.fromTag(rule.tag), rule, "his rfc rule roundtrip \(rule.tag)")
        }
        try expectEqual(RfcRule.fromTag("nope"), nil, "his rfc rule unknown")
    }

    // Pins aiWatermarkDetectabilityDetect against the ground-truth theorems in
    // Unicode/Security/Crypto/AiWatermarkDetectability.lean: the shared context-free
    // fixture runs through detect; the two Context-tolerance vectors (which the
    // shared detector-fixture schema cannot express) are transcribed from the
    // Rust reference's test module (detect_zwsp_jittered_*).
    private static func testAiWatermarkDetectability() throws {
        // Shared context-free fixture through detect. required_findings carries
        // full reason codes (unicode.security.K.ai-watermark-detectability.<Tag>);
        // an empty list means clear.
        let fixture = try loadFixture("detectors/ai_watermark_detectability.json")
        try expectEqual(fixture["schema"] as? Int, 1, "ai-watermark-detectability schema")
        try expectEqual(try string(fixture, "family"), "ai-watermark-detectability", "ai-watermark-detectability family")
        for entry in try array(fixture, "cases") {
            let name = try string(entry, "name")
            let input = try intArray(entry, "input")
            let required = try stringArray(entry, "required_findings")
            if let tag = aiWatermarkDetectabilityDetect(input).classify.tag {
                let code = aiWatermarkDetectabilityReasonCode(tag)
                try expect(required.contains(code), "ai-watermark-detectability \(name): expected \(code) in \(required)")
            } else {
                try expect(required.isEmpty, "ai-watermark-detectability \(name): expected clear, got \(required)")
            }
        }

        // ── Context-tolerance vectors, transcribed from the Rust reference.
        // ZWSPs at 1, 3, 6 (gaps 2, 3). Bare detect (tolerance 0) does not fire
        // gpt5ZwspModulo; it falls through to defaultIgnorableCarrier.
        let jittered = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65]
        try expectEqual(
            aiWatermarkDetectabilityDetect(jittered).classify.tag,
            "DefaultIgnorableCarrier", "aiwm zwsp jittered strict")
        // With zwspModuloTolerance 1, the light jitter is within tolerance and
        // gpt5ZwspModulo fires.
        try expectEqual(
            aiWatermarkDetectabilityDetectWithContext(
                AiWatermarkDetectabilityContext(zwspModuloTolerance: 1), jittered).classify.tag,
            "Gpt5ZwspModulo", "aiwm zwsp jittered tolerant")

        // Default context equals bare detect.
        try expectEqual(
            aiWatermarkDetectabilityDetectWithContext(.default, [0x61, 0x202F, 0x62]).classify,
            aiWatermarkDetectabilityDetect([0x61, 0x202F, 0x62]).classify,
            "aiwm default matches detect")
    }

    // Pins streamSafeViolationDetect against the detect_* ground-truth theorems
    // in Unicode/Security/Form/StreamSafeViolation.lean: the shared context-free
    // fixture runs through detect, plus the 30/31 boundary case is asserted
    // directly (max run of 30 stays clear under strict `>`; 31 fires
    // StreamSafeOverrun at basePos 1).
    private static func testStreamSafeViolation() throws {
        // Shared context-free fixture through detect. required_findings carries
        // full reason codes (unicode.security.F.stream-safe-violation.<Tag>);
        // an empty list means clear.
        let fixture = try loadFixture("detectors/stream_safe_violation.json")
        try expectEqual(fixture["schema"] as? Int, 1, "stream-safe-violation schema")
        try expectEqual(try string(fixture, "family"), "stream-safe-violation", "stream-safe-violation family")
        for entry in try array(fixture, "cases") {
            let name = try string(entry, "name")
            let input = try intArray(entry, "input")
            let required = try stringArray(entry, "required_findings")
            if let tag = streamSafeViolationDetect(input).classify.tag {
                let code = streamSafeViolationReasonCode(tag)
                try expect(required.contains(code), "stream-safe-violation \(name): expected \(code) in \(required)")
            } else {
                try expect(required.isEmpty, "stream-safe-violation \(name): expected clear, got \(required)")
            }
        }

        // ── 30/31 boundary, asserted directly. U+0301 COMBINING ACUTE ACCENT
        // has CCC = 230 (a non-starter); the leading "a" (U+0061) is a starter.
        let acute = 0x0301
        func aPlusMarks(_ n: Int) -> [Int] { [0x61] + Array(repeating: acute, count: n) }

        // Exactly 30 marks: the maximal run is 30, which does not exceed the
        // limit under strict `>`, so the input stays clear.
        let thirty = streamSafeViolationDetect(aPlusMarks(30))
        try expect(thirty.classify.isClear, "stream-safe-violation 30 marks clear")
        try expectEqual(thirty.classify.tag, nil, "stream-safe-violation 30 marks tag")
        try expectEqual(thirty.maxRunLen, 30, "stream-safe-violation 30 marks maxRunLen")
        try expectEqual(thirty.overrunCount, 0, "stream-safe-violation 30 marks overrunCount")
        try expectEqual(thirty.totalNonStarters, 30, "stream-safe-violation 30 marks totalNonStarters")

        // 31 marks: the run overruns; StreamSafeOverrun fires at basePos 1.
        let thirtyOne = streamSafeViolationDetect(aPlusMarks(31))
        try expect(!thirtyOne.classify.isClear, "stream-safe-violation 31 marks hazard")
        try expectEqual(thirtyOne.classify.tag, "StreamSafeOverrun", "stream-safe-violation 31 marks tag")
        try expectEqual(thirtyOne.classify.positions, [1], "stream-safe-violation 31 marks positions")
        try expectEqual(
            thirtyOne.classify,
            .hazard(sub: .streamSafeOverrun(basePos: 1, runLen: 31), positions: [1], decoded: []),
            "stream-safe-violation 31 marks classification")
        try expectEqual(thirtyOne.maxRunLen, 31, "stream-safe-violation 31 marks maxRunLen")
        try expectEqual(thirtyOne.overrunCount, 1, "stream-safe-violation 31 marks overrunCount")
        try expectEqual(thirtyOne.totalNonStarters, 31, "stream-safe-violation 31 marks totalNonStarters")

        // A bare 31-mark run (no leading starter) opens its run at index 0.
        let bare = streamSafeViolationDetect(Array(repeating: acute, count: 31))
        try expectEqual(bare.classify.tag, "StreamSafeOverrun", "stream-safe-violation bare run tag")
        try expectEqual(bare.classify.positions, [0], "stream-safe-violation bare run positions")

        // Default reason code shape.
        try expectEqual(
            streamSafeViolationReasonCode("StreamSafeOverrun"),
            "unicode.security.F.stream-safe-violation.StreamSafeOverrun",
            "stream-safe-violation reason code")
    }

    // Pins emojiZwjIntegrityDetect against the ground-truth theorems in
    // Unicode/Security/Identity/EmojiZwjIntegrity.lean and the verified Rust
    // reference: the shared context-free fixture runs through detect, plus the
    // 11 Rust spot-checks and 3 structural checks are asserted directly.
    private static func testEmojiZwjIntegrity() throws {
        // Shared context-free fixture through detect. required_findings carries
        // full reason codes (unicode.security.I.emoji-zwj-integrity.<Tag>);
        // an empty list means clear.
        let fixture = try loadFixture("detectors/emoji_zwj_integrity.json")
        try expectEqual(fixture["schema"] as? Int, 1, "emoji-zwj-integrity schema")
        try expectEqual(try string(fixture, "family"), "emoji-zwj-integrity", "emoji-zwj-integrity family")
        for entry in try array(fixture, "cases") {
            let name = try string(entry, "name")
            let input = try intArray(entry, "input")
            let required = try stringArray(entry, "required_findings")
            if let tag = emojiZwjIntegrityDetect(input).classify.tag {
                let code = emojiZwjIntegrityReasonCode(tag)
                try expect(required.contains(code), "emoji-zwj-integrity \(name): expected \(code) in \(required)")
            } else {
                try expect(required.isEmpty, "emoji-zwj-integrity \(name): expected clear, got \(required)")
            }
        }

        // ── data-layer sanity (mirrors the Rust data-layer tests). ──────────
        try expect(emojiZwjIsEmojiModifier(0x1F3FB), "emoji-zwj modifier low bound")
        try expect(emojiZwjIsEmojiModifier(0x1F3FF), "emoji-zwj modifier high bound")
        try expect(!emojiZwjIsEmojiModifier(0x1F3FA), "emoji-zwj modifier below range")
        try expect(!emojiZwjIsEmojiModifier(0x1F600), "emoji-zwj modifier grinning excluded")
        // U+2764 HEAVY BLACK HEART and U+1F468 MAN appear in registered RGI
        // sequences; U+1F600 GRINNING FACE does not; the joiner is excluded.
        try expect(emojiZwjIsEmojiTarget(0x2764), "emoji-zwj alphabet admits heart")
        try expect(emojiZwjIsEmojiTarget(0x1F468), "emoji-zwj alphabet admits man")
        try expect(!emojiZwjIsEmojiTarget(0x1F600), "emoji-zwj alphabet rejects grinning")
        try expect(!emojiZwjIsEmojiTarget(emojiZwjZwj), "emoji-zwj alphabet excludes joiner")
        // MAN + ZWJ + LAPTOP is registered; MAN + ZWJ + WOMAN is not.
        try expect(
            emojiZwjIsRegisteredSequence([0x1F468, 0x200D, 0x1F4BB]),
            "emoji-zwj man-technologist registered")
        try expect(
            !emojiZwjIsRegisteredSequence([0x1F468, 0x200D, 0x1F469]),
            "emoji-zwj man-woman unregistered")

        // ── §5 detect spot checks (one per Rust/Lean theorem). ──────────────
        // detect_empty_clear
        let empty = emojiZwjIntegrityDetect([])
        try expect(empty.classify.isClear, "emoji-zwj empty clear")
        try expectEqual(empty.classify.tag, nil, "emoji-zwj empty tag")
        try expectEqual(empty.zwjPositions, [], "emoji-zwj empty positions")
        try expectEqual(empty.chainLength, 0, "emoji-zwj empty chainLength")
        try expectEqual(empty.skinToneCount, 0, "emoji-zwj empty skinToneCount")
        // detect_ascii_clear
        try expect(
            emojiZwjIntegrityDetect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear,
            "emoji-zwj ascii clear")
        // detect_plain_emoji_clear
        try expect(emojiZwjIntegrityDetect([0x1F600]).classify.isClear, "emoji-zwj plain emoji clear")
        // detect_one_skintone_clear
        let oneSkin = emojiZwjIntegrityDetect([0x1F44B, 0x1F3FB])
        try expect(oneSkin.classify.isClear, "emoji-zwj one skintone clear")
        try expectEqual(oneSkin.skinToneCount, 1, "emoji-zwj one skintone count")
        // detect_family_rgi_clear
        let family = emojiZwjIntegrityDetect([0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466])
        try expect(family.classify.isClear, "emoji-zwj family rgi clear")
        try expect(family.isRegisteredRgi, "emoji-zwj family rgi registered")
        // detect_double_zwj
        let dbl = emojiZwjIntegrityDetect([0x1F600, 0x200D, 0x200D, 0x1F600])
        try expectEqual(dbl.classify.tag, "DoubleZWJ", "emoji-zwj double zwj tag")
        try expectEqual(dbl.classify.positions, [1], "emoji-zwj double zwj positions")
        // detect_non_emoji_injection
        try expectEqual(
            emojiZwjIntegrityDetect([0x1F600, 0x200D, 0x0061]).classify.tag,
            "NonEmojiInjection", "emoji-zwj non-emoji injection tag")
        // detect_skin_tone_overflow
        let overflow = emojiZwjIntegrityDetect([0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF])
        try expectEqual(overflow.classify.tag, "SkinToneOverflow", "emoji-zwj skin overflow tag")
        try expectEqual(overflow.skinToneCount, 5, "emoji-zwj skin overflow count")
        // detect_man_laptop_registered_clear
        try expect(
            emojiZwjIntegrityDetect([0x1F468, 0x200D, 0x1F4BB]).classify.isClear,
            "emoji-zwj man-laptop registered clear")
        // detect_unregistered
        try expectEqual(
            emojiZwjIntegrityDetect([0x1F468, 0x200D, 0x1F469]).classify.tag,
            "UnregisteredSequence", "emoji-zwj unregistered tag")
        // detect_grinning_laptop_non_emoji_injection
        try expectEqual(
            emojiZwjIntegrityDetect([0x1F600, 0x200D, 0x1F4BB]).classify.tag,
            "NonEmojiInjection", "emoji-zwj grinning-laptop injection tag")

        // ── structural checks (follow from the priority ladder). ────────────
        // A 9-man / 8-ZWJ chain (17 codepoints) exceeds the cap and, hitting no
        // earlier sub-threat, surfaces as OverLength.
        var overLen: [Int] = []
        for i in 0..<9 {
            if i > 0 { overLen.append(0x200D) }
            overLen.append(0x1F468)
        }
        try expectEqual(overLen.count, 17, "emoji-zwj over-length input size")
        let ol = emojiZwjIntegrityDetect(overLen)
        try expectEqual(ol.classify.tag, "OverLength", "emoji-zwj over-length tag")
        try expectEqual(
            ol.classify,
            .hazard(sub: .overLength(length: 17, maxLength: emojiZwjMaxRgiLength), positions: [], decoded: []),
            "emoji-zwj over-length classification")
        // A ZWJ at the trailing edge is an injection-class hazard at position 1.
        let trailing = emojiZwjIntegrityDetect([0x1F468, 0x200D])
        try expectEqual(trailing.classify.tag, "NonEmojiInjection", "emoji-zwj trailing zwj tag")
        try expectEqual(trailing.classify.positions, [1], "emoji-zwj trailing zwj positions")
        // Double-ZWJ wins over the unregistered catch-all (priority order).
        try expectEqual(
            emojiZwjIntegrityDetect([0x1F468, 0x200D, 0x200D, 0x1F466]).classify.tag,
            "DoubleZWJ", "emoji-zwj double beats unregistered")

        // Reason-code shape.
        try expectEqual(
            emojiZwjIntegrityReasonCode("DoubleZWJ"),
            "unicode.security.I.emoji-zwj-integrity.DoubleZWJ",
            "emoji-zwj reason code")
    }

    // Pins rendererDivergenceDetect against the ground-truth theorems in
    // Unicode/Security/Display/RendererDivergence.lean and the verified Rust
    // reference: the shared context-free fixture runs through detect, plus the
    // 9 Rust spot-checks and 2 structural checks are asserted directly.
    private static func testRendererDivergence() throws {
        // Shared context-free fixture through detect. required_findings carries
        // full reason codes (unicode.security.D.renderer-divergence.<Tag>);
        // an empty list means clear.
        let fixture = try loadFixture("detectors/renderer_divergence.json")
        try expectEqual(fixture["schema"] as? Int, 1, "renderer-divergence schema")
        try expectEqual(try string(fixture, "family"), "renderer-divergence", "renderer-divergence family")
        for entry in try array(fixture, "cases") {
            let name = try string(entry, "name")
            let input = try intArray(entry, "input")
            let required = try stringArray(entry, "required_findings")
            if let tag = rendererDivergenceDetect(input).classify.tag {
                let code = rendererDivergenceReasonCode(tag)
                try expect(required.contains(code), "renderer-divergence \(name): expected \(code) in \(required)")
            } else {
                try expect(required.isEmpty, "renderer-divergence \(name): expected clear, got \(required)")
            }
        }

        // ── §5 detect spot checks (one per Rust/Lean theorem). ──────────────
        // detect_empty_clear
        try expect(rendererDivergenceDetect([]).classify.isClear, "renderer-divergence empty clear")
        // detect_ascii_clear
        try expect(
            rendererDivergenceDetect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear,
            "renderer-divergence ascii clear")
        // detect_han_clear
        try expect(rendererDivergenceDetect([0x4E2D, 0x6587]).classify.isClear, "renderer-divergence han clear")
        // detect_vs_variance — a single VS (FE0F) after an emoji.
        try expectEqual(
            rendererDivergenceDetect([0x1F600, 0xFE0F]).classify.tag,
            "VariationSelectorVariance", "renderer-divergence vs variance")
        // detect_rgi_family_clear — a registered RGI family ZWJ sequence.
        let family = rendererDivergenceDetect([0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466])
        try expect(family.classify.isClear, "renderer-divergence rgi family clear")
        try expect(family.hasZwj, "renderer-divergence rgi family has zwj")
        // detect_unregistered_zwj_variance — man + ZWJ + woman, not in RGI.
        try expectEqual(
            rendererDivergenceDetect([0x1F468, 0x200D, 0x1F469]).classify.tag,
            "UnregisteredZwjVariance", "renderer-divergence unregistered zwj variance")
        // detect_zalgo_variance — a 4-deep combining stack.
        let zalgo = rendererDivergenceDetect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304])
        try expectEqual(zalgo.classify.tag, "CombiningStackOverflow", "renderer-divergence zalgo tag")
        try expectEqual(zalgo.classify.positions, [0], "renderer-divergence zalgo positions")
        try expectEqual(zalgo.combiningCount, 4, "renderer-divergence zalgo combining count")
        // detect_fullwidth_variance — fullwidth 'A'.
        try expectEqual(
            rendererDivergenceDetect([0xFF21]).classify.tag,
            "FullwidthVariance", "renderer-divergence fullwidth variance")
        // detect_mixed_direction — Latin + Hebrew in one input.
        let mixed = rendererDivergenceDetect([0x41, 0x42, 0x05D0, 0x05D1])
        try expectEqual(mixed.classify.tag, "MixedDirectionVariance", "renderer-divergence mixed direction tag")
        try expect(
            mixed.strongLtrCount > 0 && mixed.strongRtlCount > 0,
            "renderer-divergence mixed direction counts")

        // ── priority-ladder structural checks. ──────────────────────────────
        // A combining stack outranks a variation selector present later.
        try expectEqual(
            rendererDivergenceDetect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F]).classify.tag,
            "CombiningStackOverflow", "renderer-divergence combining stack beats vs")
        // Exactly three combining marks is below the stack threshold — no overflow.
        try expect(
            rendererDivergenceDetect([0x0061, 0x0301, 0x0302, 0x0303]).classify.tag != "CombiningStackOverflow",
            "renderer-divergence three marks below threshold")

        // Reason-code shape.
        try expectEqual(
            rendererDivergenceReasonCode("MixedDirectionVariance"),
            "unicode.security.D.renderer-divergence.MixedDirectionVariance",
            "renderer-divergence reason code")
    }

    // Pins filenameDisguiseDetect against the ground-truth theorems in
    // Unicode/Security/Display/FilenameDisguise.lean and the verified Rust
    // reference: the shared context-free fixture runs through detect, plus the
    // 10 Rust spot-checks and 1 structural check are asserted directly.
    private static func testFilenameDisguise() throws {
        // Shared context-free fixture through detect. required_findings carries
        // full reason codes (unicode.security.D.filename-disguise.<Tag>);
        // an empty list means clear.
        let fixture = try loadFixture("detectors/filename_disguise.json")
        try expectEqual(fixture["schema"] as? Int, 1, "filename-disguise schema")
        try expectEqual(try string(fixture, "family"), "filename-disguise", "filename-disguise family")
        for entry in try array(fixture, "cases") {
            let name = try string(entry, "name")
            let input = try intArray(entry, "input")
            let required = try stringArray(entry, "required_findings")
            if let tag = filenameDisguiseDetect(input).classify.tag {
                let code = filenameDisguiseReasonCode(tag)
                try expect(required.contains(code), "filename-disguise \(name): expected \(code) in \(required)")
            } else {
                try expect(required.isEmpty, "filename-disguise \(name): expected clear, got \(required)")
            }
        }

        // ── §5 detect spot checks (one per Rust/Lean theorem). ──────────────
        // detect_empty_clear
        try expect(filenameDisguiseDetect([]).classify.isClear, "filename-disguise empty clear")
        // detect_plain_txt_clear — "document.txt"
        let plain = filenameDisguiseDetect([0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74])
        try expect(plain.classify.isClear, "filename-disguise plain txt clear")
        try expectEqual(plain.lastDotPos, 8, "filename-disguise plain txt last dot")
        // detect_no_extension_clear — "foo"
        let noExt = filenameDisguiseDetect([0x66, 0x6F, 0x6F])
        try expect(noExt.classify.isClear, "filename-disguise no extension clear")
        try expectEqual(noExt.lastDotPos, nil, "filename-disguise no extension last dot")
        // detect_tar_gz_clear — "archive.tar.gz" (2 dots, below the multi-ext bound)
        try expect(
            filenameDisguiseDetect([0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A])
                .classify.isClear,
            "filename-disguise tar.gz clear")
        // detect_hebrew_clear — native Hebrew name, no bidi controls.
        try expect(
            filenameDisguiseDetect([0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74]).classify.isClear,
            "filename-disguise hebrew clear")
        // detect_rlo_flip — "document<RLO>txt.exe"
        let rlo = filenameDisguiseDetect([
            0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65,
        ])
        try expectEqual(rlo.classify.tag, "RloFlip", "filename-disguise rlo flip tag")
        try expectEqual(rlo.classify.positions, [8], "filename-disguise rlo flip positions")
        // detect_isolate_flip — RLI/PDI isolate variant, also RloFlip.
        try expectEqual(
            filenameDisguiseDetect([0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069])
                .classify.tag,
            "RloFlip", "filename-disguise isolate flip tag")
        // detect_fullwidth_exe — "file.ＥＸＥ"
        try expectEqual(
            filenameDisguiseDetect([0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25]).classify.tag,
            "WidthClassExt", "filename-disguise fullwidth exe tag")
        // detect_combining_in_ext — "file.é xe" (combining acute in the extension)
        try expectEqual(
            filenameDisguiseDetect([0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65]).classify.tag,
            "CombiningInExt", "filename-disguise combining in ext tag")
        // detect_triple_extension — "setup.tar.gz.sig"
        try expectEqual(
            filenameDisguiseDetect([
                0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A, 0x2E, 0x73, 0x69, 0x67,
            ]).classify.tag,
            "MultipleExtensions", "filename-disguise triple extension tag")

        // ── priority-ladder structural check. ───────────────────────────────
        // A bidi control outranks a fullwidth extension.
        try expectEqual(
            filenameDisguiseDetect([0x202E, 0x66, 0x2E, 0xFF25]).classify.tag,
            "RloFlip", "filename-disguise bidi beats fullwidth")

        // Reason-code shape.
        try expectEqual(
            filenameDisguiseReasonCode("RloFlip"),
            "unicode.security.D.filename-disguise.RloFlip",
            "filename-disguise reason code")
    }

    // Pins identifierFormDriftDetect against the ground-truth theorems in
    // Unicode/Security/Boundary/IdentifierFormDrift.lean and the verified Rust
    // reference: the shared context-free fixture runs through detect, plus the
    // per-theorem spot checks and the mid-string first-shift-position case.
    private static func testIdentifierFormDrift() throws {
        // Shared context-free fixture through detect. required_findings carries
        // full reason codes (unicode.security.X.identifier-form-drift.<Tag>);
        // an empty list means clear.
        let fixture = try loadFixture("detectors/identifier_form_drift.json")
        try expectEqual(fixture["schema"] as? Int, 1, "identifier-form-drift schema")
        try expectEqual(try string(fixture, "family"), "identifier-form-drift", "identifier-form-drift family")
        for entry in try array(fixture, "cases") {
            let name = try string(entry, "name")
            let input = try intArray(entry, "input")
            let required = try stringArray(entry, "required_findings")
            if let tag = identifierFormDriftDetect(input).classify.tag {
                let code = identifierFormDriftReasonCode(tag)
                try expect(required.contains(code), "identifier-form-drift \(name): expected \(code) in \(required)")
            } else {
                try expect(required.isEmpty, "identifier-form-drift \(name): expected clear, got \(required)")
            }
        }

        // ── §5 detect spot checks (one per Rust/Lean theorem). ──────────────
        // detect_empty_clear
        try expect(identifierFormDriftDetect([]).classify.isClear, "identifier-form-drift empty clear")
        // detect_ascii_clear — "Hello"; every ASCII letter Allowed, identity NFKD.
        let hello = identifierFormDriftDetect([0x48, 0x65, 0x6C, 0x6C, 0x6F])
        try expect(hello.classify.isClear, "identifier-form-drift ascii clear")
        try expectEqual(hello.shiftCount, 0, "identifier-form-drift ascii shift count")
        // detect_greek_alpha_clear — α Allowed with identity NFKD.
        try expect(identifierFormDriftDetect([0x03B1]).classify.isClear, "identifier-form-drift greek alpha clear")
        // detect_math_italic_a_shift — U+1D44E Restricted, NFKD head U+0061 Allowed.
        let mathA = identifierFormDriftDetect([0x1D44E])
        try expectEqual(mathA.classify.tag, "IdentifierStatusShift", "identifier-form-drift math italic a tag")
        try expectEqual(mathA.classify.positions, [0], "identifier-form-drift math italic a positions")
        try expectEqual(mathA.shiftCount, 1, "identifier-form-drift math italic a shift count")
        // detect_fullwidth_A_shift — U+FF21 Restricted, NFKD head U+0041 Allowed.
        try expectEqual(
            identifierFormDriftDetect([0xFF21]).classify.tag,
            "IdentifierStatusShift", "identifier-form-drift fullwidth A tag")
        // detect_circled_A_shift — U+24B6 Restricted, NFKD head U+0041 Allowed.
        try expectEqual(
            identifierFormDriftDetect([0x24B6]).classify.tag,
            "IdentifierStatusShift", "identifier-form-drift circled A tag")
        // detect_fi_ligature_shift — U+FB01 Restricted, NFKD head U+0066 Allowed.
        try expectEqual(
            identifierFormDriftDetect([0xFB01]).classify.tag,
            "IdentifierStatusShift", "identifier-form-drift fi ligature tag")
        // detect_roman_iv_shift — U+2163 Restricted, NFKD head U+0049 Allowed.
        try expectEqual(
            identifierFormDriftDetect([0x2163]).classify.tag,
            "IdentifierStatusShift", "identifier-form-drift roman iv tag")

        // detect_reports_first_shift_position — "ab" + U+1D44E: positions 0,1 are
        // Allowed/identity, position 2 shifts.
        let midString = identifierFormDriftDetect([0x61, 0x62, 0x1D44E])
        try expectEqual(midString.classify.positions, [2], "identifier-form-drift mid-string positions")
        try expectEqual(midString.shiftCount, 1, "identifier-form-drift mid-string shift count")

        // Reason-code shape.
        try expectEqual(
            identifierFormDriftReasonCode("IdentifierStatusShift"),
            "unicode.security.X.identifier-form-drift.IdentifierStatusShift",
            "identifier-form-drift reason code")
    }

    // Pins the covert-display-compound detector against the detect_* spot-check
    // theorems in Unicode/Security/Boundary/CovertDisplayCompound.lean.
    private static func testCovertDisplayCompound() throws {
        let cases: [(String, [Int], String?)] = [
            ("clear-empty", [], nil),
            ("clear-ascii-hello", [0x48, 0x65, 0x6C, 0x6C, 0x6F], nil),
            ("clear-rlo-alone", [0x202E], nil),
            ("clear-vs-no-bidi", [0x0041, 0xFE00], nil),
            ("bidi-plus-unregistered-vs", [0x202E, 0x0041, 0xFE00], "BidiPlusUnregisteredVs"),
            ("bidi-plus-tag-block", [0x202E, 0x0041, 0xE0001], "BidiPlusTagBlock"),
        ]
        for (name, input, want) in cases {
            try expectEqual(covertDisplayCompoundDetect(input).subThreat, want, "covert-display-compound \(name)")
        }
    }

    // Pins the confusable-bidi-compound detector against the detect_* spot-check
    // theorems in Unicode/Security/Boundary/ConfusableBidiCompound.lean.
    private static func testConfusableBidiCompound() throws {
        let cases: [(String, [Int], String?)] = [
            ("clear-empty", [], nil),
            ("clear-ascii-hello", [0x48, 0x65, 0x6C, 0x6C, 0x6F], nil),
            ("clear-override-no-confusable", [0x202E, 0x0041, 0x0042, 0x0043], nil),
            ("clear-confusable-no-bidi", [0x0430], nil),
            ("override-cyrillic-a", [0x202E, 0x0430], "ConfusableInOverride"),
            ("isolate-greek-o", [0x2066, 0x03BF], "ConfusableInIsolate"),
        ]
        for (name, input, want) in cases {
            try expectEqual(confusableBidiCompoundDetect(input).subThreat, want, "confusable-bidi-compound \(name)")
        }
    }

    // Pins the surrogate-reassembly detector against the detect_* spot-check
    // theorems in Unicode/Security/Covert/SurrogateReassembly.lean. Each byte
    // stream is scanned; the surrogate-reassembly finding's sub-threat (or its
    // absence, for a clear input) must match the Lean verdict.
    private static func testSurrogateReassembly() throws {
        let cases: [(String, [Int], String?)] = [
            ("clear-empty", [], nil),
            ("clear-ascii", [0x48, 0x65, 0x6C, 0x6C, 0x6F], nil),
            ("clear-e-acute", [0xC3, 0xA9], nil),
            ("clear-han", [0xE4, 0xB8, 0xAD], nil),
            ("clear-emoji", [0xF0, 0x9F, 0x98, 0x80], nil),
            ("invalid-start-c080", [0xC0, 0x80], "InvalidStartByte"),
            ("invalid-start-c0af", [0xC0, 0xAF], "InvalidStartByte"),
            ("invalid-start-fe", [0xFE], "InvalidStartByte"),
            ("invalid-start-lone-cont", [0x80], "InvalidStartByte"),
            ("invalid-start-ff", [0xFF], "InvalidStartByte"),
            ("overlong-3byte", [0xE0, 0x80, 0xAF], "Overlong"),
            ("overlong-4byte", [0xF0, 0x80, 0x80, 0xAF], "Overlong"),
            ("cesu8-surrogate", [0xED, 0xA0, 0x80], "Cesu8"),
            ("cesu8-surrogate-high", [0xED, 0xAF, 0xBF], "Cesu8"),
            ("truncated-2byte", [0xC3], "Truncated"),
            ("truncated-4byte", [0xF0, 0x9F, 0x98], "Truncated"),
            ("non-byte-stream-emoji", [0x1F600], nil),
            ("non-byte-stream-mixed", [0x41, 0x100], nil),
        ]
        for (name, input, want) in cases {
            let verdict = scan(profile: Profile.gatewayHeader, mode: Mode.observe, input: input)
            let sub = verdict.findings.first { $0.family == Family.surrogateReassembly }?.subThreat
            try expectEqual(sub, want, "surrogate-reassembly \(name)")
        }
    }

    // Pins the RTL-injection detector against the detect_* spot-check
    // theorems in Unicode/Security/Display/RtlInjection.lean.
    private static func testRtlInjection() throws {
        let cases: [(String, [Int], String?)] = [
            ("clear-digits", [0x30, 0x31, 0x32, 0x33], nil),
            ("clear-cyrillic", [0x043F], nil),
            ("rlo-in-ltr", [0x41, 0x202E, 0x42], "RloInLTRField"),
            ("field-takeover-hebrew", [0x05D0, 0x42, 0x43], "FieldTakeover"),
            ("field-takeover-arabic", [0x0627, 0x42, 0x43], "FieldTakeover"),
            ("mid-stream-hebrew", [0x41, 0x42, 0x05D0, 0x44], "StrongRTLInLTR"),
            ("overflow-hebrew", [0x41, 0x42, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x44], "MixedOverflow"),
        ]
        for (name, input, want) in cases {
            try expectEqual(rtlInjectionDetect(input).subThreat, want, "rtl-injection \(name)")
        }
    }

    // Pins the locale-case-inversion detector against the detect_* spot-check
    // theorems in Unicode/Security/Form/LocaleCaseInversion.lean.
    private static func testLocaleCaseInversion() throws {
        try expectEqual(localeCaseInversionDetect([]).subThreat, nil, "locale-case-inversion empty")
        try expectEqual(localeCaseInversionDetect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).subThreat, nil, "locale-case-inversion ascii")
        try expectEqual(localeCaseInversionDetect([0x0049]).subThreat, "TurkishCaseDivergence", "locale-case-inversion capital-I")
        try expectEqual(localeCaseInversionDetect([0x0049]).positions, [0], "locale-case-inversion capital-I pos")
        try expectEqual(localeCaseInversionDetect([0x0130]).subThreat, "TurkishCaseDivergence", "locale-case-inversion dotted-I")
        try expectEqual(localeCaseInversionDetect([0x0049, 0x0300]).subThreat, "TurkishCaseDivergence", "locale-case-inversion I-grave")
        try expectEqual(localeCaseInversionDetect([0x004A, 0x0300]).subThreat, "LithuanianCaseDivergence", "locale-case-inversion J-grave")
    }

    private static func testNormalizationBomb() throws {
        try expectEqual(normalizationBombDetect([]).subThreat, nil, "normalization-bomb empty")
        try expectEqual(normalizationBombDetect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).subThreat, nil, "normalization-bomb ascii")
        try expectEqual(normalizationBombDetect([0xD55C]).subThreat, nil, "normalization-bomb korean")
        try expectEqual(normalizationBombDetect([0x2460]).subThreat, nil, "normalization-bomb circled-one")
        try expectEqual(normalizationBombDetect([0xFDFA]).subThreat, "SingleCpBlowup", "normalization-bomb arabic-ligature")
        try expectEqual(normalizationBombDetect([0xFDFA]).positions, [0], "normalization-bomb arabic-ligature pos")
        try expectEqual(normalizationBombDetect([0xFDFB]).subThreat, "NfkdHighExpansion", "normalization-bomb fdfb")
        try expectEqual(normalizationBombDetect([0x1F82]).subThreat, "NfdHighExpansion", "normalization-bomb greek-extended")
    }

    private static func testNfcIdempotenceWitness() throws {
        try expectEqual(nfcIdempotenceWitnessDetect([]).subThreat, nil, "nfc-idempotence empty")
        try expectEqual(nfcIdempotenceWitnessDetect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).subThreat, nil, "nfc-idempotence ascii")
        try expectEqual(nfcIdempotenceWitnessDetect([0x00E9]).subThreat, nil, "nfc-idempotence precomposed-e-acute")
        try expectEqual(nfcIdempotenceWitnessDetect([0x0065, 0x0301]).subThreat, "NonNfcForm", "nfc-idempotence decomposed-e-acute")
        try expectEqual(nfcIdempotenceWitnessDetect([0x0065, 0x0301]).positions, [0], "nfc-idempotence decomposed-e-acute pos")
        try expectEqual(nfcIdempotenceWitnessDetect([0xFB01]).subThreat, "NonNfkcCompatForm", "nfc-idempotence fi-ligature")
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

    // Pins the Utf8Blob / ValidatedUtf8 byte-layer refinements against the
    // strict RFC 3629 validator.
    private static func testOpaqueBlob() throws {
        try expect(isUtf8Blob([0x48, 0x69]), "blob ascii")
        try expect(isUtf8Blob([0xC3, 0xA9]), "blob 2-byte")
        try expect(isUtf8Blob([0xF0, 0x9F, 0x98, 0x80]), "blob 4-byte")
        try expect(!isUtf8Blob([0xC0, 0x80]), "blob overlong rejected")
        try expect(!isUtf8Blob([0xED, 0xA0, 0x80]), "blob surrogate rejected")

        guard let within = Utf8Blob.of([0x48, 0x69], maxBytes: 16) else {
            throw TestError.message("blob within bound returned nil")
        }
        try expectEqual(within.value, [0x48, 0x69], "blob value")
        try expectEqual(within.maxBytes, 16, "blob maxBytes")
        try expect(Utf8Blob.of([0x48, 0x69, 0x21], maxBytes: 2) == nil, "blob over bound")
        try expect(Utf8Blob.of([0xC0, 0x80], maxBytes: 16) == nil, "blob malformed")
        try expect(Utf8Blob.of([], maxBytes: 32) != nil, "blob empty any bound")

        guard let validated = ValidatedUtf8.validate([0xC3, 0xA9]) else {
            throw TestError.message("validated rejected valid input")
        }
        try expectEqual(validated.asBytes(), [0xC3, 0xA9], "validated asBytes")
        try expectEqual(ValidatedUtf8.unwrap(validated), [0xC3, 0xA9], "validated unwrap")
        try expect(ValidatedUtf8.validate([0xED, 0xA0, 0x80]) == nil, "validated rejects malformed")
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

    // Pins the compatibility-normalization API against Unicode.Normalization.NFKD
    // and Unicode.Normalization.NFKC: NFKC folds compatibility variants (ligature,
    // circled digit, fullwidth) to their canonical composites while leaving already
    // composed canonical forms untouched, and NFKD expands them to compatibility
    // decompositions in canonical order.
    private static func testCompatibilityNormalization() throws {
        let nfkcCases: [(String, [Int], [Int])] = [
            ("ligature-fi", [0xFB01], [0x66, 0x69]),
            ("circled-one", [0x2460], [0x31]),
            ("fullwidth-A", [0xFF21], [0x41]),
            ("precomposed-e-acute", [0x00E9], [0x00E9]),
            ("decomposed-e-acute", [0x0065, 0x0301], [0x00E9]),
            ("hangul-han", [0x1112, 0x1161, 0x11AB], [0xD55C]),
        ]
        for (name, input, want) in nfkcCases {
            try expectEqual(toNfkc(input), want, "toNfkc \(name)")
        }
        let nfkdCases: [(String, [Int], [Int])] = [
            ("fullwidth-A", [0xFF21], [0x41]),
            ("precomposed-e-acute", [0x00E9], [0x0065, 0x0301]),
        ]
        for (name, input, want) in nfkdCases {
            try expectEqual(toNfkd(input), want, "toNfkd \(name)")
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
