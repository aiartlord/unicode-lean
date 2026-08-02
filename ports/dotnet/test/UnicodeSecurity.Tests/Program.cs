using System.Text.Json;
using UnicodeSecurity;
using UnicodeSecurity.Segmentation;
using His = UnicodeSecurity.Security.HashInputStability;
using Awd = UnicodeSecurity.Security.AiWatermarkDetectability;

TestCovertDisplayCompoundVectors();
TestConfusableBidiCompoundVectors();
TestSurrogateReassemblyVectors();
TestRtlInjectionVectors();
TestPolicyContract();
TestVerdictContract();
TestUtf8DecodeContract();
TestMultiEncodingDecodeContract();
TestDetectorFixtures();
TestCompatNormalizationVectors();
TestCasing();
TestBip39();
TestLocaleCaseInversion();
TestNormalizationBomb();
TestNfcIdempotenceWitness();
TestHashInputStabilityFixture();
TestHashInputStabilityContextVectors();
TestAiWatermarkDetectabilityFixture();
TestAiWatermarkDetectabilityContextVectors();
TestUtf8Blob();
TestValidatedUtf8();
TestGraphemeVectors();
TestGraphemeBreakTestFile();
Console.WriteLine("clean: .NET contract tests pass");

// Direct spot-check of the covert-display-compound detector, mirroring the
// detect_* spot-check theorems in
// Unicode/Security/Boundary/CovertDisplayCompound.lean and the Rust port's
// tests. Runs first so its result is visible before every other test. Sub ==
// null means a clear input; otherwise it is the compound sub-threat tag.
static void TestCovertDisplayCompoundVectors()
{
    var vectors = new (int[] Input, string? Sub)[]
    {
        (System.Array.Empty<int>(), null),
        (new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }, null),
        (new[] { 0x202E }, null),
        (new[] { 0x0041, 0xFE00 }, null),
        (new[] { 0x202E, 0x0041, 0xFE00 }, "BidiPlusUnregisteredVs"),
        (new[] { 0x202E, 0x0041, 0xE0001 }, "BidiPlusTagBlock"),
    };
    foreach (var (input, expected) in vectors)
    {
        var (actual, _) = Security.CovertDisplayCompoundDetect(input);
        var name = "covert-display-compound [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertEqual(expected ?? "<clear>", actual ?? "<clear>", name);
    }
    Console.WriteLine("clean: .NET covert-display-compound 6-vector spot-check passes");
}

// Direct spot-check of the confusable-bidi-compound detector, mirroring the
// detect_* spot-check theorems in
// Unicode/Security/Boundary/ConfusableBidiCompound.lean and the Rust port's
// tests. Runs first so its result is visible before every other test. Sub ==
// null means a clear input; otherwise it is the compound sub-threat tag.
static void TestConfusableBidiCompoundVectors()
{
    var vectors = new (int[] Input, string? Sub)[]
    {
        (System.Array.Empty<int>(), null),
        (new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }, null),
        (new[] { 0x202E, 0x0041, 0x0042, 0x0043 }, null),
        (new[] { 0x0430 }, null),
        (new[] { 0x202E, 0x0430 }, "ConfusableInOverride"),
        (new[] { 0x2066, 0x03BF }, "ConfusableInIsolate"),
    };
    foreach (var (input, expected) in vectors)
    {
        var (actual, _) = Security.ConfusableBidiCompoundDetect(input);
        var name = "confusable-bidi-compound [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertEqual(expected ?? "<clear>", actual ?? "<clear>", name);
    }
    Console.WriteLine("clean: .NET confusable-bidi-compound 6-vector spot-check passes");
}

// Direct spot-check of the surrogate-reassembly detector, mirroring the
// detect_* spot-check theorems in Unicode/Security/Covert/SurrogateReassembly.lean
// and the Rust port's tests. Runs first so its result is visible before every
// other test. Sub == null means a clear input (well-formed, or not a byte
// stream); otherwise it is the malformed-UTF-8 sub-threat tag.
static void TestSurrogateReassemblyVectors()
{
    var vectors = new (int[] Input, string? Sub)[]
    {
        (System.Array.Empty<int>(), null),
        (new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }, null),
        (new[] { 0xC3, 0xA9 }, null),
        (new[] { 0xE4, 0xB8, 0xAD }, null),
        (new[] { 0xF0, 0x9F, 0x98, 0x80 }, null),
        (new[] { 0xC0, 0x80 }, "InvalidStartByte"),
        (new[] { 0xC0, 0xAF }, "InvalidStartByte"),
        (new[] { 0xFE }, "InvalidStartByte"),
        (new[] { 0x80 }, "InvalidStartByte"),
        (new[] { 0xFF }, "InvalidStartByte"),
        (new[] { 0xE0, 0x80, 0xAF }, "Overlong"),
        (new[] { 0xF0, 0x80, 0x80, 0xAF }, "Overlong"),
        (new[] { 0xED, 0xA0, 0x80 }, "Cesu8"),
        (new[] { 0xED, 0xAF, 0xBF }, "Cesu8"),
        (new[] { 0xC3 }, "Truncated"),
        (new[] { 0xF0, 0x9F, 0x98 }, "Truncated"),
        // The unit detect clamps values > 0xFF to 0xFF (mirroring the Lean
        // toBytes helper), so it surfaces InvalidStartByte. The scan
        // orchestrator gates these out (mirroring runAll).
        (new[] { 0x1F600 }, "InvalidStartByte"),
        (new[] { 0x41, 0x100 }, "InvalidStartByte"),
    };
    foreach (var (input, expected) in vectors)
    {
        var (actual, _) = Security.SurrogateReassemblyDetect(input);
        var name = "surrogate-reassembly [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertEqual(expected ?? "<clear>", actual ?? "<clear>", name);
    }
    Console.WriteLine("clean: .NET surrogate-reassembly 18-vector spot-check passes");
}

// Direct spot-check of the rtl-injection detector's DerivedBidiClass-backed
// strong-Bidi lookup, mirroring the Rust/Python/C++ port tests. Runs first so
// its result is visible before the shared contract tests. Sub == null means a
// clear input; otherwise it is the highest-priority sub-threat.
static void TestRtlInjectionVectors()
{
    var vectors = new (int[] Input, string? Sub)[]
    {
        (new[] { 0x30, 0x31, 0x32, 0x33 }, null),
        (new[] { 0x043F }, null),
        (new[] { 0x41, 0x202E, 0x42 }, "RloInLTRField"),
        (new[] { 0x05D0, 0x42, 0x43 }, "FieldTakeover"),
        (new[] { 0x0627, 0x42, 0x43 }, "FieldTakeover"),
        (new[] { 0x41, 0x42, 0x05D0, 0x44 }, "StrongRTLInLTR"),
        (new[] { 0x41, 0x42, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x44 }, "MixedOverflow"),
    };
    foreach (var (input, expected) in vectors)
    {
        var (actual, _) = Security.RtlInjectionDetect(input);
        var name = "rtl-injection [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertEqual(expected ?? "<clear>", actual ?? "<clear>", name);
    }
    Console.WriteLine("clean: .NET rtl-injection 7-vector spot-check passes");
}

static void TestPolicyContract()
{
    using var contract = LoadFixture("policy_contract.json");
    AssertEqual(1, contract.RootElement.GetProperty("schema").GetInt32(), "policy schema");
    AssertEqual("unicode-security-policy-v0", contract.RootElement.GetProperty("contract").GetString(), "policy contract");
    foreach (var entry in contract.RootElement.GetProperty("cases").EnumerateArray())
    {
        var verdict = Security.Scan(String(entry, "profile"), String(entry, "mode"), Ints(entry.GetProperty("input")));
        AssertEqual(String(entry, "action"), verdict.Action, String(entry, "name"));
        foreach (var required in Strings(entry.GetProperty("required_findings")))
        {
            AssertTrue(HasFinding(verdict.Findings, required), $"{String(entry, "name")}: missing {required}");
        }
    }
}

static void TestVerdictContract()
{
    using var contract = LoadFixture("verdict_contract.json");
    AssertEqual(1, contract.RootElement.GetProperty("schema").GetInt32(), "verdict schema");
    AssertEqual("unicode-security-verdict-v0", contract.RootElement.GetProperty("contract").GetString(), "verdict contract");
    foreach (var entry in contract.RootElement.GetProperty("cases").EnumerateArray())
    {
        var verdict = Security.Scan(String(entry, "profile"), String(entry, "mode"), Ints(entry.GetProperty("input")));
        var expected = JsonSerializer.Serialize(entry.GetProperty("verdict"));
        AssertEqual(expected, Security.VerdictJson(verdict), String(entry, "name"));
    }
}

static void TestUtf8DecodeContract()
{
    using var contract = LoadFixture("decode_contract.json");
    AssertEqual(1, contract.RootElement.GetProperty("schema").GetInt32(), "decode schema");
    AssertEqual("unicode-security-decode-v0", contract.RootElement.GetProperty("contract").GetString(), "decode contract");
    foreach (var entry in contract.RootElement.GetProperty("cases").EnumerateArray())
    {
        var verdict = Security.ScanUtf8(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes")));
        AssertDecodeEntry(entry, verdict);
    }
}

static void TestMultiEncodingDecodeContract()
{
    using var contract = LoadFixture("decode_multiencoding_contract.json");
    AssertEqual(1, contract.RootElement.GetProperty("schema").GetInt32(), "multi-encoding schema");
    AssertEqual("unicode-security-multiencoding-decode-v0", contract.RootElement.GetProperty("contract").GetString(), "multi-encoding contract");
    foreach (var entry in contract.RootElement.GetProperty("cases").EnumerateArray())
    {
        var verdict = String(entry, "encoding") switch
        {
            "utf-8" => Security.ScanUtf8(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes"))),
            "utf-16be" => Security.ScanUtf16BE(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes"))),
            "utf-16le" => Security.ScanUtf16LE(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes"))),
            "utf-32be" => Security.ScanUtf32BE(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes"))),
            "utf-32le" => Security.ScanUtf32LE(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes"))),
            var other => throw new InvalidOperationException($"unknown encoding: {other}"),
        };
        AssertDecodeEntry(entry, verdict);
    }
}

static void TestDetectorFixtures()
{
    foreach (var fixture in new[]
    {
        "detectors/tag_block_payload.json",
        "detectors/variation_selector_payload.json",
        "detectors/zero_width_payload.json",
        "detectors/bidi_control_balance.json",
        "detectors/noncharacter_control.json",
        "detectors/homoglyph_confusable.json",
        "detectors/mixed_script_admissibility.json",
    })
    {
        using var detector = LoadFixture(fixture);
        AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), $"{fixture} schema");
        var family = String(detector.RootElement, "family");
        foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
        {
            var verdict = Security.Scan("gateway-header", "observe", Ints(entry.GetProperty("input")));
            var requiredFindings = Strings(entry.GetProperty("required_findings")).ToList();
            foreach (var required in requiredFindings)
            {
                AssertTrue(HasFinding(verdict.Findings, required), $"{fixture}:{String(entry, "name")}: missing {required}");
            }
            if (requiredFindings.Count == 0)
            {
                AssertTrue(!HasFamilyFinding(verdict.Findings, family), $"{fixture}:{String(entry, "name")}: unexpected family");
            }
        }
    }
}

// Direct spot-check of compatibility normalization (NFKD / NFKC), mirroring
// Unicode.Normalization.NFKD / NFKC and the Rust port's to_nfkd / to_nfkc.
// NFKC applies the compatibility mappings and then composes; NFKD stops after
// compatibility decomposition.
static void TestCompatNormalizationVectors()
{
    var nfkc = new (int[] Input, int[] Expected)[]
    {
        (new[] { 0xFB01 }, new[] { 0x66, 0x69 }),
        (new[] { 0x2460 }, new[] { 0x31 }),
        (new[] { 0xFF21 }, new[] { 0x41 }),
        (new[] { 0x00E9 }, new[] { 0x00E9 }),
        (new[] { 0x0065, 0x0301 }, new[] { 0x00E9 }),
        (new[] { 0x1112, 0x1161, 0x11AB }, new[] { 0xD55C }),
    };
    foreach (var (input, expected) in nfkc)
    {
        var actual = Security.ToNfkc(input);
        var name = "ToNfkc [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertSequence(expected, actual, name);
    }
    var nfkd = new (int[] Input, int[] Expected)[]
    {
        (new[] { 0xFF21 }, new[] { 0x41 }),
        (new[] { 0x00E9 }, new[] { 0x0065, 0x0301 }),
    };
    foreach (var (input, expected) in nfkd)
    {
        var actual = Security.ToNfkd(input);
        var name = "ToNfkd [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertSequence(expected, actual, name);
    }
    Console.WriteLine("clean: .NET NFKD/NFKC 8-vector spot-check passes");
}

static void AssertDecodeEntry(JsonElement entry, Security.Verdict verdict)
{
    AssertEqual(String(entry, "action"), verdict.Action, $"{String(entry, "name")} action");
    AssertSequence(Ints(entry.GetProperty("input")), verdict.Input, $"{String(entry, "name")} input");
    foreach (var required in Strings(entry.GetProperty("required_findings")))
    {
        AssertTrue(HasFinding(verdict.Findings, required), $"{String(entry, "name")}: missing {required}");
    }
    foreach (var expected in entry.GetProperty("required_positions").EnumerateArray())
    {
        var code = String(expected, "code");
        var finding = verdict.Findings.FirstOrDefault(candidate => candidate.Code == code);
        AssertTrue(finding is not null, $"{String(entry, "name")}: missing positions for {code}");
        AssertSequence(Ints(expected.GetProperty("positions")), finding!.Positions, $"{String(entry, "name")}: {code}");
    }
}

static JsonDocument LoadFixture(string name)
{
    var path = Path.Combine(AppContext.BaseDirectory, "testdata", "fixtures", "security", name);
    if (!File.Exists(path)) path = Path.Combine("testdata", "fixtures", "security", name);
    return JsonDocument.Parse(File.ReadAllText(path));
}

static string String(JsonElement element, string name) => element.GetProperty(name).GetString() ?? "";

static IEnumerable<string> Strings(JsonElement array) =>
    array.EnumerateArray().Select(item => item.GetString() ?? "");

static List<int> Ints(JsonElement array) =>
    array.EnumerateArray().Select(item => item.GetInt32()).ToList();

static byte[] Bytes(JsonElement array) =>
    array.EnumerateArray().Select(item => (byte)item.GetInt32()).ToArray();

static bool HasFinding(IReadOnlyList<Security.Finding> findings, string code) =>
    findings.Any(finding => finding.Code == code);

static bool HasFamilyFinding(IReadOnlyList<Security.Finding> findings, string family) =>
    findings.Any(finding => finding.Family == family);

static void AssertTrue(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

// Ground truth: the toLower spot-check theorems in Unicode.Casing.
static void TestCasing()
{
    AssertSequence(new[] { 0x68, 0x65, 0x6C, 0x6C, 0x6F },
        Security.ToLower(Security.CasingLocale.Default, new List<int> { 0x48, 0x65, 0x6C, 0x6C, 0x6F }), "toLower hello");
    AssertSequence(new[] { 0x0069 },
        Security.ToLower(Security.CasingLocale.Default, new List<int> { 0x0049 }), "toLower I default");
    AssertSequence(new[] { 0x0131 },
        Security.ToLower(Security.CasingLocale.Turkish, new List<int> { 0x0049 }), "toLower I turkish");
    AssertSequence(new[] { 0x0131 },
        Security.ToLower(Security.CasingLocale.Azeri, new List<int> { 0x0049 }), "toLower I azeri");
    AssertSequence(new[] { 0x0069 },
        Security.ToLower(Security.CasingLocale.Turkish, new List<int> { 0x0130 }), "toLower dotted-I turkish");
    AssertSequence(new[] { 0x0069, 0x0307 },
        Security.ToLower(Security.CasingLocale.Default, new List<int> { 0x0130 }), "toLower dotted-I default");
    Console.WriteLine("clean: .NET toLower 6-theorem spot-check passes");
}

// Ground truth: the detect spot-check theorems in Bip39CanonicalVectorsDetect.
static void TestBip39()
{
    var abandon = new List<int> { 0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E };
    var about = new List<int> { 0x61, 0x62, 0x6F, 0x75, 0x74 };
    string? Tag(List<int> input) => Security.Bip39CanonicalDetect(input).SubThreat;

    var trailing = new List<int>(abandon) { 0x20 };
    AssertEqual("TrailingWhitespace", Tag(trailing), "bip39 trailing");
    AssertSequence(new[] { 7 }, Security.Bip39CanonicalDetect(trailing).Positions, "bip39 trailing pos");
    AssertEqual("MixedCase", Tag(new List<int> { 0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E }), "bip39 mixed");
    var dbl = new List<int>(abandon) { 0x20, 0x20 };
    dbl.AddRange(about);
    AssertEqual("WhitespaceAnomaly", Tag(dbl), "bip39 double");
    var lead = new List<int> { 0x20 };
    lead.AddRange(abandon);
    AssertEqual("WhitespaceAnomaly", Tag(lead), "bip39 leading");
    AssertEqual("NonNFKD", Tag(new List<int> { 0xFB00 }), "bip39 ligature");
    AssertEqual("NonNFKD", Tag(new List<int> { 0x61, 0x00A0, 0x62 }), "bip39 nbsp");
    AssertEqual("WordlistMismatch", Tag(new List<int> { 0x71, 0x7A, 0x71, 0x7A }), "bip39 mismatch");

    var empty = Security.Bip39CanonicalDetect(new List<int>());
    AssertEqual<string?>(null, empty.SubThreat, "bip39 empty sub");
    AssertEqual("english", empty.Language, "bip39 empty lang");

    var mnemonic = new List<int>();
    for (var i = 0; i < 11; i++)
    {
        mnemonic.AddRange(abandon);
        mnemonic.Add(0x20);
    }
    mnemonic.AddRange(about);
    var verdict = Security.Bip39CanonicalDetect(mnemonic);
    AssertEqual<string?>(null, verdict.SubThreat, "bip39 12word sub");
    AssertEqual("english", verdict.Language, "bip39 12word lang");
    AssertEqual(12, verdict.WordCount, "bip39 12word count");
    Console.WriteLine("clean: .NET bip39-canonical detect spot-check passes");
}

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/LocaleCaseInversion.lean and the Rust/Go ports' tests.
static void TestLocaleCaseInversion()
{
    string? Sub(List<int> input) => Security.LocaleCaseInversionDetect(input).SubThreat;

    AssertEqual<string?>(null, Sub(new List<int>()), "locale-case empty");
    AssertEqual<string?>(null, Sub(new List<int> { 0x48, 0x65, 0x6C, 0x6C, 0x6F }), "locale-case ascii");
    AssertEqual("TurkishCaseDivergence", Sub(new List<int> { 0x0049 }), "locale-case capital-I turkish");
    AssertSequence(new[] { 0 }, Security.LocaleCaseInversionDetect(new List<int> { 0x0049 }).Positions, "locale-case capital-I pos");
    AssertEqual("TurkishCaseDivergence", Sub(new List<int> { 0x0130 }), "locale-case dotted-I turkish");
    AssertEqual("TurkishCaseDivergence", Sub(new List<int> { 0x0049, 0x0300 }), "locale-case I-grave turkish-first");
    AssertEqual("LithuanianCaseDivergence", Sub(new List<int> { 0x004A, 0x0300 }), "locale-case J-grave lithuanian");
    Console.WriteLine("clean: .NET locale-case-inversion detect spot-check passes");
}

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/NormalizationBomb.lean and the Rust port's tests.
static void TestNormalizationBomb()
{
    string? Sub(List<int> input) => Security.NormalizationBombDetect(input).SubThreat;

    AssertEqual<string?>(null, Sub(new List<int>()), "norm-bomb empty");
    AssertEqual<string?>(null, Sub(new List<int> { 0x48, 0x65, 0x6C, 0x6C, 0x6F }), "norm-bomb ascii");
    AssertEqual<string?>(null, Sub(new List<int> { 0xD55C }), "norm-bomb korean");
    AssertEqual<string?>(null, Sub(new List<int> { 0x2460 }), "norm-bomb circled-one");
    AssertEqual("SingleCpBlowup", Sub(new List<int> { 0xFDFA }), "norm-bomb fdfa blowup");
    AssertSequence(new[] { 0 }, Security.NormalizationBombDetect(new List<int> { 0xFDFA }).Positions, "norm-bomb fdfa pos");
    AssertEqual("NfkdHighExpansion", Sub(new List<int> { 0xFDFB }), "norm-bomb fdfb nfkd");
    AssertEqual("NfdHighExpansion", Sub(new List<int> { 0x1F82 }), "norm-bomb greek nfd");
    Console.WriteLine("clean: .NET normalization-bomb detect spot-check passes");
}

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/NfcIdempotenceWitness.lean and the Rust port's tests.
static void TestNfcIdempotenceWitness()
{
    string? Sub(List<int> input) => Security.NfcIdempotenceWitnessDetect(input).SubThreat;

    AssertEqual<string?>(null, Sub(new List<int>()), "nfc-witness empty");
    AssertEqual<string?>(null, Sub(new List<int> { 0x48, 0x65, 0x6C, 0x6C, 0x6F }), "nfc-witness ascii");
    AssertEqual<string?>(null, Sub(new List<int> { 0x00E9 }), "nfc-witness precomposed-e-acute");
    AssertEqual("NonNfcForm", Sub(new List<int> { 0x0065, 0x0301 }), "nfc-witness decomposed-e-acute");
    AssertSequence(new[] { 0 }, Security.NfcIdempotenceWitnessDetect(new List<int> { 0x0065, 0x0301 }).Positions, "nfc-witness decomposed-e-acute pos");
    AssertEqual("NonNfkcCompatForm", Sub(new List<int> { 0xFB01 }), "nfc-witness fi-ligature");
    Console.WriteLine("clean: .NET nfc-idempotence-witness detect spot-check passes");
}

// Ground truth: the shared context-free detector fixture
// fixtures/security/detectors/hash_input_stability.json, run through
// Security.HashInputStability.Detect (the empty-context wrapper). Each case's
// required_findings is the fully-qualified reason code
// (unicode.security.K.hash-input-stability.<tag>); an empty list means the
// input must classify Clear. Mirrors the Rust port's §8 detect spot checks.
static void TestHashInputStabilityFixture()
{
    using var detector = LoadFixture("detectors/hash_input_stability.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "hash-input-stability schema");
    AssertEqual("hash-input-stability", String(detector.RootElement, "family"), "hash-input-stability family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Security.HashInputStability.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"hash-input-stability {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"hash-input-stability {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET hash-input-stability {cases}-case shared-fixture detect passes");
}

// Ground truth: the verbatim Context-vector comment block in the Rust port's
// hash_input_stability.rs test module (the shared detector-fixture schema
// cannot express a Context, so these live only in-source). Every vector is
// transcribed here: the four context-bearing probes, their clear cases, and the
// three cross-probe priority vectors, plus the RfcRule tag round-trip and the
// hash_stable / default-context identity spot checks.
static void TestHashInputStabilityContextVectors()
{
    string? CtxTag(His.Context ctx, int[] input) =>
        Security.HashInputStability.DetectWithContext(ctx, input).Classify.Tag;
    IReadOnlyList<int> CtxPos(His.Context ctx, int[] input) =>
        Security.HashInputStability.DetectWithContext(ctx, input).Classify.Positions;

    // encodingMismatch: non-UTF-8 label, invalid surrogate, out-of-range scalar.
    var encUtf16 = new His.Context(DeclaredEncoding: "utf-16");
    AssertEqual<string?>("EncodingMismatch", CtxTag(encUtf16, new[] { 0x61, 0x62, 0x63 }), "his utf-16 label tag");
    AssertSequence(new[] { 0 }, CtxPos(encUtf16, new[] { 0x61, 0x62, 0x63 }), "his utf-16 label pos");
    var encUtf8 = new His.Context(DeclaredEncoding: "utf-8");
    AssertEqual<string?>("EncodingMismatch", CtxTag(encUtf8, new[] { 0x61, 0xD800, 0x62 }), "his invalid surrogate tag");
    AssertSequence(new[] { 1 }, CtxPos(encUtf8, new[] { 0x61, 0xD800, 0x62 }), "his invalid surrogate pos");
    AssertEqual<string?>("EncodingMismatch", CtxTag(encUtf8, new[] { 0x61, 0x110000, 0x62 }), "his out-of-range tag");
    AssertSequence(new[] { 1 }, CtxPos(encUtf8, new[] { 0x61, 0x110000, 0x62 }), "his out-of-range pos");
    foreach (var label in new[] { "UTF-8", "utf-8", "UTF8", "utf8" })
    {
        AssertEqual<string?>(null, CtxTag(new His.Context(DeclaredEncoding: label), new[] { 0x61, 0x62, 0x63 }),
            $"his utf-8 label {label} clear");
    }

    // signedMessageRule: one firing and (where present) one clear vector per RFC rule.
    var pgp4880 = new His.Context(RfcRule: His.RfcRule.Pgp4880TrailingWhitespace);
    AssertEqual<string?>("SignedMessageRule", CtxTag(pgp4880, new[] { 0x61, 0x20 }), "his pgp4880 tag");
    AssertSequence(new[] { 1 }, CtxPos(pgp4880, new[] { 0x61, 0x20 }), "his pgp4880 pos");
    var pgp9580 = new His.Context(RfcRule: His.RfcRule.Pgp9580LineEnding);
    AssertEqual<string?>("SignedMessageRule", CtxTag(pgp9580, new[] { 0x61, 0x0A, 0x62 }), "his pgp9580 bare-lf tag");
    AssertSequence(new[] { 1 }, CtxPos(pgp9580, new[] { 0x61, 0x0A, 0x62 }), "his pgp9580 bare-lf pos");
    AssertEqual<string?>(null, CtxTag(pgp9580, new[] { 0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66 }),
        "his pgp9580 crlf clear");
    var rfc8785 = new His.Context(RfcRule: His.RfcRule.Rfc8785NfcRequirement);
    AssertEqual<string?>("SignedMessageRule", CtxTag(rfc8785, new[] { 0x0065, 0x0301 }), "his rfc8785 tag");
    AssertSequence(new[] { 0 }, CtxPos(rfc8785, new[] { 0x0065, 0x0301 }), "his rfc8785 pos");
    var rfc8259 = new His.Context(RfcRule: His.RfcRule.Rfc8259ControlChar);
    AssertEqual<string?>("SignedMessageRule", CtxTag(rfc8259, new[] { 0x61, 0x01, 0x62 }), "his rfc8259 tag");
    AssertSequence(new[] { 1 }, CtxPos(rfc8259, new[] { 0x61, 0x01, 0x62 }), "his rfc8259 pos");
    var rfc7515 = new His.Context(RfcRule: His.RfcRule.Rfc7515JwsBase64Url);
    AssertEqual<string?>("SignedMessageRule", CtxTag(rfc7515, new[] { 0x41, 0x2B, 0x42 }), "his rfc7515 plus tag");
    AssertSequence(new[] { 1 }, CtxPos(rfc7515, new[] { 0x41, 0x2B, 0x42 }), "his rfc7515 plus pos");
    AssertEqual<string?>(null, CtxTag(rfc7515, new[] { 0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39 }),
        "his rfc7515 clean clear");
    var rfc6376 = new His.Context(RfcRule: His.RfcRule.Rfc6376DkimRelaxed);
    AssertEqual<string?>("SignedMessageRule", CtxTag(rfc6376, new[] { 0x61, 0x20, 0x20, 0x62 }), "his rfc6376 double-space tag");
    AssertSequence(new[] { 2 }, CtxPos(rfc6376, new[] { 0x61, 0x20, 0x20, 0x62 }), "his rfc6376 double-space pos");
    AssertEqual<string?>(null, CtxTag(rfc6376, new[] { 0x61, 0x20, 0x62 }), "his rfc6376 single-space clear");
    var rfc5751 = new His.Context(RfcRule: His.RfcRule.Rfc5751SmimeLineEnding);
    AssertEqual<string?>("SignedMessageRule", CtxTag(rfc5751, new[] { 0x61, 0x0A, 0x62 }), "his rfc5751 bare-lf tag");
    AssertSequence(new[] { 1 }, CtxPos(rfc5751, new[] { 0x61, 0x0A, 0x62 }), "his rfc5751 bare-lf pos");

    // auditLogReinterpretation.
    var audit = new His.Context(AsWritten: new[] { 0x61, 0x62, 0x63 });
    AssertEqual<string?>("AuditLogReinterpretation", CtxTag(audit, new[] { 0x61, 0x62, 0x64 }), "his audit tag");
    AssertSequence(new[] { 2 }, CtxPos(audit, new[] { 0x61, 0x62, 0x64 }), "his audit pos");
    AssertEqual<string?>(null, CtxTag(audit, new[] { 0x61, 0x62, 0x63 }), "his audit identical clear");

    // webhookSignatureDrift.
    var webhook = new His.Context(ServerBytes: new[] { 0x61, 0x62, 0x64 });
    AssertEqual<string?>("WebhookSignatureDrift", CtxTag(webhook, new[] { 0x61, 0x62, 0x63 }), "his webhook tag");
    AssertSequence(new[] { 2 }, CtxPos(webhook, new[] { 0x61, 0x62, 0x63 }), "his webhook pos");
    AssertEqual<string?>(null, CtxTag(new His.Context(ServerBytes: new[] { 0x61, 0x62, 0x63 }), new[] { 0x61, 0x62, 0x63 }),
        "his webhook match clear");

    // Cross-probe priority vectors.
    var encOverRfc = new His.Context(DeclaredEncoding: "utf-16", RfcRule: His.RfcRule.Pgp9580LineEnding);
    AssertEqual<string?>("EncodingMismatch", CtxTag(encOverRfc, new[] { 0x0065, 0x0301, 0x0A }), "his encoding-over-rfc priority");
    var webhookOverAudit = new His.Context(AsWritten: new[] { 0x61, 0x62, 0x66 }, ServerBytes: new[] { 0x61, 0x62, 0x65 });
    AssertEqual<string?>("WebhookSignatureDrift", CtxTag(webhookOverAudit, new[] { 0x61, 0x62, 0x63 }), "his webhook-over-audit priority");
    AssertEqual<string?>("SignedMessageRule", CtxTag(pgp4880, new[] { 0x61, 0x20 }), "his rfc-over-trailing priority");

    // Empty context is the identity of Detect.
    var bare = Security.HashInputStability.Detect(new[] { 0x61, 0x62, 0x63 });
    var withDefault = Security.HashInputStability.DetectWithContext(His.Context.Default, new[] { 0x61, 0x62, 0x63 });
    AssertEqual(bare.Classify.Tag, withDefault.Classify.Tag, "his default-context tag matches detect");
    AssertEqual(bare.StableSize, withDefault.StableSize, "his default-context stable-size matches detect");

    // §4 hash_stable spot checks.
    AssertSequence(System.Array.Empty<int>(), Security.HashInputStability.HashStable(System.Array.Empty<int>()), "his stable empty");
    AssertSequence(new[] { 0x61, 0x62, 0x63 }, Security.HashInputStability.HashStable(new[] { 0x61, 0x62, 0x63 }), "his stable ascii");
    AssertSequence(new[] { 0x61 }, Security.HashInputStability.HashStable(new[] { 0x61, 0x20 }), "his stable strip space");
    AssertSequence(new[] { 0x61 }, Security.HashInputStability.HashStable(new[] { 0x61, 0x0D, 0x0A }), "his stable strip crlf");
    AssertSequence(new[] { 0x00E9 }, Security.HashInputStability.HashStable(new[] { 0x0065, 0x0301 }), "his stable compose nfc");
    AssertSequence(new[] { 0x61, 0x00A0 }, Security.HashInputStability.HashStable(new[] { 0x61, 0x00A0 }), "his stable keep nbsp");

    // RfcRule tag round-trip.
    foreach (var rule in new[]
    {
        His.RfcRule.Pgp4880TrailingWhitespace,
        His.RfcRule.Pgp9580LineEnding,
        His.RfcRule.Rfc8785NfcRequirement,
        His.RfcRule.Rfc8259ControlChar,
        His.RfcRule.Rfc7515JwsBase64Url,
        His.RfcRule.Rfc6376DkimRelaxed,
        His.RfcRule.Rfc5751SmimeLineEnding,
    })
    {
        AssertEqual<His.RfcRule?>(rule, Security.HashInputStability.FromTag(Security.HashInputStability.Tag(rule)), $"his rfc-rule roundtrip {rule}");
    }
    AssertEqual<His.RfcRule?>(null, Security.HashInputStability.FromTag("nope"), "his rfc-rule unknown tag");

    Console.WriteLine("clean: .NET hash-input-stability 21-vector context spot-check passes");
}

// Ground truth: the shared context-free detector fixture
// fixtures/security/detectors/ai_watermark_detectability.json, run through
// Security.AiWatermarkDetectability.Detect (the empty-context wrapper). Each
// case's required_findings is the fully-qualified reason code
// (unicode.security.K.ai-watermark-detectability.<tag>); an empty list means
// the input must classify Clear. Mirrors the Rust port's §6/§7 detect spot
// checks.
static void TestAiWatermarkDetectabilityFixture()
{
    using var detector = LoadFixture("detectors/ai_watermark_detectability.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "ai-watermark-detectability schema");
    AssertEqual("ai-watermark-detectability", String(detector.RootElement, "family"), "ai-watermark-detectability family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Awd.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"ai-watermark-detectability {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"ai-watermark-detectability {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET ai-watermark-detectability {cases}-case shared-fixture detect passes");
}

// Ground truth: the Context-tolerance vectors and every probe/priority/cue-class
// spot-check theorem in the Rust port's ai_watermark_detectability.rs test
// module (the shared detector-fixture schema cannot express a Context, so the
// tolerance vectors live only in-source). Detect(input).Classify.Tag maps each
// theorem's classification to one assertion.
static void TestAiWatermarkDetectabilityContextVectors()
{
    string? Tag(int[] input) => Awd.Detect(input).Classify.Tag;

    // §4 detect spot checks.
    AssertEqual<string?>(null, Tag(System.Array.Empty<int>()), "awd empty clear");
    AssertEqual<string?>(null, Tag(new[] { 0x61, 0x62, 0x63 }), "awd ascii clear");
    AssertEqual<string?>(null, Tag(new[] { 0x4E2D, 0x6587 }), "awd han clear");

    var nnbsp = Awd.Detect(new[] { 0x61, 0x202F, 0x62 });
    AssertEqual<string?>("NnbspBoundary", nnbsp.Classify.Tag, "awd nnbsp tag");
    AssertSequence(new[] { 1 }, nnbsp.Classify.Positions, "awd nnbsp pos");
    AssertEqual(1, nnbsp.MarkerCount, "awd nnbsp count");

    var vsPlain = Awd.Detect(new[] { 0x61, 0xFE0F, 0x62 });
    AssertEqual<string?>("VariationSelectorCarrier", vsPlain.Classify.Tag, "awd vs-plain tag");
    AssertEqual(1, vsPlain.MarkerCount, "awd vs-plain count");
    AssertEqual<string?>(null, Tag(new[] { 0x1F600, 0xFE0F }), "awd vs-after-emoji clear");

    var zwjPlain = Awd.Detect(new[] { 0x61, 0x200D, 0x62 });
    AssertEqual<string?>("ZwjNonEmoji", zwjPlain.Classify.Tag, "awd zwj-plain tag");
    AssertEqual(1, zwjPlain.MarkerCount, "awd zwj-plain count");
    AssertEqual<string?>(null, Tag(new[] { 0x1F469, 0x200D, 0x1F52C }), "awd zwj-emoji-seq clear");

    AssertEqual<string?>("DefaultIgnorableCarrier", Tag(new[] { 0x61, 0x00AD, 0x62 }), "awd soft-hyphen tag");
    AssertEqual<string?>("DefaultIgnorableCarrier", Tag(new[] { 0x61, 0x200B, 0x62 }), "awd zwsp tag");

    var multiNnbsp = Awd.Detect(new[] { 0x61, 0x202F, 0x62, 0x202F, 0x63 });
    AssertEqual<string?>("NnbspBoundary", multiNnbsp.Classify.Tag, "awd multi-nnbsp tag");
    AssertEqual(2, multiNnbsp.MarkerCount, "awd multi-nnbsp count");
    AssertSequence(new[] { 1, 3 }, multiNnbsp.Classify.Positions, "awd multi-nnbsp pos");

    // §7 refinement-probe spot checks.
    var adv = Awd.Detect(new[] { 0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64 });
    AssertEqual<string?>("Adversarial", adv.Classify.Tag, "awd adversarial tag");
    AssertEqual(3, adv.MarkerCount, "awd adversarial count");
    AssertEqual<string?>("NnbspBoundary", Tag(new[] { 0x61, 0x202F, 0x62, 0x202F, 0x63 }), "awd nnbsp-below-adversarial");

    var gpt5 = Awd.Detect(new[] { 0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64 });
    AssertEqual<string?>("Gpt5ZwspModulo", gpt5.Classify.Tag, "awd gpt5-zwsp-modulo tag");
    AssertEqual(3, gpt5.MarkerCount, "awd gpt5-zwsp-modulo count");
    AssertEqual<string?>("DefaultIgnorableCarrier", Tag(new[] { 0x61, 0x200B, 0x62, 0x200B, 0x63 }), "awd zwsp-below-modulo");

    var smart = Awd.Detect(new[] { 0x201C, 0x61, 0x62, 0x63, 0x201D });
    AssertEqual<string?>("SmartQuoteAlternation", smart.Classify.Tag, "awd smart-quote tag");
    AssertEqual(2, smart.MarkerCount, "awd smart-quote count");
    AssertEqual<string?>(null, Tag(new[] { 0x201C, 0x61, 0x22, 0x201D }), "awd smart-quote-with-straight clear");

    var emDash = Awd.Detect(new[] { 0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66 });
    AssertEqual<string?>("EmDashPattern", emDash.Classify.Tag, "awd em-dash tag");
    AssertEqual(2, emDash.MarkerCount, "awd em-dash count");
    AssertEqual<string?>(null, Tag(new[] { 0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66 }), "awd em-dash-with-hyphen clear");

    var delve = Awd.Detect(new[] { 0x64, 0x65, 0x6C, 0x76, 0x65 });
    AssertEqual<string?>("StatisticalTokenChoice", delve.Classify.Tag, "awd statistical-delve tag");
    AssertEqual(1, delve.MarkerCount, "awd statistical-delve count");
    var moreover = Awd.Detect(new[] { 0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20 });
    AssertEqual<string?>("StatisticalTokenChoice", moreover.Classify.Tag, "awd statistical-moreover tag");
    AssertSequence(new[] { 2 }, moreover.Classify.Positions, "awd statistical-moreover pos");

    // Unknown priority (>= 2 distinct invisible categories).
    var unkNnbspDi = Awd.Detect(new[] { 0x61, 0x202F, 0x00AD, 0x62 });
    AssertEqual<string?>("Unknown", unkNnbspDi.Classify.Tag, "awd unknown-nnbsp-di tag");
    AssertEqual(2, unkNnbspDi.MarkerCount, "awd unknown-nnbsp-di count");
    var unkVsZwj = Awd.Detect(new[] { 0x61, 0xFE0F, 0x200D, 0x62 });
    AssertEqual<string?>("Unknown", unkVsZwj.Classify.Tag, "awd unknown-vs-zwj tag");
    AssertEqual(2, unkVsZwj.MarkerCount, "awd unknown-vs-zwj count");
    var unkNnbspZwj = Awd.Detect(new[] { 0x61, 0x202F, 0x200D, 0x62 });
    AssertEqual<string?>("Unknown", unkNnbspZwj.Classify.Tag, "awd unknown-nnbsp-zwj tag");
    AssertEqual(2, unkNnbspZwj.MarkerCount, "awd unknown-nnbsp-zwj count");
    AssertEqual<string?>("NnbspBoundary", Tag(new[] { 0x61, 0x202F, 0x62 }), "awd single-category-skips-unknown");

    // §8 tolerance-parameterised probes (the two Context vectors).
    var jitter = new[] { 0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65 };
    AssertEqual<string?>("DefaultIgnorableCarrier", Tag(jitter), "awd zwsp-jittered-strict clear");
    var tolerant = new Awd.Context(ZwspModuloTolerance: 1);
    AssertEqual<string?>("Gpt5ZwspModulo", Awd.DetectWithContext(tolerant, jitter).Classify.Tag, "awd zwsp-jittered-tolerant fires");

    var bare = Awd.Detect(new[] { 0x61, 0x202F, 0x62 });
    var withDefault = Awd.DetectWithContext(Awd.Context.Default, new[] { 0x61, 0x202F, 0x62 });
    AssertEqual(bare.Classify.Tag, withDefault.Classify.Tag, "awd default-context matches detect");

    // §7 cue-class coverage: every CueClass is probed by some sub-threat.
    var cueClasses = new[] { Awd.CueClass.GreenListBias, Awd.CueClass.PseudorandomSeq, Awd.CueClass.SemanticDrift };
    var probed = new Awd.SubThreat[]
    {
        new Awd.NnbspBoundary(0),
        new Awd.VariationSelectorCarrier(0),
        new Awd.ZwjNonEmoji(0),
        new Awd.DefaultIgnorableCarrier(0),
        new Awd.Gpt5ZwspModulo(0),
        new Awd.EmDashPattern(0),
        new Awd.SmartQuoteAlternation(0),
        new Awd.StatisticalTokenChoice(0),
        new Awd.Adversarial("", 0),
    };
    foreach (var cls in cueClasses)
    {
        AssertTrue(probed.Any(st => st.Cue == cls), $"awd cue class {cls} is probed");
    }
    AssertEqual<Awd.CueClass?>(null, new Awd.Unknown(0).Cue, "awd unknown has no cue class");

    Console.WriteLine("clean: .NET ai-watermark-detectability 34-vector context spot-check passes");
}

// Opaque-blob refinement: structurally valid strict UTF-8 under a size bound,
// validity routed through Security.IsValidUtf8 (the port's strict decoder),
// mirroring ports/rust/src/opaque_blob.rs.
static void TestUtf8Blob()
{
    // Accepted: ASCII, 2-byte (é), 4-byte (😀), empty under any bound.
    AssertTrue(Utf8Blob.Of(new byte[] { 0x41, 0x42 }, 10) is not null, "blob ascii accepted");
    AssertTrue(Utf8Blob.Of(new byte[] { 0xC3, 0xA9 }, 10) is not null, "blob 2-byte accepted");
    AssertTrue(Utf8Blob.Of(new byte[] { 0xF0, 0x9F, 0x98, 0x80 }, 10) is not null, "blob 4-byte accepted");
    AssertTrue(Utf8Blob.Of(System.Array.Empty<byte>(), 0) is not null, "blob empty accepted bound 0");
    AssertTrue(Utf8Blob.Of(System.Array.Empty<byte>(), 5) is not null, "blob empty accepted bound 5");

    // Rejected: overlong C0 80, surrogate ED A0 80, over-bound.
    AssertTrue(Utf8Blob.Of(new byte[] { 0xC0, 0x80 }, 10) is null, "blob overlong rejected");
    AssertTrue(Utf8Blob.Of(new byte[] { 0xED, 0xA0, 0x80 }, 10) is null, "blob surrogate rejected");
    AssertTrue(Utf8Blob.Of(new byte[] { 0x41, 0x42, 0x43 }, 2) is null, "blob over-bound rejected");

    // Predicate agrees with the smart constructor's validity gate.
    AssertTrue(Utf8Blob.IsUtf8Blob(new byte[] { 0xC3, 0xA9 }), "blob predicate valid");
    AssertTrue(!Utf8Blob.IsUtf8Blob(new byte[] { 0xC0, 0x80 }), "blob predicate overlong");

    // Bytes / MaxBytes are carried faithfully.
    var blob = Utf8Blob.Of(new byte[] { 0x41 }, 5);
    AssertTrue(blob is not null, "blob single built");
    AssertSequence(new[] { 0x41 }, blob!.Bytes.Select(b => (int)b).ToList(), "blob bytes roundtrip");
    AssertEqual(5, blob.MaxBytes, "blob max bytes");
    Console.WriteLine("clean: .NET utf8-blob refinement spot-check passes");
}

// ValidatedUtf8 refinement: strict RFC 3629 validity pinned at construction,
// validity routed through Security.IsValidUtf8, mirroring
// ports/rust/src/validated_utf8.rs.
static void TestValidatedUtf8()
{
    // Empty and every well-formed width validate.
    AssertTrue(ValidatedUtf8.Validate(System.Array.Empty<byte>()) is not null, "validated empty accepted");
    AssertTrue(ValidatedUtf8.Validate(new byte[] { 0x41, 0x42 }) is not null, "validated ascii accepted");
    AssertTrue(ValidatedUtf8.Validate(new byte[] { 0xE4, 0xB8, 0xAD }) is not null, "validated 3-byte accepted");
    AssertTrue(ValidatedUtf8.Validate(new byte[] { 0xF0, 0x9F, 0x98, 0x80 }) is not null, "validated 4-byte accepted");

    // Overlong and surrogate forms fail the strict state machine.
    AssertTrue(ValidatedUtf8.Validate(new byte[] { 0xC0, 0x80 }) is null, "validated overlong rejected");
    AssertTrue(ValidatedUtf8.Validate(new byte[] { 0xED, 0xA0, 0x80 }) is null, "validated surrogate rejected");

    // Validate + AsBytes + Unwrap roundtrip preserves the exact bytes.
    var input = new byte[] { 0xF0, 0x9F, 0x98, 0x80, 0x41 };
    var validated = ValidatedUtf8.Validate(input);
    AssertTrue(validated is not null, "validated roundtrip built");
    AssertSequence(input.Select(b => (int)b).ToList(), validated!.AsBytes.Select(b => (int)b).ToList(), "validated as-bytes roundtrip");
    AssertSequence(input.Select(b => (int)b).ToList(), validated.Unwrap().Select(b => (int)b).ToList(), "validated unwrap roundtrip");
    Console.WriteLine("clean: .NET validated-utf8 refinement spot-check passes");
}

// UAX #29 grapheme segmentation targeted vectors, mirroring
// ports/rust/tests/segmentation.rs and the rust grapheme.rs unit tests.
static void TestGraphemeVectors()
{
    AssertBoolSequence(new[] { true, true, true, true }, Grapheme.GraphemeBreaks(new[] { 0x61, 0x62, 0x63 }), "grapheme abc breaks");
    AssertBoolSequence(new[] { true, false, true }, Grapheme.GraphemeBreaks(new[] { 0x65, 0x0301 }), "grapheme e+acute breaks");
    AssertBoolSequence(new[] { true, false, true }, Grapheme.GraphemeBreaks(new[] { 0x0D, 0x0A }), "grapheme CR LF breaks");
    AssertBoolSequence(new[] { true, false, true }, Grapheme.GraphemeBreaks(new[] { 0x1F1EF, 0x1F1F5 }), "grapheme flag pair breaks");

    AssertEqual(3, Grapheme.GraphemeClusters(new[] { 0x61, 0x62, 0x63 }).Count, "grapheme abc clusters");
    AssertEqual(1, Grapheme.GraphemeClusters(new[] { 0x65, 0x0301 }).Count, "grapheme e+acute clusters");
    AssertEqual(1, Grapheme.GraphemeClusters(new[] { 0x1F1EF, 0x1F1F5 }).Count, "grapheme flag pair clusters");
    AssertEqual(2, Grapheme.GraphemeClusters(new[] { 0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8 }).Count, "grapheme four RI clusters");
    AssertEqual(1, Grapheme.GraphemeClusters(new[] { 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467 }).Count, "grapheme ZWJ family clusters");
    Console.WriteLine("clean: .NET grapheme targeted-vector spot-check passes");
}

// Full UAX #29 conformance corpus. Every "÷"/"×"-marked row of the pinned
// GraphemeBreakTest.txt must reproduce under Grapheme.GraphemeBreaks.
static void TestGraphemeBreakTestFile()
{
    var path = Path.Combine(AppContext.BaseDirectory, "testdata", "GraphemeBreakTest.txt");
    if (!File.Exists(path)) path = Path.Combine("testdata", "GraphemeBreakTest.txt");
    var rows = 0;
    foreach (var raw in File.ReadAllLines(path))
    {
        var hash = raw.IndexOf('#');
        var body = (hash >= 0 ? raw.Substring(0, hash) : raw).Trim();
        if (body.Length == 0)
        {
            continue;
        }
        var tokens = body.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        var codepoints = new List<int>();
        var expected = new List<bool>();
        foreach (var token in tokens)
        {
            if (token == "÷")
            {
                expected.Add(true);
            }
            else if (token == "×")
            {
                expected.Add(false);
            }
            else
            {
                codepoints.Add(Convert.ToInt32(token, 16));
            }
        }
        var actual = Grapheme.GraphemeBreaks(codepoints);
        AssertBoolSequence(expected, actual, $"GraphemeBreakTest row {rows + 1}: [{string.Join(" ", tokens)}]");
        rows++;
    }
    AssertEqual(766, rows, "GraphemeBreakTest row count");
    Console.WriteLine($"clean: .NET GraphemeBreakTest.txt {rows}-row conformance passes");
}

static void AssertBoolSequence(IReadOnlyList<bool> expected, IReadOnlyList<bool> actual, string message)
{
    if (!expected.SequenceEqual(actual))
    {
        throw new Exception($"{message}\nexpected: [{string.Join(",", expected)}]\nactual:   [{string.Join(",", actual)}]");
    }
}

static void AssertEqual<T>(T expected, T actual, string message)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new Exception($"{message}\nexpected: {expected}\nactual:   {actual}");
    }
}

static void AssertSequence(IReadOnlyList<int> expected, IReadOnlyList<int> actual, string message)
{
    if (!expected.SequenceEqual(actual))
    {
        throw new Exception($"{message}\nexpected: [{string.Join(",", expected)}]\nactual:   [{string.Join(",", actual)}]");
    }
}
