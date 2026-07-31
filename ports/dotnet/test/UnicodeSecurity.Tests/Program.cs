using System.Text.Json;
using UnicodeSecurity;

TestConfusableBidiCompoundVectors();
TestSurrogateReassemblyVectors();
TestRtlInjectionVectors();
TestPolicyContract();
TestVerdictContract();
TestUtf8DecodeContract();
TestMultiEncodingDecodeContract();
TestDetectorFixtures();
Console.WriteLine("clean: .NET contract tests pass");

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
        (new[] { 0x1F600 }, null),
        (new[] { 0x41, 0x100 }, null),
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
