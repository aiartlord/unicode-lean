package com.unicodesecurity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class SecurityContractTest {
  public static void main(String[] args) throws Exception {
    testCovertDisplayCompound();
    testNfkNormalization();
    testCasing();
    testBip39();
    testLocaleCaseInversion();
    testNormalizationBomb();
    testConfusableBidiCompound();
    testSurrogateReassembly();
    testRtlInjection();
    testPolicyContract();
    testVerdictContract();
    testUtf8DecodeContract();
    testMultiEncodingDecodeContract();
    testDetectorFixtures();
  }

  // Pins the covert-display-compound detector against the detect_* spot-check
  // theorems in Unicode/Security/Boundary/CovertDisplayCompound.lean. Runs
  // first so its result shows before the shared contract tests.
  private static void testCovertDisplayCompound() {
    int[][] inputs = {
      {},
      {0x48, 0x65, 0x6C, 0x6C, 0x6F},
      {0x202E},
      {0x0041, 0xFE00},
      {0x202E, 0x0041, 0xFE00},
      {0x202E, 0x0041, 0xE0001},
    };
    String[] wants = {null, null, null, null, "BidiPlusUnregisteredVs", "BidiPlusTagBlock"};
    for (int i = 0; i < inputs.length; i++) {
      List<Integer> input = new ArrayList<>();
      for (int cp : inputs[i]) input.add(cp);
      Security.CovertDisplayCompoundResult result = Security.covertDisplayCompoundDetect(input);
      assertEquals(wants[i], result.subThreat(), "covert-display-compound case " + i);
    }
    System.out.println("clean: covert-display-compound spot checks pass (" + inputs.length + " vectors)");
  }

  // Pins Security.toNfkd / Security.toNfkc against Unicode.Normalization.NFKD
  // and NFKC, matching the vectors exercised by the Rust port's to_nfkd /
  // to_nfkc: compatibility decomposition (ligature, circled digit, fullwidth),
  // canonical identity, canonical composition, and Hangul syllable composition.
  private static void testNfkNormalization() {
    int[][] nfkcInputs = {
      {0xFB01},
      {0x2460},
      {0xFF21},
      {0x00E9},
      {0x0065, 0x0301},
      {0x1112, 0x1161, 0x11AB},
    };
    int[][] nfkcWants = {
      {0x66, 0x69},
      {0x31},
      {0x41},
      {0x00E9},
      {0x00E9},
      {0xD55C},
    };
    for (int i = 0; i < nfkcInputs.length; i++) {
      assertEquals(intList(nfkcWants[i]), Security.toNfkc(intList(nfkcInputs[i])), "toNfkc case " + i);
    }
    int[][] nfkdInputs = {
      {0xFF21},
      {0x00E9},
    };
    int[][] nfkdWants = {
      {0x41},
      {0x0065, 0x0301},
    };
    for (int i = 0; i < nfkdInputs.length; i++) {
      assertEquals(intList(nfkdWants[i]), Security.toNfkd(intList(nfkdInputs[i])), "toNfkd case " + i);
    }
    System.out.println("clean: NFKD/NFKC normalization spot checks pass ("
        + (nfkcInputs.length + nfkdInputs.length) + " vectors)");
  }

  // Ground truth: the toLower spot-check theorems in Unicode.Casing.
  private static void testCasing() {
    assertEquals(
        intList(new int[] {0x68, 0x65, 0x6C, 0x6C, 0x6F}),
        Security.toLower(Security.CasingLocale.DEFAULT, intList(new int[] {0x48, 0x65, 0x6C, 0x6C, 0x6F})),
        "toLower hello");
    assertEquals(intList(new int[] {0x0069}),
        Security.toLower(Security.CasingLocale.DEFAULT, intList(new int[] {0x0049})), "toLower I default");
    assertEquals(intList(new int[] {0x0131}),
        Security.toLower(Security.CasingLocale.TURKISH, intList(new int[] {0x0049})), "toLower I turkish");
    assertEquals(intList(new int[] {0x0131}),
        Security.toLower(Security.CasingLocale.AZERI, intList(new int[] {0x0049})), "toLower I azeri");
    assertEquals(intList(new int[] {0x0069}),
        Security.toLower(Security.CasingLocale.TURKISH, intList(new int[] {0x0130})), "toLower dotted-I turkish");
    assertEquals(intList(new int[] {0x0069, 0x0307}),
        Security.toLower(Security.CasingLocale.DEFAULT, intList(new int[] {0x0130})), "toLower dotted-I default");
    System.out.println("clean: JVM toLower 6-theorem spot-check passes");
  }

  // Ground truth: the detect spot-check theorems in Bip39CanonicalVectorsDetect.
  private static void testBip39() {
    List<Integer> abandon = intList(new int[] {0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E});
    List<Integer> about = intList(new int[] {0x61, 0x62, 0x6F, 0x75, 0x74});

    List<Integer> trailing = new ArrayList<>(abandon);
    trailing.add(0x20);
    assertEquals("TrailingWhitespace", Security.bip39CanonicalDetect(trailing).subThreat(), "bip39 trailing");
    assertEquals(List.of(7), Security.bip39CanonicalDetect(trailing).positions(), "bip39 trailing pos");
    assertEquals("MixedCase",
        Security.bip39CanonicalDetect(intList(new int[] {0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E})).subThreat(),
        "bip39 mixed");
    List<Integer> dbl = new ArrayList<>(abandon);
    dbl.add(0x20);
    dbl.add(0x20);
    dbl.addAll(about);
    assertEquals("WhitespaceAnomaly", Security.bip39CanonicalDetect(dbl).subThreat(), "bip39 double");
    List<Integer> lead = new ArrayList<>();
    lead.add(0x20);
    lead.addAll(abandon);
    assertEquals("WhitespaceAnomaly", Security.bip39CanonicalDetect(lead).subThreat(), "bip39 leading");
    assertEquals("NonNFKD", Security.bip39CanonicalDetect(intList(new int[] {0xFB00})).subThreat(), "bip39 ligature");
    assertEquals("NonNFKD",
        Security.bip39CanonicalDetect(intList(new int[] {0x61, 0x00A0, 0x62})).subThreat(), "bip39 nbsp");
    assertEquals("WordlistMismatch",
        Security.bip39CanonicalDetect(intList(new int[] {0x71, 0x7A, 0x71, 0x7A})).subThreat(), "bip39 mismatch");

    Security.Bip39CanonicalResult empty = Security.bip39CanonicalDetect(List.of());
    assertEquals(null, empty.subThreat(), "bip39 empty sub");
    assertEquals("english", empty.language(), "bip39 empty lang");

    List<Integer> mnemonic = new ArrayList<>();
    for (int i = 0; i < 11; i++) {
      mnemonic.addAll(abandon);
      mnemonic.add(0x20);
    }
    mnemonic.addAll(about);
    Security.Bip39CanonicalResult verdict = Security.bip39CanonicalDetect(mnemonic);
    assertEquals(null, verdict.subThreat(), "bip39 12word sub");
    assertEquals("english", verdict.language(), "bip39 12word lang");
    assertEquals(12, verdict.wordCount(), "bip39 12word count");
    System.out.println("clean: JVM bip39-canonical detect spot-check passes");
  }

  // Ground truth: the detect_* spot-check theorems in
  // Unicode/Security/Form/LocaleCaseInversion.lean.
  private static void testLocaleCaseInversion() {
    assertEquals(null,
        Security.localeCaseInversionDetect(intList(new int[] {})).subThreat(), "lci empty");
    assertEquals(null,
        Security.localeCaseInversionDetect(intList(new int[] {0x48, 0x65, 0x6C, 0x6C, 0x6F})).subThreat(),
        "lci ascii");
    assertEquals("TurkishCaseDivergence",
        Security.localeCaseInversionDetect(intList(new int[] {0x0049})).subThreat(), "lci capital I");
    assertEquals(List.of(0),
        Security.localeCaseInversionDetect(intList(new int[] {0x0049})).positions(), "lci capital I pos");
    assertEquals("TurkishCaseDivergence",
        Security.localeCaseInversionDetect(intList(new int[] {0x0130})).subThreat(), "lci dotted I");
    assertEquals("TurkishCaseDivergence",
        Security.localeCaseInversionDetect(intList(new int[] {0x0049, 0x0300})).subThreat(),
        "lci I grave picks Turkish");
    assertEquals("LithuanianCaseDivergence",
        Security.localeCaseInversionDetect(intList(new int[] {0x004A, 0x0300})).subThreat(),
        "lci J grave picks Lithuanian");
    System.out.println("clean: JVM locale-case-inversion detect spot-check passes");
  }

  // Pins the normalization-bomb detector against the detect_* spot-check
  // theorems in Unicode/Security/Form/NormalizationBomb.lean, plus the two
  // ratio-branch shapes the module docstring guarantees (FDFB → NFKD ratio;
  // a Greek extended form → NFD ratio).
  private static void testNormalizationBomb() {
    assertEquals(null,
        Security.normalizationBombDetect(intList(new int[] {})).subThreat(), "bomb empty");
    assertEquals(null,
        Security.normalizationBombDetect(intList(new int[] {0x48, 0x65, 0x6C, 0x6C, 0x6F})).subThreat(),
        "bomb ascii");
    assertEquals(null,
        Security.normalizationBombDetect(intList(new int[] {0xD55C})).subThreat(), "bomb korean");
    assertEquals(null,
        Security.normalizationBombDetect(intList(new int[] {0x2460})).subThreat(), "bomb circled one");
    assertEquals("SingleCpBlowup",
        Security.normalizationBombDetect(intList(new int[] {0xFDFA})).subThreat(), "bomb arabic ligature");
    assertEquals(List.of(0),
        Security.normalizationBombDetect(intList(new int[] {0xFDFA})).positions(), "bomb arabic ligature pos");
    assertEquals("NfkdHighExpansion",
        Security.normalizationBombDetect(intList(new int[] {0xFDFB})).subThreat(), "bomb fdfb nfkd ratio");
    assertEquals("NfdHighExpansion",
        Security.normalizationBombDetect(intList(new int[] {0x1F82})).subThreat(), "bomb greek nfd ratio");
    System.out.println("clean: JVM normalization-bomb detect spot-check passes");
  }

  private static List<Integer> intList(int[] codepoints) {
    List<Integer> out = new ArrayList<>();
    for (int cp : codepoints) out.add(cp);
    return out;
  }

  // Pins the confusable-bidi-compound detector against the detect_* spot-check
  // theorems in Unicode/Security/Boundary/ConfusableBidiCompound.lean. Runs
  // first so its result shows before the shared contract tests.
  private static void testConfusableBidiCompound() {
    int[][] inputs = {
      {},
      {0x48, 0x65, 0x6C, 0x6C, 0x6F},
      {0x202E, 0x0041, 0x0042, 0x0043},
      {0x0430},
      {0x202E, 0x0430},
      {0x2066, 0x03BF},
    };
    String[] wants = {null, null, null, null, "ConfusableInOverride", "ConfusableInIsolate"};
    for (int i = 0; i < inputs.length; i++) {
      List<Integer> input = new ArrayList<>();
      for (int cp : inputs[i]) input.add(cp);
      Security.ConfusableBidiCompoundResult result = Security.confusableBidiCompoundDetect(input);
      assertEquals(wants[i], result.subThreat(), "confusable-bidi-compound case " + i);
    }
    System.out.println("clean: confusable-bidi-compound spot checks pass (" + inputs.length + " vectors)");
  }

  // Pins the surrogate-reassembly detector against the detect_* spot-check
  // theorems in Unicode/Security/Covert/SurrogateReassembly.lean. Runs first
  // so its result shows before the shared contract tests.
  private static void testSurrogateReassembly() {
    int[][] inputs = {
      {},
      {0x48, 0x65, 0x6C, 0x6C, 0x6F},
      {0xC3, 0xA9},
      {0xE4, 0xB8, 0xAD},
      {0xF0, 0x9F, 0x98, 0x80},
      {0xC0, 0x80},
      {0xC0, 0xAF},
      {0xFE},
      {0x80},
      {0xFF},
      {0xE0, 0x80, 0xAF},
      {0xF0, 0x80, 0x80, 0xAF},
      {0xED, 0xA0, 0x80},
      {0xED, 0xAF, 0xBF},
      {0xC3},
      {0xF0, 0x9F, 0x98},
      {0x1F600},
      {0x41, 0x100},
    };
    // The unit detect clamps values > 0xFF to 0xFF (mirroring the Lean toBytes
    // helper), so the final two non-byte-stream cases surface InvalidStartByte.
    // The scan orchestrator gates these out (mirroring runAll).
    String[] wants = {
      null, null, null, null, null,
      "InvalidStartByte", "InvalidStartByte", "InvalidStartByte", "InvalidStartByte", "InvalidStartByte",
      "Overlong", "Overlong",
      "Cesu8", "Cesu8",
      "Truncated", "Truncated",
      "InvalidStartByte", "InvalidStartByte",
    };
    for (int i = 0; i < inputs.length; i++) {
      List<Integer> input = new ArrayList<>();
      for (int cp : inputs[i]) input.add(cp);
      Security.SurrogateReassemblyResult result = Security.surrogateReassemblyDetect(input);
      assertEquals(wants[i], result.subThreat(), "surrogate-reassembly case " + i);
    }
    System.out.println("clean: surrogate-reassembly spot checks pass (" + inputs.length + " vectors)");
  }

  // Pins the RTL-injection detector against the detect_* spot-check
  // theorems in Unicode/Security/Display/RtlInjection.lean.
  private static void testRtlInjection() {
    int[][] inputs = {
      {0x30, 0x31, 0x32, 0x33},
      {0x043F},
      {0x41, 0x202E, 0x42},
      {0x05D0, 0x42, 0x43},
      {0x0627, 0x42, 0x43},
      {0x41, 0x42, 0x05D0, 0x44},
      {0x41, 0x42, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x44},
    };
    String[] wants = {null, null, "RloInLTRField", "FieldTakeover", "FieldTakeover", "StrongRTLInLTR", "MixedOverflow"};
    for (int i = 0; i < inputs.length; i++) {
      java.util.List<Integer> input = new java.util.ArrayList<>();
      for (int cp : inputs[i]) input.add(cp);
      Security.RtlInjectionResult result = Security.rtlInjectionDetect(input);
      assertEquals(wants[i], result.subThreat(), "rtl-injection case " + i);
    }
  }

  private static void testPolicyContract() throws IOException {
    Map<String, Object> contract = fixture("policy_contract.json");
    assertEquals(1, intValue(contract.get("schema")), "policy schema");
    assertEquals("unicode-security-policy-v0", contract.get("contract"), "policy contract");
    for (Map<String, Object> entry : objects(contract.get("cases"))) {
      Security.Verdict verdict = Security.scan(string(entry, "profile"), string(entry, "mode"), ints(entry.get("input")));
      assertEquals(string(entry, "action"), verdict.action(), string(entry, "name"));
      for (String required : strings(entry.get("required_findings"))) {
        assertTrue(hasFinding(verdict.findings(), required), string(entry, "name") + ": missing " + required);
      }
    }
  }

  private static void testVerdictContract() throws IOException {
    Map<String, Object> contract = fixture("verdict_contract.json");
    assertEquals(1, intValue(contract.get("schema")), "verdict schema");
    assertEquals("unicode-security-verdict-v0", contract.get("contract"), "verdict contract");
    for (Map<String, Object> entry : objects(contract.get("cases"))) {
      Security.Verdict verdict = Security.scan(string(entry, "profile"), string(entry, "mode"), ints(entry.get("input")));
      Map<String, Object> expected = object(entry.get("verdict"));
      assertEquals(canonicalJson(expected), Security.verdictJson(verdict), string(entry, "name"));
    }
  }

  private static void testUtf8DecodeContract() throws IOException {
    Map<String, Object> contract = fixture("decode_contract.json");
    assertEquals(1, intValue(contract.get("schema")), "decode schema");
    assertEquals("unicode-security-decode-v0", contract.get("contract"), "decode contract");
    for (Map<String, Object> entry : objects(contract.get("cases"))) {
      Security.Verdict verdict = Security.scanUtf8(string(entry, "profile"), string(entry, "mode"), bytes(entry.get("input_bytes")));
      assertDecodeEntry(entry, verdict);
    }
  }

  private static void testMultiEncodingDecodeContract() throws IOException {
    Map<String, Object> contract = fixture("decode_multiencoding_contract.json");
    assertEquals(1, intValue(contract.get("schema")), "multi-encoding schema");
    assertEquals("unicode-security-multiencoding-decode-v0", contract.get("contract"), "multi-encoding contract");
    for (Map<String, Object> entry : objects(contract.get("cases"))) {
      Security.Verdict verdict = switch (string(entry, "encoding")) {
        case "utf-8" -> Security.scanUtf8(string(entry, "profile"), string(entry, "mode"), bytes(entry.get("input_bytes")));
        case "utf-16be" -> Security.scanUtf16BE(string(entry, "profile"), string(entry, "mode"), bytes(entry.get("input_bytes")));
        case "utf-16le" -> Security.scanUtf16LE(string(entry, "profile"), string(entry, "mode"), bytes(entry.get("input_bytes")));
        case "utf-32be" -> Security.scanUtf32BE(string(entry, "profile"), string(entry, "mode"), bytes(entry.get("input_bytes")));
        case "utf-32le" -> Security.scanUtf32LE(string(entry, "profile"), string(entry, "mode"), bytes(entry.get("input_bytes")));
        default -> throw new IllegalArgumentException("unknown encoding: " + entry.get("encoding"));
      };
      assertDecodeEntry(entry, verdict);
    }
  }

  private static void testDetectorFixtures() throws IOException {
    for (String fixture : List.of(
        "detectors/tag_block_payload.json",
        "detectors/variation_selector_payload.json",
        "detectors/zero_width_payload.json",
        "detectors/bidi_control_balance.json",
        "detectors/noncharacter_control.json",
        "detectors/homoglyph_confusable.json",
        "detectors/mixed_script_admissibility.json")) {
      Map<String, Object> detector = fixture(fixture);
      assertEquals(1, intValue(detector.get("schema")), fixture + " schema");
      String family = string(detector, "family");
      for (Map<String, Object> entry : objects(detector.get("cases"))) {
        Security.Verdict verdict = Security.scan("gateway-header", "observe", ints(entry.get("input")));
        List<String> required = strings(entry.get("required_findings"));
        for (String code : required) {
          assertTrue(hasFinding(verdict.findings(), code), fixture + ":" + string(entry, "name") + ": missing " + code);
        }
        if (required.isEmpty()) {
          assertTrue(!hasFamilyFinding(verdict.findings(), family), fixture + ":" + string(entry, "name") + ": unexpected family");
        }
      }
    }
  }

  private static void assertDecodeEntry(Map<String, Object> entry, Security.Verdict verdict) {
    assertEquals(string(entry, "action"), verdict.action(), string(entry, "name") + " action");
    assertEquals(ints(entry.get("input")), verdict.input(), string(entry, "name") + " input");
    for (String required : strings(entry.get("required_findings"))) {
      assertTrue(hasFinding(verdict.findings(), required), string(entry, "name") + ": missing " + required);
    }
    for (Map<String, Object> expected : objects(entry.get("required_positions"))) {
      Security.Finding finding = finding(verdict.findings(), string(expected, "code"));
      assertTrue(finding != null, string(entry, "name") + ": missing positions");
      assertEquals(ints(expected.get("positions")), finding.positions(), string(entry, "name") + ": positions");
    }
  }

  private static boolean hasFinding(List<Security.Finding> findings, String code) {
    return finding(findings, code) != null;
  }

  private static Security.Finding finding(List<Security.Finding> findings, String code) {
    for (Security.Finding finding : findings) {
      if (finding.code().equals(code)) return finding;
    }
    return null;
  }

  private static boolean hasFamilyFinding(List<Security.Finding> findings, String family) {
    for (Security.Finding finding : findings) {
      if (finding.family().equals(family)) return true;
    }
    return false;
  }

  private static Map<String, Object> fixture(String name) throws IOException {
    String raw = Files.readString(Path.of("testdata", "fixtures", "security", name));
    return object(new Json(raw).parse());
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> object(Object value) {
    return (Map<String, Object>) value;
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> objects(Object value) {
    return (List<Map<String, Object>>) value;
  }

  @SuppressWarnings("unchecked")
  private static List<String> strings(Object value) {
    return (List<String>) value;
  }

  private static List<Integer> ints(Object value) {
    List<Integer> out = new ArrayList<>();
    for (Object item : values(value)) out.add(intValue(item));
    return out;
  }

  private static byte[] bytes(Object value) {
    List<Object> values = values(value);
    byte[] out = new byte[values.size()];
    for (int i = 0; i < values.size(); i++) out[i] = (byte) intValue(values.get(i));
    return out;
  }

  @SuppressWarnings("unchecked")
  private static List<Object> values(Object value) {
    return (List<Object>) value;
  }

  private static String string(Map<String, Object> object, String key) {
    return (String) object.get(key);
  }

  private static int intValue(Object value) {
    return ((Number) value).intValue();
  }

  private static void assertTrue(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }

  private static void assertEquals(Object expected, Object actual, String message) {
    if (!Objects.equals(expected, actual)) {
      throw new AssertionError(message + "\nexpected: " + expected + "\nactual:   " + actual);
    }
  }

  private static String canonicalJson(Object value) {
    if (value == null) return "null";
    if (value instanceof String s) return quote(s);
    if (value instanceof Number n) return n.toString();
    if (value instanceof List<?> list) {
      StringBuilder out = new StringBuilder("[");
      for (int i = 0; i < list.size(); i++) {
        if (i > 0) out.append(',');
        out.append(canonicalJson(list.get(i)));
      }
      return out.append(']').toString();
    }
    Map<String, Object> object = object(value);
    StringBuilder out = new StringBuilder("{");
    List<String> keys = new ArrayList<>(object.keySet());
    for (int i = 0; i < keys.size(); i++) {
      if (i > 0) out.append(',');
      String key = keys.get(i);
      out.append(quote(key)).append(':').append(canonicalJson(object.get(key)));
    }
    return out.append('}').toString();
  }

  private static String quote(String value) {
    StringBuilder out = new StringBuilder("\"");
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\b' -> out.append("\\b");
        case '\f' -> out.append("\\f");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (ch < 0x20) out.append(String.format("\\u%04x", (int) ch));
          else out.append(ch);
        }
      }
    }
    return out.append('"').toString();
  }

  private static final class Json {
    private final String input;
    private int offset;

    Json(String input) {
      this.input = input;
    }

    Object parse() {
      Object value = parseValue();
      skipWhitespace();
      if (offset != input.length()) throw error("trailing input");
      return value;
    }

    private Object parseValue() {
      skipWhitespace();
      if (offset >= input.length()) throw error("unexpected EOF");
      char ch = input.charAt(offset);
      if (ch == '"') return parseString();
      if (ch == '{') return parseObject();
      if (ch == '[') return parseArray();
      if (ch == 'n') return parseLiteral("null", null);
      if (ch == 't') return parseLiteral("true", Boolean.TRUE);
      if (ch == 'f') return parseLiteral("false", Boolean.FALSE);
      if (ch == '-' || Character.isDigit(ch)) return parseNumber();
      throw error("unexpected character");
    }

    private Map<String, Object> parseObject() {
      Map<String, Object> out = new java.util.LinkedHashMap<>();
      offset++;
      skipWhitespace();
      if (peek('}')) {
        offset++;
        return out;
      }
      while (true) {
        String key = parseString();
        skipWhitespace();
        expect(':');
        out.put(key, parseValue());
        skipWhitespace();
        if (peek('}')) {
          offset++;
          return out;
        }
        expect(',');
      }
    }

    private List<Object> parseArray() {
      List<Object> out = new ArrayList<>();
      offset++;
      skipWhitespace();
      if (peek(']')) {
        offset++;
        return out;
      }
      while (true) {
        out.add(parseValue());
        skipWhitespace();
        if (peek(']')) {
          offset++;
          return out;
        }
        expect(',');
      }
    }

    private String parseString() {
      expect('"');
      StringBuilder out = new StringBuilder();
      while (offset < input.length()) {
        char ch = input.charAt(offset++);
        if (ch == '"') return out.toString();
        if (ch != '\\') {
          out.append(ch);
          continue;
        }
        if (offset >= input.length()) throw error("bad escape");
        char escaped = input.charAt(offset++);
        switch (escaped) {
          case '"' -> out.append('"');
          case '\\' -> out.append('\\');
          case '/' -> out.append('/');
          case 'b' -> out.append('\b');
          case 'f' -> out.append('\f');
          case 'n' -> out.append('\n');
          case 'r' -> out.append('\r');
          case 't' -> out.append('\t');
          case 'u' -> {
            if (offset + 4 > input.length()) throw error("short unicode escape");
            int cp = Integer.parseInt(input.substring(offset, offset + 4), 16);
            offset += 4;
            out.append((char) cp);
          }
          default -> throw error("bad escape");
        }
      }
      throw error("unterminated string");
    }

    private Number parseNumber() {
      int start = offset;
      if (peek('-')) offset++;
      while (offset < input.length() && Character.isDigit(input.charAt(offset))) offset++;
      return Integer.parseInt(input.substring(start, offset));
    }

    private Object parseLiteral(String literal, Object value) {
      if (!input.startsWith(literal, offset)) throw error("bad literal");
      offset += literal.length();
      return value;
    }

    private void expect(char expected) {
      skipWhitespace();
      if (!peek(expected)) throw error("expected " + expected);
      offset++;
    }

    private boolean peek(char expected) {
      return offset < input.length() && input.charAt(offset) == expected;
    }

    private void skipWhitespace() {
      while (offset < input.length() && Character.isWhitespace(input.charAt(offset))) offset++;
    }

    private IllegalArgumentException error(String message) {
      return new IllegalArgumentException(message + " at byte " + offset);
    }
  }
}
