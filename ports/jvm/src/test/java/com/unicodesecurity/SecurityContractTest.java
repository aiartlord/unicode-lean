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
    testPolicyContract();
    testVerdictContract();
    testUtf8DecodeContract();
    testMultiEncodingDecodeContract();
    testDetectorFixtures();
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
