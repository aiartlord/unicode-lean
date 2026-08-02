package com.unicodesecurity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class SecurityContractTest {
  public static void main(String[] args) throws Exception {
    testCovertDisplayCompound();
    testNfkNormalization();
    testCasing();
    testBip39();
    testLocaleCaseInversion();
    testNormalizationBomb();
    testNfcIdempotenceWitness();
    testHashInputStability();
    testAiWatermarkDetectability();
    testEmojiZwjIntegrity();
    testSkinToneVariationForgery();
    testRendererDivergence();
    testFilenameDisguise();
    testIdentifierFormDrift();
    testStreamSafeViolation();
    testCaseExpansionMismatch();
    testConfusableBidiCompound();
    testSurrogateReassembly();
    testRtlInjection();
    testPolicyContract();
    testVerdictContract();
    testUtf8DecodeContract();
    testMultiEncodingDecodeContract();
    testByteLayerRefinements();
    testDetectorFixtures();
  }

  // Pins the byte-layer refinement types Utf8Blob and ValidatedUtf8 against the
  // Rust port's opaque_blob / validated_utf8 modules. Both refine over the shared
  // strict RFC 3629 decoder (Security.isValidUtf8), so overlong and surrogate
  // forms reject at the byte boundary and never reach the codepoint scanner.
  private static void testByteLayerRefinements() {
    byte[] ascii = {(byte) 0x41};
    byte[] twoByte = {(byte) 0xC3, (byte) 0xA9};                             // U+00E9
    byte[] fourByte = {(byte) 0xF0, (byte) 0x9F, (byte) 0x98, (byte) 0x80};  // U+1F600
    byte[] overlong = {(byte) 0xC0, (byte) 0x80};                           // overlong NUL
    byte[] surrogate = {(byte) 0xED, (byte) 0xA0, (byte) 0x80};              // U+D800
    byte[] empty = {};

    // Predicate mirrors is_utf8_blob: strict validity, nothing more.
    assertTrue(Utf8Blob.isUtf8Blob(ascii), "isUtf8Blob accepts ascii");
    assertTrue(Utf8Blob.isUtf8Blob(twoByte), "isUtf8Blob accepts 2-byte");
    assertTrue(Utf8Blob.isUtf8Blob(fourByte), "isUtf8Blob accepts 4-byte");
    assertTrue(Utf8Blob.isUtf8Blob(empty), "isUtf8Blob accepts empty");
    assertTrue(!Utf8Blob.isUtf8Blob(overlong), "isUtf8Blob rejects overlong C0 80");
    assertTrue(!Utf8Blob.isUtf8Blob(surrogate), "isUtf8Blob rejects surrogate ED A0 80");

    // Utf8Blob.of: bound + validity gate, bytes preserved on the happy path.
    Optional<Utf8Blob> asciiBlob = Utf8Blob.of(ascii, 8);
    assertTrue(asciiBlob.isPresent(), "Utf8Blob.of accepts ascii under bound");
    assertTrue(Arrays.equals(ascii, asciiBlob.get().bytes()), "Utf8Blob preserves ascii bytes");
    assertEquals(8, asciiBlob.get().maxBytes(), "Utf8Blob preserves declared bound");
    assertTrue(Utf8Blob.of(twoByte, 2).isPresent(), "Utf8Blob.of accepts 2-byte at exact bound");
    assertTrue(Utf8Blob.of(fourByte, 4).isPresent(), "Utf8Blob.of accepts 4-byte at exact bound");

    // Over-bound rejects even though the bytes are structurally valid.
    assertTrue(Utf8Blob.of(fourByte, 3).isEmpty(), "Utf8Blob.of rejects over-bound valid bytes");
    // Invalid bytes reject regardless of a generous bound.
    assertTrue(Utf8Blob.of(overlong, 64).isEmpty(), "Utf8Blob.of rejects overlong");
    assertTrue(Utf8Blob.of(surrogate, 64).isEmpty(), "Utf8Blob.of rejects surrogate");
    // Empty accepted under any bound, including zero.
    assertTrue(Utf8Blob.of(empty, 0).isPresent(), "Utf8Blob.of accepts empty at bound 0");
    assertTrue(Utf8Blob.of(empty, 100).isPresent(), "Utf8Blob.of accepts empty at bound 100");

    // Defensive copy: mutating the caller's array cannot corrupt the blob.
    byte[] mutable = {(byte) 0x41};
    Utf8Blob captured = Utf8Blob.of(mutable, 4).orElseThrow();
    mutable[0] = (byte) 0x42;
    assertEquals(0x41, captured.bytes()[0] & 0xFF, "Utf8Blob copies its bytes defensively");

    // ValidatedUtf8.validate: strict-decoder gate, unwrap/asBytes roundtrip.
    Optional<ValidatedUtf8> validated = ValidatedUtf8.validate(fourByte);
    assertTrue(validated.isPresent(), "ValidatedUtf8.validate accepts 4-byte");
    assertTrue(Arrays.equals(fourByte, validated.get().asBytes()), "ValidatedUtf8.asBytes roundtrip");
    assertTrue(Arrays.equals(fourByte, validated.get().unwrap()), "ValidatedUtf8.unwrap roundtrip");
    assertTrue(ValidatedUtf8.validate(ascii).isPresent(), "ValidatedUtf8.validate accepts ascii");
    assertTrue(ValidatedUtf8.validate(twoByte).isPresent(), "ValidatedUtf8.validate accepts 2-byte");
    assertTrue(ValidatedUtf8.validate(empty).isPresent(), "ValidatedUtf8.validate accepts empty");
    assertTrue(ValidatedUtf8.validate(overlong).isEmpty(), "ValidatedUtf8.validate rejects overlong");
    assertTrue(ValidatedUtf8.validate(surrogate).isEmpty(), "ValidatedUtf8.validate rejects surrogate");

    System.out.println("clean: byte-layer refinement spot checks pass (Utf8Blob + ValidatedUtf8)");
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

  // Pins the NFC-idempotence-witness detector against the detect_* spot-check
  // theorems in Unicode/Security/Form/NfcIdempotenceWitness.lean, matching the
  // vectors exercised by the Rust port's tests: empty and ASCII are clear, the
  // precomposed e-acute is clear, the decomposed sequence fires NonNfcForm at
  // position 0, and the fi ligature fires NonNfkcCompatForm.
  private static void testNfcIdempotenceWitness() {
    assertEquals(null,
        Security.nfcIdempotenceWitnessDetect(intList(new int[] {})).subThreat(), "nfc-witness empty");
    assertEquals(null,
        Security.nfcIdempotenceWitnessDetect(intList(new int[] {0x48, 0x65, 0x6C, 0x6C, 0x6F})).subThreat(),
        "nfc-witness ascii");
    assertEquals(null,
        Security.nfcIdempotenceWitnessDetect(intList(new int[] {0x00E9})).subThreat(),
        "nfc-witness precomposed e-acute");
    assertEquals("NonNfcForm",
        Security.nfcIdempotenceWitnessDetect(intList(new int[] {0x0065, 0x0301})).subThreat(),
        "nfc-witness decomposed e-acute");
    assertEquals(List.of(0),
        Security.nfcIdempotenceWitnessDetect(intList(new int[] {0x0065, 0x0301})).positions(),
        "nfc-witness decomposed e-acute pos");
    assertEquals("NonNfkcCompatForm",
        Security.nfcIdempotenceWitnessDetect(intList(new int[] {0xFB01})).subThreat(),
        "nfc-witness fi ligature");
    System.out.println("clean: JVM nfc-idempotence-witness detect spot-check passes");
  }

  private static List<Integer> intList(int[] codepoints) {
    List<Integer> out = new ArrayList<>();
    for (int cp : codepoints) out.add(cp);
    return out;
  }

  // Pins the hash-input-stability detector against the verified Rust reference
  // ports/rust/src/security/crypto/hash_input_stability.rs. Two independent
  // sources of truth are exercised: (a) the shared context-free fixture
  // detectors/hash_input_stability.json, run through HashInputStability.detect
  // and checked against the fixture reason codes; (b) every Context-bearing
  // vector transcribed verbatim from the Rust test module's comment block, which
  // the shared detector-fixture schema cannot express. The detector reuses the
  // port's own NFC (Security.toNfc) via HashInputStability.hashStable.
  private static void testHashInputStability() throws IOException {
    // (a) Shared context-free fixture through detect.
    Map<String, Object> detector = fixture("detectors/hash_input_stability.json");
    assertEquals(1, intValue(detector.get("schema")), "hash-input-stability schema");
    assertEquals("hash-input-stability", string(detector, "family"), "hash-input-stability family");
    int fixtureCases = 0;
    for (Map<String, Object> entry : objects(detector.get("cases"))) {
      HashInputStability.Verdict verdict = HashInputStability.detect(ints(entry.get("input")));
      String code = HashInputStability.reasonCode(verdict.classify());
      List<String> required = strings(entry.get("required_findings"));
      if (required.isEmpty()) {
        assertEquals(null, code, "hash-input-stability " + string(entry, "name") + " should be clear");
      } else {
        assertEquals(1, required.size(), "hash-input-stability " + string(entry, "name") + " single finding");
        assertEquals(required.get(0), code, "hash-input-stability " + string(entry, "name"));
      }
      fixtureCases++;
    }

    // (b) Context-bearing vectors transcribed from the Rust test comment block.
    int contextVectors = 0;

    // declared_encoding = Some("utf-16"), [abc] → EncodingMismatch, [0]
    assertHisCtx(HashInputStability.Context.empty().withDeclaredEncoding("utf-16"),
        new int[] {0x61, 0x62, 0x63}, "EncodingMismatch", List.of(0), "ctx utf-16 label");
    contextVectors++;
    // declared_encoding = Some("utf-8"), [a,D800,b] → EncodingMismatch, [1] (invalid surrogate)
    assertHisCtx(HashInputStability.Context.empty().withDeclaredEncoding("utf-8"),
        new int[] {0x61, 0xD800, 0x62}, "EncodingMismatch", List.of(1), "ctx invalid surrogate");
    contextVectors++;
    // declared_encoding = Some("utf-8"), [a,110000,b] → EncodingMismatch, [1] (out of range)
    assertHisCtx(HashInputStability.Context.empty().withDeclaredEncoding("utf-8"),
        new int[] {0x61, 0x110000, 0x62}, "EncodingMismatch", List.of(1), "ctx out of range");
    contextVectors++;
    // declared_encoding = Some("UTF-8"|"utf-8"|"UTF8"|"utf8"), [abc] → clear
    for (String label : new String[] {"UTF-8", "utf-8", "UTF8", "utf8"}) {
      assertHisCtx(HashInputStability.Context.empty().withDeclaredEncoding(label),
          new int[] {0x61, 0x62, 0x63}, null, List.of(), "ctx utf-8 label " + label);
    }
    contextVectors++;
    // rfc_rule = Pgp4880TrailingWhitespace, [a,SP] → SignedMessageRule, [1]
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.PGP4880_TRAILING_WHITESPACE),
        new int[] {0x61, 0x20}, "SignedMessageRule", List.of(1), "ctx pgp4880");
    contextVectors++;
    // rfc_rule = Pgp9580LineEnding, [a,LF,b] → SignedMessageRule, [1] (bare LF)
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.PGP9580_LINE_ENDING),
        new int[] {0x61, 0x0A, 0x62}, "SignedMessageRule", List.of(1), "ctx pgp9580 bare lf");
    contextVectors++;
    // rfc_rule = Pgp9580LineEnding, [abc CRLF def] → clear
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.PGP9580_LINE_ENDING),
        new int[] {0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66}, null, List.of(), "ctx pgp9580 crlf clear");
    contextVectors++;
    // rfc_rule = Rfc8785NfcRequirement, [0065,0301] → SignedMessageRule, [0]
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.RFC8785_NFC_REQUIREMENT),
        new int[] {0x0065, 0x0301}, "SignedMessageRule", List.of(0), "ctx rfc8785 decomposed");
    contextVectors++;
    // rfc_rule = Rfc8259ControlChar, [a,01,b] → SignedMessageRule, [1]
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.RFC8259_CONTROL_CHAR),
        new int[] {0x61, 0x01, 0x62}, "SignedMessageRule", List.of(1), "ctx rfc8259 control");
    contextVectors++;
    // rfc_rule = Rfc7515JwsBase64Url, [A,+,B] → SignedMessageRule, [1] ('+')
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.RFC7515_JWS_BASE64URL),
        new int[] {0x41, 0x2B, 0x42}, "SignedMessageRule", List.of(1), "ctx rfc7515 plus");
    contextVectors++;
    // rfc_rule = Rfc7515JwsBase64Url, [A,a,0,-,_,z,Z,9] → clear
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.RFC7515_JWS_BASE64URL),
        new int[] {0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39}, null, List.of(), "ctx rfc7515 clean");
    contextVectors++;
    // rfc_rule = Rfc6376DkimRelaxed, [a,SP,SP,b] → SignedMessageRule, [2]
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.RFC6376_DKIM_RELAXED),
        new int[] {0x61, 0x20, 0x20, 0x62}, "SignedMessageRule", List.of(2), "ctx rfc6376 double space");
    contextVectors++;
    // rfc_rule = Rfc6376DkimRelaxed, [a,SP,b] → clear (single space)
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.RFC6376_DKIM_RELAXED),
        new int[] {0x61, 0x20, 0x62}, null, List.of(), "ctx rfc6376 single space clear");
    contextVectors++;
    // rfc_rule = Rfc5751SmimeLineEnding, [a,LF,b] → SignedMessageRule, [1] (bare LF)
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.RFC5751_SMIME_LINE_ENDING),
        new int[] {0x61, 0x0A, 0x62}, "SignedMessageRule", List.of(1), "ctx rfc5751 bare lf");
    contextVectors++;
    // as_written = Some([abc]), input [abd] → AuditLogReinterpretation, [2]
    assertHisCtx(HashInputStability.Context.empty().withAsWritten(intList(new int[] {0x61, 0x62, 0x63})),
        new int[] {0x61, 0x62, 0x64}, "AuditLogReinterpretation", List.of(2), "ctx audit divergence");
    contextVectors++;
    // as_written = Some([abc]), input [abc] → clear
    assertHisCtx(HashInputStability.Context.empty().withAsWritten(intList(new int[] {0x61, 0x62, 0x63})),
        new int[] {0x61, 0x62, 0x63}, null, List.of(), "ctx audit identical clear");
    contextVectors++;
    // server_bytes = Some([abd]), input [abc] → WebhookSignatureDrift, [2]
    assertHisCtx(HashInputStability.Context.empty().withServerBytes(intList(new int[] {0x61, 0x62, 0x64})),
        new int[] {0x61, 0x62, 0x63}, "WebhookSignatureDrift", List.of(2), "ctx webhook drift");
    contextVectors++;
    // server_bytes = Some([abc]), input [abc] → clear
    assertHisCtx(HashInputStability.Context.empty().withServerBytes(intList(new int[] {0x61, 0x62, 0x63})),
        new int[] {0x61, 0x62, 0x63}, null, List.of(), "ctx webhook match clear");
    contextVectors++;
    // declared_encoding = Some("utf-16") + rfc_rule = Pgp9580LineEnding,
    //   [0065,0301,LF] → EncodingMismatch (priority over rfc)
    assertHisCtx(HashInputStability.Context.empty()
            .withDeclaredEncoding("utf-16")
            .withRfcRule(HashInputStability.RfcRule.PGP9580_LINE_ENDING),
        new int[] {0x0065, 0x0301, 0x0A}, "EncodingMismatch", List.of(0), "ctx priority encoding over rfc");
    contextVectors++;
    // server_bytes = Some([abe]) + as_written = Some([abf]), input [abc]
    //   → WebhookSignatureDrift (priority over audit)
    assertHisCtx(HashInputStability.Context.empty()
            .withServerBytes(intList(new int[] {0x61, 0x62, 0x65}))
            .withAsWritten(intList(new int[] {0x61, 0x62, 0x66})),
        new int[] {0x61, 0x62, 0x63}, "WebhookSignatureDrift", List.of(2), "ctx priority webhook over audit");
    contextVectors++;
    // rfc_rule = Pgp4880TrailingWhitespace, [a,SP] → SignedMessageRule (priority over trailing)
    assertHisCtx(HashInputStability.Context.empty().withRfcRule(HashInputStability.RfcRule.PGP4880_TRAILING_WHITESPACE),
        new int[] {0x61, 0x20}, "SignedMessageRule", List.of(1), "ctx priority rfc over trailing");
    contextVectors++;

    // detect_with_context(empty) matches detect.
    HashInputStability.Verdict bare = HashInputStability.detect(intList(new int[] {0x61, 0x62, 0x63}));
    HashInputStability.Verdict ctxDefault =
        HashInputStability.detectWithContext(HashInputStability.Context.empty(), intList(new int[] {0x61, 0x62, 0x63}));
    assertEquals(bare.classify().tag(), ctxDefault.classify().tag(), "empty context matches detect tag");
    assertEquals(bare.stableSize(), ctxDefault.stableSize(), "empty context matches detect stableSize");

    // RfcRule fixture-tag round-trip.
    for (HashInputStability.RfcRule rule : HashInputStability.RfcRule.values()) {
      assertEquals(Optional.of(rule), HashInputStability.RfcRule.fromTag(rule.tag()), "rfc rule roundtrip " + rule);
    }
    assertEquals(Optional.empty(), HashInputStability.RfcRule.fromTag("nope"), "rfc rule unrecognised");

    System.out.println("clean: JVM hash-input-stability passes (" + fixtureCases
        + " fixture cases + " + contextVectors + " context vectors)");
  }

  // Pins the ai-watermark-detectability detector against the verified Rust
  // reference ports/rust/src/security/crypto/ai_watermark_detectability.rs. Two
  // independent sources of truth are exercised: (a) the shared context-free
  // fixture detectors/ai_watermark_detectability.json, run through
  // AiWatermarkDetectability.detect and checked against the fixture reason codes;
  // (b) the two Context-tolerance vectors (detect_zwsp_jittered_*) transcribed
  // from the Rust test module, which the shared detector-fixture schema cannot
  // express. The emoji-adjacency probe parses the port's own SHA-pinned
  // data/emoji-data.txt (never a host emoji library); the residual
  // Default_Ignorable probe reuses Security.isDefaultIgnorableCodepoint.
  private static void testAiWatermarkDetectability() throws IOException {
    // (a) Shared context-free fixture through detect.
    Map<String, Object> detector = fixture("detectors/ai_watermark_detectability.json");
    assertEquals(1, intValue(detector.get("schema")), "ai-watermark-detectability schema");
    assertEquals("ai-watermark-detectability", string(detector, "family"),
        "ai-watermark-detectability family");
    int fixtureCases = 0;
    for (Map<String, Object> entry : objects(detector.get("cases"))) {
      AiWatermarkDetectability.Verdict verdict = AiWatermarkDetectability.detect(ints(entry.get("input")));
      String code = AiWatermarkDetectability.reasonCode(verdict.classify());
      List<String> required = strings(entry.get("required_findings"));
      if (required.isEmpty()) {
        assertEquals(null, code,
            "ai-watermark-detectability " + string(entry, "name") + " should be clear");
      } else {
        assertEquals(1, required.size(),
            "ai-watermark-detectability " + string(entry, "name") + " single finding");
        assertEquals(required.get(0), code, "ai-watermark-detectability " + string(entry, "name"));
      }
      fixtureCases++;
    }

    // (b) The two Context-tolerance vectors (detect_zwsp_jittered_*). ZWSPs at
    // positions 1, 3, 6 (gaps 2, 3). Bare/strict (tolerance 0) does not fire
    // gpt5ZwspModulo and falls through to defaultIgnorableCarrier; tolerance 1
    // accepts the +/-1 jitter and fires gpt5ZwspModulo.
    int[] jittered = {0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65};
    AiWatermarkDetectability.Verdict strict = AiWatermarkDetectability.detect(intList(jittered));
    assertEquals("DefaultIgnorableCarrier", strict.classify().tag(),
        "aw zwsp jittered strict falls through");
    AiWatermarkDetectability.Verdict tolerant = AiWatermarkDetectability.detectWithContext(
        AiWatermarkDetectability.Context.empty().withZwspModuloTolerance(1), intList(jittered));
    assertEquals("Gpt5ZwspModulo", tolerant.classify().tag(),
        "aw zwsp jittered tolerant fires modulo");
    int contextVectors = 2;

    // detect_with_context(empty) matches detect.
    AiWatermarkDetectability.Verdict bare =
        AiWatermarkDetectability.detect(intList(new int[] {0x61, 0x202F, 0x62}));
    AiWatermarkDetectability.Verdict ctxDefault = AiWatermarkDetectability.detectWithContext(
        AiWatermarkDetectability.Context.empty(), intList(new int[] {0x61, 0x202F, 0x62}));
    assertEquals(bare.classify().tag(), ctxDefault.classify().tag(),
        "aw empty context matches detect");

    System.out.println("clean: JVM ai-watermark-detectability passes (" + fixtureCases
        + " fixture cases + " + contextVectors + " context vectors)");
  }

  // Pins the emoji-zwj-integrity detector (identity-layer I3) against the
  // verified Rust reference ports/rust/src/security/identity/emoji_zwj_integrity.rs.
  // Two independent sources of truth are exercised: (a) the shared context-free
  // fixture detectors/emoji_zwj_integrity.json, run through
  // EmojiZwjIntegrity.detect and checked against the fixture reason codes; (b)
  // the detect spot-checks and priority-ladder structure checks transcribed from
  // the Rust test module. The registered-RGI set and ZWJ alphabet are parsed
  // from the port's own SHA-pinned data/emoji-zwj-sequences.txt (never a host
  // emoji/ICU library, never String normalization); the skin-tone-modifier range
  // U+1F3FB..U+1F3FF is the port's own EmojiZwjIntegrity.isEmojiModifier.
  private static void testEmojiZwjIntegrity() throws IOException {
    // (a) Shared context-free fixture through detect.
    Map<String, Object> detector = fixture("detectors/emoji_zwj_integrity.json");
    assertEquals(1, intValue(detector.get("schema")), "emoji-zwj-integrity schema");
    assertEquals("emoji-zwj-integrity", string(detector, "family"), "emoji-zwj-integrity family");
    int fixtureCases = 0;
    for (Map<String, Object> entry : objects(detector.get("cases"))) {
      EmojiZwjIntegrity.Verdict verdict = EmojiZwjIntegrity.detect(ints(entry.get("input")));
      String code = EmojiZwjIntegrity.reasonCode(verdict.classify());
      List<String> required = strings(entry.get("required_findings"));
      if (required.isEmpty()) {
        assertEquals(null, code, "emoji-zwj-integrity " + string(entry, "name") + " should be clear");
      } else {
        assertEquals(1, required.size(),
            "emoji-zwj-integrity " + string(entry, "name") + " single finding");
        assertEquals(required.get(0), code, "emoji-zwj-integrity " + string(entry, "name"));
      }
      fixtureCases++;
    }

    // (b) Data-layer sanity, detect spot-checks, and priority-ladder structure
    // checks transcribed one-for-one from the Rust test module.
    int specVectors = 0;

    // is_emoji_modifier_checks
    assertTrue(EmojiZwjIntegrity.isEmojiModifier(0x1F3FB), "ezwj modifier 1F3FB");
    assertTrue(EmojiZwjIntegrity.isEmojiModifier(0x1F3FF), "ezwj modifier 1F3FF");
    assertTrue(!EmojiZwjIntegrity.isEmojiModifier(0x1F3FA), "ezwj non-modifier 1F3FA");
    assertTrue(!EmojiZwjIntegrity.isEmojiModifier(0x1F600), "ezwj non-modifier 1F600");
    specVectors++;

    // zwj_alphabet_admits_heart_rejects_grinning
    assertTrue(EmojiZwjIntegrity.isEmojiTarget(0x2764), "ezwj alphabet admits heart");
    assertTrue(EmojiZwjIntegrity.isEmojiTarget(0x1F468), "ezwj alphabet admits man");
    assertTrue(!EmojiZwjIntegrity.isEmojiTarget(0x1F600), "ezwj alphabet rejects grinning");
    assertTrue(!EmojiZwjIntegrity.isEmojiTarget(EmojiZwjIntegrity.ZWJ), "ezwj alphabet excludes joiner");
    specVectors++;

    // registered_membership_is_exact
    assertTrue(EmojiZwjIntegrity.isRegisteredZwjSequence(intList(new int[] {0x1F468, 0x200D, 0x1F4BB})),
        "ezwj man-technologist registered");
    assertTrue(!EmojiZwjIntegrity.isRegisteredZwjSequence(intList(new int[] {0x1F468, 0x200D, 0x1F469})),
        "ezwj man-woman unregistered");
    specVectors++;

    // detect_empty_clear
    EmojiZwjIntegrity.Verdict empty = EmojiZwjIntegrity.detect(intList(new int[] {}));
    assertTrue(empty.classify().isClear(), "ezwj empty clear");
    assertEquals(null, empty.classify().tag(), "ezwj empty tag");
    assertEquals(List.of(), empty.zwjPositions(), "ezwj empty zwjPositions");
    assertEquals(0, empty.chainLength(), "ezwj empty chainLength");
    assertEquals(0, empty.skinToneCount(), "ezwj empty skinToneCount");
    specVectors++;

    // detect_ascii_clear
    assertTrue(EmojiZwjIntegrity.detect(intList(new int[] {0x48, 0x65, 0x6C, 0x6C, 0x6F})).classify().isClear(),
        "ezwj ascii clear");
    specVectors++;

    // detect_plain_emoji_clear
    assertTrue(EmojiZwjIntegrity.detect(intList(new int[] {0x1F600})).classify().isClear(),
        "ezwj plain emoji clear");
    specVectors++;

    // detect_one_skintone_clear
    EmojiZwjIntegrity.Verdict oneSkin = EmojiZwjIntegrity.detect(intList(new int[] {0x1F44B, 0x1F3FB}));
    assertTrue(oneSkin.classify().isClear(), "ezwj one skintone clear");
    assertEquals(1, oneSkin.skinToneCount(), "ezwj one skintone count");
    specVectors++;

    // detect_family_rgi_clear
    EmojiZwjIntegrity.Verdict family = EmojiZwjIntegrity.detect(
        intList(new int[] {0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466}));
    assertTrue(family.classify().isClear(), "ezwj family rgi clear");
    assertTrue(family.isRegisteredRgi(), "ezwj family rgi registered");
    specVectors++;

    // detect_double_zwj
    EmojiZwjIntegrity.Verdict dzwj = EmojiZwjIntegrity.detect(intList(new int[] {0x1F600, 0x200D, 0x200D, 0x1F600}));
    assertEquals("DoubleZWJ", dzwj.classify().tag(), "ezwj double zwj tag");
    assertEquals(List.of(1), dzwj.classify().positions(), "ezwj double zwj positions");
    specVectors++;

    // detect_non_emoji_injection
    assertEquals("NonEmojiInjection",
        EmojiZwjIntegrity.detect(intList(new int[] {0x1F600, 0x200D, 0x0061})).classify().tag(),
        "ezwj non-emoji injection tag");
    specVectors++;

    // detect_skin_tone_overflow
    EmojiZwjIntegrity.Verdict overflow = EmojiZwjIntegrity.detect(
        intList(new int[] {0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF}));
    assertEquals("SkinToneOverflow", overflow.classify().tag(), "ezwj skin tone overflow tag");
    assertEquals(5, overflow.skinToneCount(), "ezwj skin tone overflow count");
    specVectors++;

    // detect_man_laptop_registered_clear
    assertTrue(EmojiZwjIntegrity.detect(intList(new int[] {0x1F468, 0x200D, 0x1F4BB})).classify().isClear(),
        "ezwj man laptop registered clear");
    specVectors++;

    // detect_unregistered
    assertEquals("UnregisteredSequence",
        EmojiZwjIntegrity.detect(intList(new int[] {0x1F468, 0x200D, 0x1F469})).classify().tag(),
        "ezwj unregistered tag");
    specVectors++;

    // detect_grinning_laptop_non_emoji_injection
    assertEquals("NonEmojiInjection",
        EmojiZwjIntegrity.detect(intList(new int[] {0x1F600, 0x200D, 0x1F4BB})).classify().tag(),
        "ezwj grinning laptop non-emoji injection tag");
    specVectors++;

    // over_length_fires_past_cap — 9 men joined by 8 ZWJs = 17 codepoints (> cap).
    List<Integer> longChain = new ArrayList<>();
    for (int i = 0; i < 9; i++) {
      if (i > 0) longChain.add(0x200D);
      longChain.add(0x1F468);
    }
    assertEquals(17, longChain.size(), "ezwj over-length chain size");
    EmojiZwjIntegrity.Verdict overLen = EmojiZwjIntegrity.detect(longChain);
    assertEquals("OverLength", overLen.classify().tag(), "ezwj over-length tag");
    EmojiZwjIntegrity.Hazard overLenHz = (EmojiZwjIntegrity.Hazard) overLen.classify();
    EmojiZwjIntegrity.OverLength overLenSub = (EmojiZwjIntegrity.OverLength) overLenHz.sub();
    assertEquals(17, overLenSub.length(), "ezwj over-length length");
    assertEquals(EmojiZwjIntegrity.MAX_RGI_LENGTH, overLenSub.maxLength(), "ezwj over-length cap");
    assertEquals(List.of(), overLenHz.positions(), "ezwj over-length positions empty");
    assertEquals(List.of(), overLenHz.decoded(), "ezwj over-length decoded empty");
    specVectors++;

    // trailing_zwj_is_injection — a ZWJ at the trailing edge.
    EmojiZwjIntegrity.Verdict trailing = EmojiZwjIntegrity.detect(intList(new int[] {0x1F468, 0x200D}));
    assertEquals("NonEmojiInjection", trailing.classify().tag(), "ezwj trailing zwj tag");
    assertEquals(List.of(1), trailing.classify().positions(), "ezwj trailing zwj positions");
    specVectors++;

    // double_zwj_beats_unregistered — priority order (man ZWJ ZWJ boy).
    assertEquals("DoubleZWJ",
        EmojiZwjIntegrity.detect(intList(new int[] {0x1F468, 0x200D, 0x200D, 0x1F466})).classify().tag(),
        "ezwj double beats unregistered");
    specVectors++;

    System.out.println("clean: JVM emoji-zwj-integrity passes (" + fixtureCases
        + " fixture cases + " + specVectors + " spec vectors)");
  }

  // Pins the identity-layer SkinToneVariationForgery detector against the verified
  // Rust reference ports/rust/src/security/identity/skin_tone_variation_forgery.rs.
  // Two sources of truth are exercised: (a) the shared context-free fixture
  // detectors/skin_tone_variation_forgery.json, run through
  // SkinToneVariationForgery.detect and checked against the fixture reason codes;
  // (b) the detect spot-checks and priority-ladder structure checks transcribed
  // one-for-one from the Rust test module. The skin-tone-modifier predicate reuses
  // the port's own EmojiZwjIntegrity.isEmojiModifier (U+1F3FB..U+1F3FF); the
  // Emoji_Modifier_Base and Emoji_Presentation property predicates parse the port's
  // own SHA-pinned data/emoji-data.txt (the same file AiWatermarkDetectability
  // reads its Emoji rows from), never a host emoji library.
  private static void testSkinToneVariationForgery() throws IOException {
    // (a) Shared context-free fixture through detect.
    Map<String, Object> detector = fixture("detectors/skin_tone_variation_forgery.json");
    assertEquals(1, intValue(detector.get("schema")), "skin-tone-variation-forgery schema");
    assertEquals("skin-tone-variation-forgery", string(detector, "family"),
        "skin-tone-variation-forgery family");
    int fixtureCases = 0;
    for (Map<String, Object> entry : objects(detector.get("cases"))) {
      SkinToneVariationForgery.Verdict verdict =
          SkinToneVariationForgery.detect(ints(entry.get("input")));
      String code = SkinToneVariationForgery.reasonCode(verdict.classify());
      List<String> required = strings(entry.get("required_findings"));
      if (required.isEmpty()) {
        assertEquals(null, code,
            "skin-tone-variation-forgery " + string(entry, "name") + " should be clear");
      } else {
        assertEquals(1, required.size(),
            "skin-tone-variation-forgery " + string(entry, "name") + " single finding");
        assertEquals(required.get(0), code,
            "skin-tone-variation-forgery " + string(entry, "name"));
      }
      fixtureCases++;
    }

    // (b) Predicate sanity, detect spot-checks, and priority-ladder structure
    // checks transcribed one-for-one from the Rust test module.
    int specVectors = 0;

    // Predicate reuse: skin-tone modifier is the port's own EmojiZwjIntegrity set.
    assertTrue(SkinToneVariationForgery.isSkinTone(0x1F3FB), "stvf skin-tone 1F3FB");
    assertTrue(SkinToneVariationForgery.isSkinTone(0x1F3FF), "stvf skin-tone 1F3FF");
    assertTrue(!SkinToneVariationForgery.isSkinTone(0x1F3FA), "stvf non-skin-tone 1F3FA");
    // Emoji_Modifier_Base / Emoji_Presentation from bundled emoji-data.txt.
    assertTrue(SkinToneVariationForgery.isSkinToneBase(0x1F44B), "stvf wave is modifier base");
    assertTrue(!SkinToneVariationForgery.isSkinToneBase(0x0041), "stvf ascii not modifier base");
    assertTrue(!SkinToneVariationForgery.isSkinToneBase(0x1F600), "stvf grinning not modifier base");
    assertTrue(SkinToneVariationForgery.isEmojiPresentation(0x1F600), "stvf grinning emoji-presentation");
    assertTrue(!SkinToneVariationForgery.isEmojiPresentation(0x0041), "stvf ascii not emoji-presentation");
    assertTrue(SkinToneVariationForgery.isVs15(0xFE0E), "stvf vs15");
    assertTrue(SkinToneVariationForgery.isVs16(0xFE0F), "stvf vs16");
    specVectors++;

    // detect_empty_clear
    assertTrue(SkinToneVariationForgery.detect(intList(new int[] {})).classify().isClear(),
        "stvf empty clear");
    specVectors++;

    // detect_ascii_clear — "He"
    assertTrue(SkinToneVariationForgery.detect(intList(new int[] {0x48, 0x65})).classify().isClear(),
        "stvf ascii clear");
    specVectors++;

    // detect_plain_emoji_clear — grinning face
    assertTrue(SkinToneVariationForgery.detect(intList(new int[] {0x1F600})).classify().isClear(),
        "stvf plain emoji clear");
    specVectors++;

    // detect_wave_skin_tone_clear — waving hand (a modifier base) + one skin tone.
    SkinToneVariationForgery.Verdict wave =
        SkinToneVariationForgery.detect(intList(new int[] {0x1F44B, 0x1F3FB}));
    assertTrue(wave.classify().isClear(), "stvf wave one skin tone clear");
    assertEquals(1, wave.skinToneCount(), "stvf wave skin-tone count");
    specVectors++;

    // detect_stacked_skin_tones — waving hand + two skin tones.
    SkinToneVariationForgery.Verdict stacked =
        SkinToneVariationForgery.detect(intList(new int[] {0x1F44B, 0x1F3FB, 0x1F3FC}));
    assertEquals("StackedSkinTones", stacked.classify().tag(), "stvf stacked tag");
    assertEquals(List.of(1, 2), stacked.classify().positions(), "stvf stacked positions");
    SkinToneVariationForgery.Hazard stackedHz =
        (SkinToneVariationForgery.Hazard) stacked.classify();
    SkinToneVariationForgery.StackedSkinTones stackedSub =
        (SkinToneVariationForgery.StackedSkinTones) stackedHz.sub();
    assertEquals(0, stackedSub.basePos(), "stvf stacked basePos");
    assertEquals(List.of(0x1F3FB, 0x1F3FC), stackedSub.modifiers(), "stvf stacked modifiers");
    assertEquals(List.of(), stackedHz.decoded(), "stvf stacked decoded empty");
    specVectors++;

    // detect_invalid_target_ascii — skin tone on ASCII 'A'.
    SkinToneVariationForgery.Verdict invalidAscii =
        SkinToneVariationForgery.detect(intList(new int[] {0x0041, 0x1F3FB}));
    assertEquals("InvalidSkinToneTarget", invalidAscii.classify().tag(), "stvf invalid ascii tag");
    assertEquals(List.of(1), invalidAscii.classify().positions(), "stvf invalid ascii positions");
    SkinToneVariationForgery.InvalidSkinToneTarget invalidSub =
        (SkinToneVariationForgery.InvalidSkinToneTarget)
            ((SkinToneVariationForgery.Hazard) invalidAscii.classify()).sub();
    assertEquals(0, invalidSub.basePos(), "stvf invalid ascii basePos");
    assertEquals(0x0041, invalidSub.baseCp(), "stvf invalid ascii baseCp");
    assertEquals(0x1F3FB, invalidSub.modifierCp(), "stvf invalid ascii modifierCp");
    specVectors++;

    // detect_invalid_target_smiley — skin tone on grinning face (not a modifier base).
    assertEquals("InvalidSkinToneTarget",
        SkinToneVariationForgery.detect(intList(new int[] {0x1F600, 0x1F3FB})).classify().tag(),
        "stvf invalid smiley tag");
    specVectors++;

    // detect_forced_text_style — VS15 on grinning face (Emoji_Presentation).
    SkinToneVariationForgery.Verdict forced =
        SkinToneVariationForgery.detect(intList(new int[] {0x1F600, 0xFE0E}));
    assertEquals("ForcedTextStyle", forced.classify().tag(), "stvf forced text style tag");
    assertEquals(List.of(1), forced.classify().positions(), "stvf forced text style positions");
    assertEquals(1, forced.variationSelector15Count(), "stvf forced vs15 count");
    SkinToneVariationForgery.ForcedTextStyle forcedSub =
        (SkinToneVariationForgery.ForcedTextStyle)
            ((SkinToneVariationForgery.Hazard) forced.classify()).sub();
    assertEquals(0, forcedSub.basePos(), "stvf forced basePos");
    assertEquals(0x1F600, forcedSub.baseCp(), "stvf forced baseCp");
    specVectors++;

    // Priority: stacked skin tones beats the invalid-target that the second skin
    // tone would otherwise raise on a valid modifier base.
    assertEquals("StackedSkinTones",
        SkinToneVariationForgery.detect(intList(new int[] {0x1F44B, 0x1F3FB, 0x1F3FC})).classify().tag(),
        "stvf stacked beats invalid");
    specVectors++;

    // The composed reason codes for each sub-threat.
    assertEquals("unicode.security.I.skin-tone-variation-forgery.StackedSkinTones",
        SkinToneVariationForgery.reasonCode(
            new SkinToneVariationForgery.Hazard(
                new SkinToneVariationForgery.StackedSkinTones(0, List.of(0x1F3FB, 0x1F3FC)),
                List.of(1, 2), List.of())),
        "stvf reason code stacked");
    assertEquals("unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle",
        SkinToneVariationForgery.reasonCode(
            new SkinToneVariationForgery.Hazard(
                new SkinToneVariationForgery.ForcedTextStyle(0, 0x1F600),
                List.of(1), List.of())),
        "stvf reason code forced");
    assertEquals(null, SkinToneVariationForgery.reasonCode(new SkinToneVariationForgery.Clear()),
        "stvf reason code clear");
    specVectors++;

    System.out.println("clean: JVM skin-tone-variation-forgery passes (" + fixtureCases
        + " fixture cases + " + specVectors + " spec vectors)");
  }

  // Pins the display-layer RendererDivergence detector against the verified Rust
  // reference ports/rust/src/security/display/renderer_divergence.rs. Two
  // independent sources of truth are exercised: (a) the shared context-free
  // fixture detectors/renderer_divergence.json, run through
  // RendererDivergence.detect and checked against the fixture reason codes; (b)
  // the detect spot-checks and priority-ladder structure checks transcribed from
  // the Rust test module. Every predicate the detector consumes is the port's
  // own SHA-pinned table, never a host rendering/shaping/ICU library: the
  // variation-selector set (Security.isVariationSelector), the grapheme
  // GCB=Extend class (Security.isGraphemeExtend, Grapheme_Extend ∪ emoji-modifier
  // from DerivedCoreProperties.txt), the registered RGI ZWJ registry
  // (EmojiZwjIntegrity.isRegisteredZwjSequence over emoji-zwj-sequences.txt), and
  // the strong-bidi classes over DerivedBidiClass.txt (via RtlInjection's own
  // Security.isStrongLtr / Security.isStrongRtl).
  private static void testRendererDivergence() throws IOException {
    // (a) Shared context-free fixture through detect.
    Map<String, Object> detector = fixture("detectors/renderer_divergence.json");
    assertEquals(1, intValue(detector.get("schema")), "renderer-divergence schema");
    assertEquals("renderer-divergence", string(detector, "family"), "renderer-divergence family");
    int fixtureCases = 0;
    for (Map<String, Object> entry : objects(detector.get("cases"))) {
      RendererDivergence.Verdict verdict = RendererDivergence.detect(ints(entry.get("input")));
      String code = RendererDivergence.reasonCode(verdict.classify());
      List<String> required = strings(entry.get("required_findings"));
      if (required.isEmpty()) {
        assertEquals(null, code, "renderer-divergence " + string(entry, "name") + " should be clear");
      } else {
        assertEquals(1, required.size(),
            "renderer-divergence " + string(entry, "name") + " single finding");
        assertEquals(required.get(0), code, "renderer-divergence " + string(entry, "name"));
      }
      fixtureCases++;
    }

    // (b) detect spot-checks and priority-ladder structure checks transcribed
    // one-for-one from the Rust test module.
    int specVectors = 0;

    // detect_empty_clear
    assertTrue(RendererDivergence.detect(intList(new int[] {})).classify().isClear(),
        "rd empty clear");
    specVectors++;

    // detect_ascii_clear
    assertTrue(
        RendererDivergence.detect(intList(new int[] {0x48, 0x65, 0x6C, 0x6C, 0x6F})).classify().isClear(),
        "rd ascii clear");
    specVectors++;

    // detect_han_clear
    assertTrue(RendererDivergence.detect(intList(new int[] {0x4E2D, 0x6587})).classify().isClear(),
        "rd han clear");
    specVectors++;

    // detect_vs_variance — a single VS (FE0F) after an emoji.
    assertEquals("VariationSelectorVariance",
        RendererDivergence.detect(intList(new int[] {0x1F600, 0xFE0F})).classify().tag(),
        "rd vs variance tag");
    specVectors++;

    // detect_rgi_family_clear — a registered RGI family ZWJ sequence.
    RendererDivergence.Verdict rgi = RendererDivergence.detect(
        intList(new int[] {0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466}));
    assertTrue(rgi.classify().isClear(), "rd rgi family clear");
    assertTrue(rgi.hasZwj(), "rd rgi family hasZwj");
    specVectors++;

    // detect_unregistered_zwj_variance — man + ZWJ + woman, not in RGI.
    assertEquals("UnregisteredZwjVariance",
        RendererDivergence.detect(intList(new int[] {0x1F468, 0x200D, 0x1F469})).classify().tag(),
        "rd unregistered zwj variance tag");
    specVectors++;

    // detect_zalgo_variance — a 4-deep combining stack.
    RendererDivergence.Verdict zalgo =
        RendererDivergence.detect(intList(new int[] {0x0061, 0x0301, 0x0302, 0x0303, 0x0304}));
    assertEquals("CombiningStackOverflow", zalgo.classify().tag(), "rd zalgo tag");
    assertEquals(List.of(0), zalgo.classify().positions(), "rd zalgo positions");
    assertEquals(4, zalgo.combiningCount(), "rd zalgo combining count");
    specVectors++;

    // detect_fullwidth_variance — fullwidth 'A'.
    assertEquals("FullwidthVariance",
        RendererDivergence.detect(intList(new int[] {0xFF21})).classify().tag(),
        "rd fullwidth variance tag");
    specVectors++;

    // detect_mixed_direction — Latin + Hebrew in one input.
    RendererDivergence.Verdict mixed =
        RendererDivergence.detect(intList(new int[] {0x41, 0x42, 0x05D0, 0x05D1}));
    assertEquals("MixedDirectionVariance", mixed.classify().tag(), "rd mixed direction tag");
    assertTrue(mixed.strongLtrCount() > 0 && mixed.strongRtlCount() > 0,
        "rd mixed direction strong counts");
    specVectors++;

    // combining_stack_beats_vs — a combining stack outranks a later VS.
    assertEquals("CombiningStackOverflow",
        RendererDivergence.detect(intList(new int[] {0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F}))
            .classify().tag(),
        "rd combining stack beats vs");
    specVectors++;

    // three_marks_below_threshold — exactly three marks is below the threshold.
    assertTrue(
        !"CombiningStackOverflow".equals(
            RendererDivergence.detect(intList(new int[] {0x0061, 0x0301, 0x0302, 0x0303}))
                .classify().tag()),
        "rd three marks below threshold");
    specVectors++;

    System.out.println("clean: JVM renderer-divergence passes (" + fixtureCases
        + " fixture cases + " + specVectors + " spec vectors)");
  }

  // Pins the display-layer FilenameDisguise detector against the verified Rust
  // reference implementation. Two independent sources of truth are exercised:
  // (a) the shared context-free fixture detectors/filename_disguise.json, run
  // through FilenameDisguise.detect and checked against the fixture reason codes;
  // (b) the detect spot-checks and priority-ladder structure check transcribed
  // from the Rust test module. Every predicate the detector consumes is the
  // port's own SHA-pinned table or an inline range, never a host filesystem or
  // rendering library: the bidi-format-control set (Security.isBidiFormatControl,
  // the LRE/RLE/LRO/RLO/PDF and LRI/RLI/FSI/PDI codepoints RtlInjection keys on),
  // the grapheme GCB=Extend class (Security.isGraphemeExtend, Grapheme_Extend ∪
  // emoji-modifier from DerivedCoreProperties.txt), the inline fullwidth range
  // U+FF01..U+FFEF, and the ASCII dot U+002E.
  private static void testFilenameDisguise() throws IOException {
    // (a) Shared context-free fixture through detect.
    Map<String, Object> detector = fixture("detectors/filename_disguise.json");
    assertEquals(1, intValue(detector.get("schema")), "filename-disguise schema");
    assertEquals("filename-disguise", string(detector, "family"), "filename-disguise family");
    int fixtureCases = 0;
    for (Map<String, Object> entry : objects(detector.get("cases"))) {
      FilenameDisguise.Verdict verdict = FilenameDisguise.detect(ints(entry.get("input")));
      String code = FilenameDisguise.reasonCode(verdict.classify());
      List<String> required = strings(entry.get("required_findings"));
      if (required.isEmpty()) {
        assertEquals(null, code, "filename-disguise " + string(entry, "name") + " should be clear");
      } else {
        assertEquals(1, required.size(),
            "filename-disguise " + string(entry, "name") + " single finding");
        assertEquals(required.get(0), code, "filename-disguise " + string(entry, "name"));
      }
      fixtureCases++;
    }

    // (b) detect spot-checks and the priority-ladder structure check transcribed
    // one-for-one from the Rust test module.
    int specVectors = 0;

    // detect_empty_clear
    assertTrue(FilenameDisguise.detect(intList(new int[] {})).classify().isClear(),
        "fd empty clear");
    specVectors++;

    // detect_plain_txt_clear — "document.txt"; last dot at index 8.
    FilenameDisguise.Verdict plain = FilenameDisguise.detect(
        intList(new int[] {0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74}));
    assertTrue(plain.classify().isClear(), "fd plain txt clear");
    assertEquals(Integer.valueOf(8), plain.lastDotPos(), "fd plain txt last dot pos");
    specVectors++;

    // detect_no_extension_clear — "foo"; no dot.
    FilenameDisguise.Verdict noExt =
        FilenameDisguise.detect(intList(new int[] {0x66, 0x6F, 0x6F}));
    assertTrue(noExt.classify().isClear(), "fd no extension clear");
    assertEquals(null, noExt.lastDotPos(), "fd no extension last dot pos null");
    specVectors++;

    // detect_tar_gz_clear — "archive.tar.gz" (2 dots, below the multi-ext bound).
    assertTrue(
        FilenameDisguise.detect(intList(new int[] {
            0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A}))
            .classify().isClear(),
        "fd tar gz clear");
    specVectors++;

    // detect_hebrew_clear — native Hebrew name, no bidi controls.
    assertTrue(
        FilenameDisguise.detect(intList(new int[] {0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74}))
            .classify().isClear(),
        "fd hebrew clear");
    specVectors++;

    // detect_rlo_flip — "document<RLO>txt.exe"; RloFlip at position 8.
    FilenameDisguise.Verdict rlo = FilenameDisguise.detect(intList(new int[] {
        0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65,
        0x78, 0x65}));
    assertEquals("RloFlip", rlo.classify().tag(), "fd rlo flip tag");
    assertEquals(List.of(8), rlo.classify().positions(), "fd rlo flip positions");
    specVectors++;

    // detect_isolate_flip — RLI/PDI isolate variant, also RloFlip.
    assertEquals("RloFlip",
        FilenameDisguise.detect(intList(new int[] {
            0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069}))
            .classify().tag(),
        "fd isolate flip tag");
    specVectors++;

    // detect_fullwidth_exe — "file.ＥＸＥ".
    assertEquals("WidthClassExt",
        FilenameDisguise.detect(intList(new int[] {0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25}))
            .classify().tag(),
        "fd fullwidth ext tag");
    specVectors++;

    // detect_combining_in_ext — "file.é xe" (combining acute in the extension).
    assertEquals("CombiningInExt",
        FilenameDisguise.detect(intList(new int[] {0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65}))
            .classify().tag(),
        "fd combining in ext tag");
    specVectors++;

    // detect_triple_extension — "setup.tar.gz.sig".
    assertEquals("MultipleExtensions",
        FilenameDisguise.detect(intList(new int[] {
            0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A, 0x2E, 0x73,
            0x69, 0x67}))
            .classify().tag(),
        "fd triple extension tag");
    specVectors++;

    // bidi_beats_fullwidth — a bidi control outranks a fullwidth extension.
    assertEquals("RloFlip",
        FilenameDisguise.detect(intList(new int[] {0x202E, 0x66, 0x2E, 0xFF25})).classify().tag(),
        "fd bidi beats fullwidth");
    specVectors++;

    System.out.println("clean: JVM filename-disguise passes (" + fixtureCases
        + " fixture cases + " + specVectors + " spec vectors)");
  }

  // Pins the boundary-layer IdentifierFormDrift detector against the verified
  // Rust reference implementation. Two independent sources of truth are
  // exercised: (a) the shared context-free fixture
  // detectors/identifier_form_drift.json, run through IdentifierFormDrift.detect
  // and checked against the fixture reason codes; (b) the detect spot-checks and
  // the mid-string first-shift-position check transcribed one-for-one from the
  // Rust test module. Both predicates the detector consumes are the port's own
  // SHA-pinned pipeline, never a host normalization or identifier library: the
  // UTS #39 Identifier_Status = Allowed set (Security.isIdAllowed over the
  // bundled IdentifierStatus.txt) and the UAX #15 compatibility decomposition
  // (Security.toNfkd). U+1D44E / U+FF21 / U+24B6 / U+FB01 / U+2163 are Restricted
  // whose NFKD heads (a / A / A / f / I) are Allowed, so each shifts; ASCII
  // letters and Greek α are Allowed with identity NFKD, so they clear.
  private static void testIdentifierFormDrift() throws IOException {
    // (a) Shared context-free fixture through detect.
    Map<String, Object> detector = fixture("detectors/identifier_form_drift.json");
    assertEquals(1, intValue(detector.get("schema")), "identifier-form-drift schema");
    assertEquals("identifier-form-drift", string(detector, "family"), "identifier-form-drift family");
    int fixtureCases = 0;
    for (Map<String, Object> entry : objects(detector.get("cases"))) {
      IdentifierFormDrift.Verdict verdict = IdentifierFormDrift.detect(ints(entry.get("input")));
      String code = IdentifierFormDrift.reasonCode(verdict.classify());
      List<String> required = strings(entry.get("required_findings"));
      if (required.isEmpty()) {
        assertEquals(null, code, "identifier-form-drift " + string(entry, "name") + " should be clear");
      } else {
        assertEquals(1, required.size(),
            "identifier-form-drift " + string(entry, "name") + " single finding");
        assertEquals(required.get(0), code, "identifier-form-drift " + string(entry, "name"));
      }
      fixtureCases++;
    }

    // (b) detect spot-checks and the mid-string first-shift-position check
    // transcribed one-for-one from the Rust test module.
    int specVectors = 0;

    // detect_empty_clear
    assertTrue(IdentifierFormDrift.detect(intList(new int[] {})).classify().isClear(),
        "ifd empty clear");
    specVectors++;

    // detect_ascii_clear — "Hello"; every ASCII letter is Allowed, identity NFKD.
    IdentifierFormDrift.Verdict ascii =
        IdentifierFormDrift.detect(intList(new int[] {0x48, 0x65, 0x6C, 0x6C, 0x6F}));
    assertTrue(ascii.classify().isClear(), "ifd ascii clear");
    assertEquals(0, ascii.shiftCount(), "ifd ascii shift count");
    specVectors++;

    // detect_greek_alpha_clear — α is Allowed with identity NFKD.
    assertTrue(IdentifierFormDrift.detect(intList(new int[] {0x03B1})).classify().isClear(),
        "ifd greek alpha clear");
    specVectors++;

    // detect_math_italic_a_shift — U+1D44E Restricted, NFKD head U+0061 Allowed.
    IdentifierFormDrift.Verdict math = IdentifierFormDrift.detect(intList(new int[] {0x1D44E}));
    assertEquals("IdentifierStatusShift", math.classify().tag(), "ifd math italic a tag");
    assertEquals(List.of(0), math.classify().positions(), "ifd math italic a positions");
    assertEquals(1, math.shiftCount(), "ifd math italic a shift count");
    specVectors++;

    // detect_fullwidth_A_shift — U+FF21 Restricted, NFKD head U+0041 Allowed.
    assertEquals("IdentifierStatusShift",
        IdentifierFormDrift.detect(intList(new int[] {0xFF21})).classify().tag(),
        "ifd fullwidth A tag");
    specVectors++;

    // detect_circled_A_shift — U+24B6 CIRCLED LATIN CAPITAL LETTER A → Restricted → Allowed (A).
    assertEquals("IdentifierStatusShift",
        IdentifierFormDrift.detect(intList(new int[] {0x24B6})).classify().tag(),
        "ifd circled A tag");
    specVectors++;

    // detect_fi_ligature_shift — U+FB01 'ﬁ' ligature → Restricted → Allowed (f).
    assertEquals("IdentifierStatusShift",
        IdentifierFormDrift.detect(intList(new int[] {0xFB01})).classify().tag(),
        "ifd fi ligature tag");
    specVectors++;

    // detect_roman_iv_shift — U+2163 ROMAN NUMERAL FOUR → Restricted → Allowed (I).
    assertEquals("IdentifierStatusShift",
        IdentifierFormDrift.detect(intList(new int[] {0x2163})).classify().tag(),
        "ifd roman iv tag");
    specVectors++;

    // detect_reports_first_shift_position — "ab" + U+1D44E: positions 0,1 clear,
    // position 2 shifts.
    IdentifierFormDrift.Verdict mid =
        IdentifierFormDrift.detect(intList(new int[] {0x61, 0x62, 0x1D44E}));
    assertEquals(List.of(2), mid.classify().positions(), "ifd first shift position");
    assertEquals(1, mid.shiftCount(), "ifd first shift count");
    specVectors++;

    // reason_code_is_stable — the composed reason code for the sole sub-threat.
    assertEquals("unicode.security.X.identifier-form-drift.IdentifierStatusShift",
        IdentifierFormDrift.reasonCode(
            IdentifierFormDrift.detect(intList(new int[] {0x1D44E})).classify()),
        "ifd reason code stable");
    specVectors++;

    System.out.println("clean: JVM identifier-form-drift passes (" + fixtureCases
        + " fixture cases + " + specVectors + " spec vectors)");
  }

  // Pins the stream-safe-violation detector against the verified Rust reference
  // ports/rust/src/security/form/stream_safe_violation.rs. Two independent
  // sources of truth are exercised: (a) the shared context-free fixture
  // detectors/stream_safe_violation.json, run through StreamSafeViolation.detect
  // and checked against the fixture reason codes; (b) the boundary and
  // run-inventory structure checks transcribed from the Rust test module — the
  // 30/31 strict-'>' boundary, a bare mark run starting at index 0, two short
  // runs summed in the totals, and first-overrun-wins base_pos reporting. The
  // detector reads non-starter status from the port's own CCC
  // (Security.combiningClass), never java.text. U+0301 COMBINING ACUTE ACCENT
  // has CCC = 230 (a non-starter); the ASCII letters are starters (CCC = 0).
  private static void testStreamSafeViolation() throws IOException {
    final int acute = 0x0301;

    // (a) Shared context-free fixture through detect.
    Map<String, Object> detector = fixture("detectors/stream_safe_violation.json");
    assertEquals(1, intValue(detector.get("schema")), "stream-safe-violation schema");
    assertEquals("stream-safe-violation", string(detector, "family"), "stream-safe-violation family");
    int fixtureCases = 0;
    for (Map<String, Object> entry : objects(detector.get("cases"))) {
      StreamSafeViolation.Verdict verdict = StreamSafeViolation.detect(ints(entry.get("input")));
      String code = StreamSafeViolation.reasonCode(verdict.classify());
      List<String> required = strings(entry.get("required_findings"));
      if (required.isEmpty()) {
        assertEquals(null, code, "stream-safe-violation " + string(entry, "name") + " should be clear");
      } else {
        assertEquals(1, required.size(), "stream-safe-violation " + string(entry, "name") + " single finding");
        assertEquals(required.get(0), code, "stream-safe-violation " + string(entry, "name"));
      }
      fixtureCases++;
    }

    // (b) Boundary and run-inventory structure checks from the Rust test module.
    int structureVectors = 0;

    // detect_empty_clear: empty input is clear; all summaries zero.
    StreamSafeViolation.Verdict empty = StreamSafeViolation.detect(intList(new int[] {}));
    assertTrue(empty.classify().isClear(), "ssv empty clear");
    assertEquals(null, empty.classify().tag(), "ssv empty tag");
    assertEquals(0, empty.maxRunLen(), "ssv empty maxRunLen");
    assertEquals(0, empty.overrunCount(), "ssv empty overrunCount");
    assertEquals(0, empty.totalNonStarters(), "ssv empty totalNonStarters");
    structureVectors++;

    // detect_one_combine_clear: "a" + one mark is clear, one non-starter.
    StreamSafeViolation.Verdict one = StreamSafeViolation.detect(intList(new int[] {0x61, acute}));
    assertTrue(one.classify().isClear(), "ssv one-combine clear");
    assertEquals(1, one.maxRunLen(), "ssv one-combine maxRunLen");
    assertEquals(0, one.overrunCount(), "ssv one-combine overrunCount");
    assertEquals(1, one.totalNonStarters(), "ssv one-combine totalNonStarters");
    structureVectors++;

    // detect_thirty_marks_clear: exactly 30 marks is the boundary — clear under strict '>'.
    StreamSafeViolation.Verdict thirty = StreamSafeViolation.detect(aPlusMarks(30, acute));
    assertTrue(thirty.classify().isClear(), "ssv 30 marks clear");
    assertEquals(null, thirty.classify().tag(), "ssv 30 marks tag");
    assertEquals(30, thirty.maxRunLen(), "ssv 30 marks maxRunLen");
    assertEquals(0, thirty.overrunCount(), "ssv 30 marks overrunCount");
    assertEquals(30, thirty.totalNonStarters(), "ssv 30 marks totalNonStarters");
    structureVectors++;

    // detect_thirtyone_marks_hazard: 31 marks fires StreamSafeOverrun(1, 31), positions [1].
    StreamSafeViolation.Verdict thirtyOne = StreamSafeViolation.detect(aPlusMarks(31, acute));
    assertTrue(!thirtyOne.classify().isClear(), "ssv 31 marks hazard");
    assertEquals("StreamSafeOverrun", thirtyOne.classify().tag(), "ssv 31 marks tag");
    assertEquals(List.of(1), thirtyOne.classify().positions(), "ssv 31 marks positions");
    StreamSafeViolation.Hazard hz = (StreamSafeViolation.Hazard) thirtyOne.classify();
    StreamSafeViolation.StreamSafeOverrun sub = (StreamSafeViolation.StreamSafeOverrun) hz.sub();
    assertEquals(1, sub.basePos(), "ssv 31 marks basePos");
    assertEquals(31, sub.runLen(), "ssv 31 marks runLen");
    assertEquals(List.of(), hz.decoded(), "ssv 31 marks decoded empty");
    assertEquals(31, thirtyOne.maxRunLen(), "ssv 31 marks maxRunLen");
    assertEquals(1, thirtyOne.overrunCount(), "ssv 31 marks overrunCount");
    assertEquals(31, thirtyOne.totalNonStarters(), "ssv 31 marks totalNonStarters");
    structureVectors++;

    // bare_mark_run_starts_at_zero: a bare 31-mark run (no leading starter) records start 0.
    List<Integer> bare = new ArrayList<>();
    for (int i = 0; i < 31; i++) bare.add(acute);
    StreamSafeViolation.Verdict bareVerdict = StreamSafeViolation.detect(bare);
    assertEquals("StreamSafeOverrun", bareVerdict.classify().tag(), "ssv bare run tag");
    assertEquals(List.of(0), bareVerdict.classify().positions(), "ssv bare run positions");
    assertEquals(31, bareVerdict.maxRunLen(), "ssv bare run maxRunLen");
    assertEquals(31, bareVerdict.totalNonStarters(), "ssv bare run totalNonStarters");
    structureVectors++;

    // two_short_runs_clear_totals_summed: "a" + 30 marks + "b" + 30 marks stays clear,
    // both runs summed in the totals.
    List<Integer> twoRuns = aPlusMarks(30, acute);
    twoRuns.add(0x62);
    for (int i = 0; i < 30; i++) twoRuns.add(acute);
    StreamSafeViolation.Verdict twoVerdict = StreamSafeViolation.detect(twoRuns);
    assertTrue(twoVerdict.classify().isClear(), "ssv two short runs clear");
    assertEquals(30, twoVerdict.maxRunLen(), "ssv two short runs maxRunLen");
    assertEquals(0, twoVerdict.overrunCount(), "ssv two short runs overrunCount");
    assertEquals(60, twoVerdict.totalNonStarters(), "ssv two short runs totalNonStarters");
    structureVectors++;

    // first_overrun_reports_long_run_start: "a" + 5 marks + "b" + 31 marks — the run
    // starting at index 7 fires; a short run before it does not shadow it.
    List<Integer> firstOverrun = aPlusMarks(5, acute);
    firstOverrun.add(0x62);
    for (int i = 0; i < 31; i++) firstOverrun.add(acute);
    StreamSafeViolation.Verdict foVerdict = StreamSafeViolation.detect(firstOverrun);
    assertEquals("StreamSafeOverrun", foVerdict.classify().tag(), "ssv first-overrun tag");
    assertEquals(List.of(7), foVerdict.classify().positions(), "ssv first-overrun positions");
    assertEquals(31, foVerdict.maxRunLen(), "ssv first-overrun maxRunLen");
    assertEquals(1, foVerdict.overrunCount(), "ssv first-overrun overrunCount");
    assertEquals(36, foVerdict.totalNonStarters(), "ssv first-overrun totalNonStarters");
    structureVectors++;

    System.out.println("clean: JVM stream-safe-violation passes (" + fixtureCases
        + " fixture cases + " + structureVectors + " structure vectors)");
  }

  // "a" (U+0061) followed by n combining marks. Mutable so callers can extend it.
  private static List<Integer> aPlusMarks(int n, int mark) {
    List<Integer> out = new ArrayList<>();
    out.add(0x61);
    for (int i = 0; i < n; i++) out.add(mark);
    return out;
  }

  // Pins the form-layer CaseExpansionMismatch detector against the verified Rust
  // reference ports/rust/src/security/form/case_expansion_mismatch.rs. Two
  // independent sources of truth are exercised: (a) the shared context-free
  // fixture detectors/case_expansion_mismatch.json, run through
  // CaseExpansionMismatch.detect and checked against the fixture reason codes;
  // (b) the classification, count, and expansion-length spot-checks transcribed
  // from the Rust test module — empty and "Hello" ASCII stay clear; U+00DF ß
  // toUpper → "SS" fires UpperExpansion (len 2); U+FB01 ﬁ and U+FB03 ﬃ (len 3)
  // fire UpperExpansion; U+0130 İ has no upper expansion and falls through to
  // LowerExpansion; and a leading ASCII then ß reports the expansion at
  // position 1. The detector reads its case mapping from the port's own
  // Security.upperCodepoint / Security.lowerCodepoint (the extended SpecialCasing
  // upper column + UnicodeData simple-uppercase), never a host casing library.
  private static void testCaseExpansionMismatch() throws IOException {
    // (a) Shared context-free fixture through detect.
    Map<String, Object> detector = fixture("detectors/case_expansion_mismatch.json");
    assertEquals(1, intValue(detector.get("schema")), "case-expansion-mismatch schema");
    assertEquals("case-expansion-mismatch", string(detector, "family"), "case-expansion-mismatch family");
    int fixtureCases = 0;
    for (Map<String, Object> entry : objects(detector.get("cases"))) {
      CaseExpansionMismatch.Verdict verdict = CaseExpansionMismatch.detect(ints(entry.get("input")));
      String code = CaseExpansionMismatch.reasonCode(verdict.classify());
      List<String> required = strings(entry.get("required_findings"));
      if (required.isEmpty()) {
        assertEquals(null, code, "case-expansion-mismatch " + string(entry, "name") + " should be clear");
      } else {
        assertEquals(1, required.size(), "case-expansion-mismatch " + string(entry, "name") + " single finding");
        assertEquals(required.get(0), code, "case-expansion-mismatch " + string(entry, "name"));
      }
      fixtureCases++;
    }

    // (b) Classification / count / length spot-checks from the Rust test module.
    int structureVectors = 0;

    // detect_empty_clear: empty input is clear; max expansion length zero.
    CaseExpansionMismatch.Verdict empty = CaseExpansionMismatch.detect(intList(new int[] {}));
    assertTrue(empty.classify().isClear(), "cem empty clear");
    assertEquals(null, empty.classify().tag(), "cem empty tag");
    assertEquals(0, empty.maxExpansionLen(), "cem empty maxExpansionLen");
    structureVectors++;

    // detect_ascii_clear: "Hello" — every ASCII cp case-maps to a single cp.
    CaseExpansionMismatch.Verdict hello =
        CaseExpansionMismatch.detect(intList(new int[] {0x48, 0x65, 0x6C, 0x6C, 0x6F}));
    assertTrue(hello.classify().isClear(), "cem ascii clear");
    assertEquals(1, hello.maxExpansionLen(), "cem ascii maxExpansionLen");
    structureVectors++;

    // detect_sharp_s_upper: ß (U+00DF) toUpper → "SS".
    CaseExpansionMismatch.Verdict sharpS = CaseExpansionMismatch.detect(intList(new int[] {0x00DF}));
    assertEquals("UpperExpansion", sharpS.classify().tag(), "cem sharp-s tag");
    assertEquals(List.of(0), sharpS.classify().positions(), "cem sharp-s positions");
    assertEquals(1, sharpS.upperExpansionCount(), "cem sharp-s upperExpansionCount");
    assertEquals(2, sharpS.maxExpansionLen(), "cem sharp-s maxExpansionLen");
    CaseExpansionMismatch.Hazard sharpHz = (CaseExpansionMismatch.Hazard) sharpS.classify();
    CaseExpansionMismatch.UpperExpansion sharpSub =
        (CaseExpansionMismatch.UpperExpansion) sharpHz.sub();
    assertEquals(0, sharpSub.basePos(), "cem sharp-s basePos");
    assertEquals(0x00DF, sharpSub.cp(), "cem sharp-s cp");
    assertEquals(2, sharpSub.expansionLen(), "cem sharp-s expansionLen");
    assertEquals(List.of(), sharpHz.decoded(), "cem sharp-s decoded empty");
    structureVectors++;

    // detect_fi_ligature_upper: ﬁ (U+FB01) toUpper → "FI".
    CaseExpansionMismatch.Verdict fi = CaseExpansionMismatch.detect(intList(new int[] {0xFB01}));
    assertEquals("UpperExpansion", fi.classify().tag(), "cem fi-ligature tag");
    structureVectors++;

    // detect_ffi_ligature_len3: ﬃ (U+FB03) toUpper → "FFI" (length 3).
    CaseExpansionMismatch.Verdict ffi = CaseExpansionMismatch.detect(intList(new int[] {0xFB03}));
    assertEquals("UpperExpansion", ffi.classify().tag(), "cem ffi-ligature tag");
    assertEquals(3, ffi.maxExpansionLen(), "cem ffi-ligature maxExpansionLen");
    structureVectors++;

    // detect_dotted_I_lower: İ (U+0130) has no upper expansion; toLower under the
    // default locale → "i + 0307", so the detector falls through to the lower scan.
    CaseExpansionMismatch.Verdict dottedI = CaseExpansionMismatch.detect(intList(new int[] {0x0130}));
    assertEquals("LowerExpansion", dottedI.classify().tag(), "cem dotted-I tag");
    assertEquals(1, dottedI.lowerExpansionCount(), "cem dotted-I lowerExpansionCount");
    structureVectors++;

    // detect_reports_first_expansion_position: a leading ASCII then ß reports the
    // upper expansion at position 1.
    CaseExpansionMismatch.Verdict midString =
        CaseExpansionMismatch.detect(intList(new int[] {0x61, 0x00DF}));
    assertEquals(List.of(1), midString.classify().positions(), "cem mid-string positions");
    structureVectors++;

    // reason_code_is_stable: the composed reason code for each sub-threat.
    assertEquals("unicode.security.F.case-expansion-mismatch.UpperExpansion",
        CaseExpansionMismatch.reasonCode(
            new CaseExpansionMismatch.Hazard(
                new CaseExpansionMismatch.UpperExpansion(0, 0x00DF, 2), List.of(0), List.of())),
        "cem reason code upper");
    assertEquals("unicode.security.F.case-expansion-mismatch.LowerExpansion",
        CaseExpansionMismatch.reasonCode(
            new CaseExpansionMismatch.Hazard(
                new CaseExpansionMismatch.LowerExpansion(0, 0x0130, 2), List.of(0), List.of())),
        "cem reason code lower");
    assertEquals(null, CaseExpansionMismatch.reasonCode(new CaseExpansionMismatch.Clear()),
        "cem reason code clear");
    structureVectors++;

    System.out.println("clean: JVM case-expansion-mismatch passes (" + fixtureCases
        + " fixture cases + " + structureVectors + " structure vectors)");
  }

  private static void assertHisCtx(HashInputStability.Context ctx, int[] input,
                                   String wantTag, List<Integer> wantPositions, String message) {
    HashInputStability.Verdict verdict = HashInputStability.detectWithContext(ctx, intList(input));
    assertEquals(wantTag, verdict.classify().tag(), message + " tag");
    assertEquals(wantPositions, verdict.classify().positions(), message + " positions");
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
