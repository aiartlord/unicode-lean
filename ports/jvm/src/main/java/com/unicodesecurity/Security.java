package com.unicodesecurity;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class Security {
  public static final class Action {
    public static final String ALLOW = "allow";
    public static final String REJECT = "reject";
    public static final String QUARANTINE = "quarantine";
    public static final String REWRITE = "rewrite";
    public static final String OBSERVE = "observe";
    private Action() {}
  }

  public static final class Mode {
    public static final String OBSERVE = "observe";
    public static final String WARN = "warn";
    public static final String ENFORCE = "enforce";
    public static final String STRICT = "strict";
    private Mode() {}
  }

  public static final class Profile {
    public static final String GATEWAY_HEADER = "gateway-header";
    public static final String DOMAIN_NAME = "domain-name";
    public static final String DNS_LABEL = "dns-label";
    public static final String URL = "url";
    public static final String USERNAME = "username";
    public static final String DISPLAY_NAME = "display-name";
    public static final String CHAT_MESSAGE = "chat-message";
    public static final String SOURCE_CODE = "source-code";
    public static final String OPAQUE_SECRET = "opaque-secret";
    public static final String BINARY_BLOB = "binary-blob";
    private Profile() {}
  }

  public static final class Family {
    public static final String MALFORMED_UTF8 = "malformed-utf8";
    public static final String MALFORMED_UTF16 = "malformed-utf16";
    public static final String MALFORMED_UTF32 = "malformed-utf32";
    public static final String TAG_BLOCK_PAYLOAD = "tag-block-payload";
    public static final String VARIATION_SELECTOR_PAYLOAD = "variation-selector-payload";
    public static final String ZERO_WIDTH_PAYLOAD = "zero-width-payload";
    public static final String SURROGATE_REASSEMBLY = "surrogate-reassembly";
    public static final String BIDI_CONTROL_BALANCE = "bidi-control-balance";
    public static final String NONCHARACTER_CONTROL = "noncharacter-control";
    public static final String HOMOGLYPH_CONFUSABLE = "homoglyph-confusable";
    public static final String MIXED_SCRIPT_ADMISSIBILITY = "mixed-script-admissibility";
    public static final String RTL_INJECTION = "rtl-injection";
    public static final String CONFUSABLE_BIDI_COMPOUND = "confusable-bidi-compound";
    private Family() {}
  }

  public record Finding(String code, String family, int severity, List<Integer> positions, String subThreat, String detail) {}

  public record Verdict(String action, String profile, String mode, List<Integer> input, List<Finding> findings, List<Integer> normalized) {}

  private enum PolicyLevel { RESTRICTIVE, MODERATE, MINIMAL }

  private record ProfilePolicy(PolicyLevel level, boolean quarantine) {}

  private record DecodeFailure(String subThreat, int offset) {}

  private record DecodeResult(List<Integer> codepoints, DecodeFailure failure) {}

  private record Utf8State(boolean inSequence, int remaining, int accum, int minCp) {}

  private record Utf8Step(Utf8State state, int emitted, String kind, boolean rejected) {}

  private enum ByteOrder { BIG, LITTLE }

  // The strong Bidi_Class distinction the display layer needs. Every
  // non-strong Bidi_Class collapses to OTHER.
  private enum BidiStrong { R, AL, L, OTHER }

  private record BidiRange(int lo, int hi, BidiStrong cls) {}

  // Explicit ranges (sorted by lo) and @missing default ranges (in file
  // order; the last match wins), parsed from DerivedBidiClass.txt.
  private record BidiTable(List<BidiRange> explicit, List<BidiRange> defaults) {}

  private static Map<Integer, List<Integer>> confusablesMap;
  private static Map<Integer, List<Integer>> caseFoldingMap;
  private static List<String> knownTargets;
  private static Set<Long> legalVariationPairs;
  private static BidiTable bidiTable;

  private Security() {}

  public static Verdict scan(String profile, String mode, List<Integer> input) {
    List<Integer> codepoints = input.stream().map(Security::ensureCodepoint).toList();
    List<Finding> findings = detect(codepoints);
    return new Verdict(decide(profile, mode, findings), profile, mode, codepoints, findings, null);
  }

  public static Verdict scanUtf8(String profile, String mode, byte[] input) {
    DecodeFailure failure = firstInvalidUtf8(input);
    if (failure != null) {
      return malformedDecodeVerdict(profile, mode, Family.MALFORMED_UTF8, failure.subThreat(), failure.offset());
    }
    return scan(profile, mode, decodeUtf8ToCodepoints(input));
  }

  public static Verdict scanUtf16BE(String profile, String mode, byte[] input) {
    return scanUtf16(profile, mode, input, ByteOrder.BIG);
  }

  public static Verdict scanUtf16LE(String profile, String mode, byte[] input) {
    return scanUtf16(profile, mode, input, ByteOrder.LITTLE);
  }

  public static Verdict scanUtf32BE(String profile, String mode, byte[] input) {
    return scanUtf32(profile, mode, input, ByteOrder.BIG);
  }

  public static Verdict scanUtf32LE(String profile, String mode, byte[] input) {
    return scanUtf32(profile, mode, input, ByteOrder.LITTLE);
  }

  public static String verdictJson(Verdict verdict) {
    StringBuilder out = new StringBuilder();
    out.append('{');
    jsonField(out, "action", verdict.action());
    out.append(',');
    jsonField(out, "profile", verdict.profile());
    out.append(',');
    jsonField(out, "mode", verdict.mode());
    out.append(',');
    out.append("\"input\":");
    appendIntArray(out, verdict.input());
    out.append(',');
    out.append("\"findings\":[");
    for (int i = 0; i < verdict.findings().size(); i++) {
      if (i > 0) out.append(',');
      appendFinding(out, verdict.findings().get(i));
    }
    out.append("],");
    out.append("\"normalized\":");
    if (verdict.normalized() == null) {
      out.append("null");
    } else {
      appendIntArray(out, verdict.normalized());
    }
    out.append('}');
    return out.toString();
  }

  private static List<Finding> detect(List<Integer> input) {
    List<Finding> findings = new ArrayList<>();
    List<Integer> tags = positionsWhere(input, Security::isTagBlockAsciiPayload);
    if (!tags.isEmpty()) findings.add(makeFinding(Family.TAG_BLOCK_PAYLOAD, "DirectAscii", tags));
    Finding variation = variationSelectorFinding(input);
    if (variation != null) findings.add(variation);
    List<Integer> zeroWidth = positionsWhere(input, Security::isZeroWidthPayload);
    if (!zeroWidth.isEmpty()) findings.add(makeFinding(Family.ZERO_WIDTH_PAYLOAD, "BareZeroWidth", zeroWidth));
    Finding surrogate = surrogateReassemblyFinding(input);
    if (surrogate != null) findings.add(surrogate);
    List<Integer> bidi = positionsWhere(input, Security::isBidiEmbeddingControl);
    if (!bidi.isEmpty()) findings.add(makeFinding(Family.BIDI_CONTROL_BALANCE, "UnbalancedEmbedding", bidi));
    findings.addAll(noncharacterControlFindings(input));
    Finding homoglyph = homoglyphConfusableFinding(input);
    if (homoglyph != null) findings.add(homoglyph);
    Finding mixedScript = mixedScriptAdmissibilityFinding(input);
    if (mixedScript != null) findings.add(mixedScript);
    Finding rtl = rtlInjectionFinding(input);
    if (rtl != null) findings.add(rtl);
    Finding confusableBidi = confusableBidiCompoundFinding(input);
    if (confusableBidi != null) findings.add(confusableBidi);
    return findings;
  }

  private static String decide(String profile, String mode, List<Finding> findings) {
    if (findings.isEmpty()) return Action.ALLOW;
    if (Objects.equals(mode, Mode.OBSERVE) || Objects.equals(mode, Mode.WARN)) return Action.OBSERVE;
    if (Objects.equals(mode, Mode.STRICT)) return Action.REJECT;
    ProfilePolicy policy = policyOfProfile(profile);
    for (Finding finding : findings) {
      if (blocks(policy.level(), finding.family())) {
        return policy.quarantine() ? Action.QUARANTINE : Action.REJECT;
      }
    }
    return Action.ALLOW;
  }

  private static ProfilePolicy policyOfProfile(String profile) {
    return switch (profile) {
      case Profile.GATEWAY_HEADER, Profile.DOMAIN_NAME, Profile.DNS_LABEL, Profile.SOURCE_CODE ->
          new ProfilePolicy(PolicyLevel.RESTRICTIVE, false);
      case Profile.URL -> new ProfilePolicy(PolicyLevel.MODERATE, false);
      case Profile.USERNAME -> new ProfilePolicy(PolicyLevel.MODERATE, true);
      case Profile.DISPLAY_NAME, Profile.CHAT_MESSAGE -> new ProfilePolicy(PolicyLevel.MINIMAL, true);
      case Profile.OPAQUE_SECRET, Profile.BINARY_BLOB -> new ProfilePolicy(PolicyLevel.MINIMAL, false);
      default -> new ProfilePolicy(PolicyLevel.RESTRICTIVE, false);
    };
  }

  private static boolean blocks(PolicyLevel level, String family) {
    if (level == PolicyLevel.MINIMAL) {
      return family.equals(Family.MALFORMED_UTF8) || family.equals(Family.MALFORMED_UTF16) ||
          family.equals(Family.MALFORMED_UTF32) || family.equals(Family.SURROGATE_REASSEMBLY) ||
          family.equals(Family.BIDI_CONTROL_BALANCE) ||
          family.equals(Family.NONCHARACTER_CONTROL);
    }
    return family.equals(Family.MALFORMED_UTF8) || family.equals(Family.MALFORMED_UTF16) ||
        family.equals(Family.MALFORMED_UTF32) || family.equals(Family.TAG_BLOCK_PAYLOAD) ||
        family.equals(Family.VARIATION_SELECTOR_PAYLOAD) || family.equals(Family.ZERO_WIDTH_PAYLOAD) ||
        family.equals(Family.SURROGATE_REASSEMBLY) ||
        family.equals(Family.CONFUSABLE_BIDI_COMPOUND) ||
        family.equals(Family.BIDI_CONTROL_BALANCE) || family.equals(Family.NONCHARACTER_CONTROL) ||
        family.equals(Family.HOMOGLYPH_CONFUSABLE) ||
        family.equals(Family.MIXED_SCRIPT_ADMISSIBILITY);
  }

  private static Verdict malformedDecodeVerdict(String profile, String mode, String family, String subThreat, int offset) {
    List<Finding> findings = List.of(makeFinding(family, subThreat, List.of(offset)));
    return new Verdict(decide(profile, mode, findings), profile, mode, List.of(), findings, null);
  }

  private static Finding makeFinding(String family, String subThreat, List<Integer> positions) {
    return new Finding(reasonCode(family, subThreat), family, 2, List.copyOf(positions), subThreat, family);
  }

  private static String reasonCode(String family, String subThreat) {
    return "unicode.security." + layer(family) + "." + family + "." + subThreat;
  }

  private static String layer(String family) {
    if (family.equals(Family.HOMOGLYPH_CONFUSABLE)
        || family.equals(Family.MIXED_SCRIPT_ADMISSIBILITY)) {
      return "I";
    }
    if (family.equals(Family.RTL_INJECTION)) {
      return "D";
    }
    if (family.equals(Family.CONFUSABLE_BIDI_COMPOUND)) {
      return "X";
    }
    return "C";
  }

  private static List<Integer> positionsWhere(List<Integer> input, IntPredicate predicate) {
    List<Integer> positions = new ArrayList<>();
    for (int i = 0; i < input.size(); i++) {
      if (predicate.test(input.get(i))) positions.add(i);
    }
    return positions;
  }

  private static boolean isTagBlockAsciiPayload(int cp) {
    return cp >= 0xE0020 && cp <= 0xE007E;
  }

  private static Finding variationSelectorFinding(List<Integer> input) {
    List<Integer> positions = positionsWhere(input, Security::isVariationSelector);
    if (positions.isEmpty()) return null;
    if (positions.size() == 1 && isRegisteredVariationPosition(input, positions.get(0))) return null;
    String subThreat = "IllegalTarget";
    if (positions.size() >= 4 && allSameAt(input, positions)) {
      subThreat = "RepeatedBase";
    } else if (!decodeVariationSelectorRun(input, positions).isEmpty()) {
      subThreat = "DirectPayload";
    }
    return makeFinding(Family.VARIATION_SELECTOR_PAYLOAD, subThreat, positions);
  }

  private static boolean isVariationSelector(int cp) {
    return (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF) || (cp >= 0x180B && cp <= 0x180D);
  }

  private static boolean isRegisteredVariationPosition(List<Integer> input, int position) {
    return position > 0 && legalVariationPairs().contains(variationPairKey(input.get(position - 1), input.get(position)));
  }

  private static Integer variationSelectorNibble(int cp) {
    if (cp >= 0xFE00 && cp <= 0xFE0F) return cp - 0xFE00;
    if (cp >= 0xE0100 && cp <= 0xE01EF) return cp - 0xE0100 + 16;
    return null;
  }

  private static List<Integer> decodeVariationSelectorRun(List<Integer> input, List<Integer> positions) {
    List<Integer> out = new ArrayList<>();
    int high = 0;
    boolean haveHigh = false;
    for (int position : positions) {
      Integer nibble = variationSelectorNibble(input.get(position));
      if (nibble == null) continue;
      if (!haveHigh) {
        high = nibble;
        haveHigh = true;
      } else {
        out.add((high << 4) | nibble);
        haveHigh = false;
      }
    }
    return out;
  }

  private static boolean allSameAt(List<Integer> input, List<Integer> positions) {
    if (positions.isEmpty()) return true;
    int first = input.get(positions.get(0));
    for (int position : positions) {
      if (input.get(position) != first) return false;
    }
    return true;
  }

  private static boolean isZeroWidthPayload(int cp) {
    return cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0x2060 || cp == 0xFEFF;
  }

  private static boolean isBidiEmbeddingControl(int cp) {
    return cp >= 0x202A && cp <= 0x202E;
  }

  /** Sub-threat and byte offset of a surrogate-reassembly scan; null sub-threat means clear. */
  public record SurrogateReassemblyResult(String subThreat, List<Integer> positions) {}

  // Surrogate-reassembly / malformed-byte-stream detection for a codepoint
  // list shaped as a byte stream — a direct port of
  // Unicode/Security/Covert/SurrogateReassembly.lean. Exposed for direct
  // spot-check testing, mirroring the Rust/Python/C++ detectors. The family
  // only applies when every entry is a byte (< 0x100); the verdict projects
  // the first UTF-8 violation found by the shared strict decoder onto a
  // covert-layer sub-threat.
  public static SurrogateReassemblyResult surrogateReassemblyDetect(List<Integer> input) {
    if (!looksLikeByteStream(input)) return new SurrogateReassemblyResult(null, List.of());
    byte[] bytes = new byte[input.size()];
    for (int i = 0; i < input.size(); i++) bytes[i] = (byte) (int) input.get(i);
    DecodeFailure failure = firstInvalidUtf8(bytes);
    if (failure == null) return new SurrogateReassemblyResult(null, List.of());
    return new SurrogateReassemblyResult(surrogateSubThreatOfRejectKind(failure.subThreat()), List.of(failure.offset()));
  }

  private static Finding surrogateReassemblyFinding(List<Integer> input) {
    SurrogateReassemblyResult result = surrogateReassemblyDetect(input);
    if (result.subThreat() == null) return null;
    return makeFinding(Family.SURROGATE_REASSEMBLY, result.subThreat(), result.positions());
  }

  // The looksLikeByteStream gate: a codepoint-array input containing any
  // value >= 0x100 is not a byte stream, and running the UTF-8 decoder on it
  // would be meaningless.
  private static boolean looksLikeByteStream(List<Integer> input) {
    for (int cp : input) {
      if (cp >= 0x100) return false;
    }
    return true;
  }

  // Project the shared strict UTF-8 reject kind onto its surrogate-reassembly
  // sub-threat tag. These tags deliberately differ from the malformed-utf8
  // tags (which reuse the raw reject-kind names) so the covert-layer verdict
  // reads in the CESU-8 / overlong / truncation vocabulary of the threat
  // model. Mirrors subThreatOfRejectKind in the Lean spec.
  private static String surrogateSubThreatOfRejectKind(String rejectKind) {
    return switch (rejectKind) {
      case "OverlongEncoding" -> "Overlong";
      case "SurrogateCodepoint" -> "Cesu8";
      case "TruncatedSequence" -> "Truncated";
      case "InvalidStartByte" -> "InvalidStartByte";
      case "InvalidContinuationByte" -> "InvalidContinuation";
      case "CodepointBeyondMax" -> "CodepointBeyondMax";
      default -> throw new IllegalStateException("unknown UTF-8 reject kind: " + rejectKind);
    };
  }

  private static List<Finding> noncharacterControlFindings(List<Integer> input) {
    List<Finding> findings = new ArrayList<>();
    List<Integer> noncharacters = positionsWhere(input, Security::isNoncharacter);
    if (!noncharacters.isEmpty()) findings.add(makeFinding(Family.NONCHARACTER_CONTROL, "Noncharacter", noncharacters));
    List<Integer> c0 = positionsWhere(input, Security::isC0Control);
    if (!c0.isEmpty()) findings.add(makeFinding(Family.NONCHARACTER_CONTROL, "C0Control", c0));
    List<Integer> c1 = positionsWhere(input, Security::isC1Control);
    if (!c1.isEmpty()) findings.add(makeFinding(Family.NONCHARACTER_CONTROL, "C1Control", c1));
    return findings;
  }

  private static Finding homoglyphConfusableFinding(List<Integer> input) {
    String subThreat = "";
    if (homoglyphTargetMatch(input) != null) subThreat = "TargetMatch";
    else if (input.stream().anyMatch(Security::isMathAlphanumeric)) subThreat = "MathAlpha";
    else if (input.stream().anyMatch(Security::isFullwidthHalfwidth)) subThreat = "WidthClass";
    else if (hasDecompositionSwap(input)) subThreat = "DecompositionSwap";
    if (subThreat.isEmpty()) return null;
    return makeFinding(Family.HOMOGLYPH_CONFUSABLE, subThreat, fullSpanPositions(input));
  }

  private static Finding mixedScriptAdmissibilityFinding(List<Integer> input) {
    if (!hasCrossScriptMix(input)) return null;
    return makeFinding(Family.MIXED_SCRIPT_ADMISSIBILITY, mixedScriptSubThreat(input), fullSpanPositions(input));
  }

  /** Sub-threat and offending positions of an RTL-injection scan; null sub-threat means clear. */
  public record RtlInjectionResult(String subThreat, List<Integer> positions) {}

  // Right-to-left injection detection for LTR-declared fields — a direct
  // port of Unicode/Security/Display/RtlInjection.lean. Exposed for direct
  // spot-check testing, mirroring the Rust/Python/C++ detectors.
  public static RtlInjectionResult rtlInjectionDetect(List<Integer> input) {
    int strongRtl = 0;
    for (int cp : input) {
      if (isStrongRtl(cp)) strongRtl++;
    }
    int[] run = longestRtlRun(input);
    int runLen = run[0];
    int runStart = run[1];

    // Phase 1: bidi format-control trumps all.
    for (int index = 0; index < input.size(); index++) {
      if (isBidiFormatControl(input.get(index))) {
        return new RtlInjectionResult("RloInLTRField", List.of(index));
      }
    }

    // Phase 2: leading-RTL field-direction takeover.
    for (int index = 0; index < input.size(); index++) {
      if (isStrongRtl(input.get(index))) return new RtlInjectionResult("FieldTakeover", List.of(index));
      if (isStrongLtr(input.get(index))) break;
    }

    // Phase 3: mid-stream strong-RTL.
    if (strongRtl == 0) return new RtlInjectionResult(null, List.of());
    if (runLen >= 4) return new RtlInjectionResult("MixedOverflow", List.of(runStart));
    for (int index = 0; index < input.size(); index++) {
      if (isStrongRtl(input.get(index))) return new RtlInjectionResult("StrongRTLInLTR", List.of(index));
    }
    return new RtlInjectionResult(null, List.of());
  }

  private static Finding rtlInjectionFinding(List<Integer> input) {
    RtlInjectionResult result = rtlInjectionDetect(input);
    if (result.subThreat() == null) return null;
    return makeFinding(Family.RTL_INJECTION, result.subThreat(), result.positions());
  }

  /** Sub-threat and offending positions of a confusable-bidi-compound scan; null sub-threat means clear. */
  public record ConfusableBidiCompoundResult(String subThreat, List<Integer> positions) {}

  // Cross-layer identity-times-display compound detection — a direct port of
  // Unicode/Security/Boundary/ConfusableBidiCompound.lean. A confusable
  // (homoglyph) codepoint co-located with a bidi format-control is materially
  // more dangerous than either alone: the homoglyph disguises an identifier
  // while the bidi control reorders how a reviewer reads it. This fires only
  // when both are present. With a confusable present, an override-class control
  // (LRE/RLE/LRO/RLO/PDF) fires ConfusableInOverride; otherwise an isolate-class
  // control (LRI/RLI/FSI/PDI) fires ConfusableInIsolate; otherwise clear.
  // Exposed for direct spot-check testing, mirroring the Rust/Python/C++ detectors.
  public static ConfusableBidiCompoundResult confusableBidiCompoundDetect(List<Integer> input) {
    int confusablePos = firstPositionWhere(input, Security::isConfusableSource);
    if (confusablePos < 0) return new ConfusableBidiCompoundResult(null, List.of());
    int overridePos = firstPositionWhere(input, Security::isConfusableBidiOverride);
    if (overridePos >= 0) {
      return new ConfusableBidiCompoundResult("ConfusableInOverride", List.of(confusablePos, overridePos));
    }
    int isolatePos = firstPositionWhere(input, Security::isConfusableBidiIsolate);
    if (isolatePos >= 0) {
      return new ConfusableBidiCompoundResult("ConfusableInIsolate", List.of(confusablePos, isolatePos));
    }
    return new ConfusableBidiCompoundResult(null, List.of());
  }

  private static Finding confusableBidiCompoundFinding(List<Integer> input) {
    ConfusableBidiCompoundResult result = confusableBidiCompoundDetect(input);
    if (result.subThreat() == null) return null;
    return makeFinding(Family.CONFUSABLE_BIDI_COMPOUND, result.subThreat(), result.positions());
  }

  // True iff cp is a confusable source per UTS #39 §4 — it has a row in
  // confusables.txt. The same table the homoglyph detector consumes.
  private static boolean isConfusableSource(int cp) {
    return confusablesMap().containsKey(cp);
  }

  // True iff cp is an override-class bidi control (LRE, RLE, LRO, RLO, PDF).
  private static boolean isConfusableBidiOverride(int cp) {
    return cp >= 0x202A && cp <= 0x202E;
  }

  // True iff cp is an isolate-class bidi control (LRI, RLI, FSI, PDI).
  private static boolean isConfusableBidiIsolate(int cp) {
    return cp >= 0x2066 && cp <= 0x2069;
  }

  private static int firstPositionWhere(List<Integer> input, IntPredicate predicate) {
    for (int i = 0; i < input.size(); i++) {
      if (predicate.test(input.get(i))) return i;
    }
    return -1;
  }

  private static boolean isBidiFormatControl(int cp) {
    return (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);
  }

  // Longest consecutive run of strong-RTL codepoints: {length, start};
  // {0, 0} when there are none.
  private static int[] longestRtlRun(List<Integer> input) {
    int longest = 0;
    int longestStart = 0;
    int current = 0;
    int currentStart = 0;
    for (int index = 0; index < input.size(); index++) {
      if (isStrongRtl(input.get(index))) {
        int newStart = current == 0 ? index : currentStart;
        current++;
        currentStart = newStart;
        if (current > longest) {
          longest = current;
          longestStart = newStart;
        }
      } else {
        current = 0;
      }
    }
    return new int[] {longest, longestStart};
  }

  private static String homoglyphTargetMatch(List<Integer> input) {
    List<Integer> inputLetters = letterSkeleton(input);
    for (String target : knownTargets()) {
      List<Integer> targetCps = codepointsFromString(target);
      if (!targetCps.equals(input) && letterSkeleton(targetCps).equals(inputLetters)) return target;
    }
    return null;
  }

  private static List<Integer> letterSkeleton(List<Integer> input) {
    List<Integer> out = new ArrayList<>();
    for (int cp : iteratedSkeleton(input)) {
      if (!isCombiningMark(cp) && !isDefaultIgnorableCodepoint(cp) && !isWhiteSpaceCodepoint(cp)) out.add(cp);
    }
    return out;
  }

  private static List<Integer> iteratedSkeleton(List<Integer> input) {
    List<Integer> current = new ArrayList<>(input);
    for (int i = 0; i < 8; i++) {
      List<Integer> next = skeleton(current);
      if (next.equals(current)) return current;
      current = next;
    }
    return current;
  }

  private static List<Integer> skeleton(List<Integer> input) {
    List<Integer> step1 = toNfdCodepoints(input);
    List<Integer> step2 = caseFoldCodepoints(step1);
    List<Integer> step3 = substituteConfusables(step2);
    List<Integer> step4 = caseFoldCodepoints(step3);
    return toNfdCodepoints(step4);
  }

  private static List<Integer> substituteConfusables(List<Integer> input) {
    Map<Integer, List<Integer>> table = confusablesMap();
    List<Integer> out = new ArrayList<>();
    for (int cp : input) out.addAll(table.getOrDefault(cp, List.of(cp)));
    return out;
  }

  private static List<Integer> caseFoldCodepoints(List<Integer> input) {
    Map<Integer, List<Integer>> table = caseFoldingMap();
    List<Integer> out = new ArrayList<>();
    for (int cp : input) out.addAll(table.getOrDefault(cp, List.of(cp)));
    return out;
  }

  private static List<Integer> toNfdCodepoints(List<Integer> input) {
    StringBuilder text = new StringBuilder();
    for (int cp : input) text.appendCodePoint(cp);
    return codepointsFromString(Normalizer.normalize(text, Normalizer.Form.NFD));
  }

  private static synchronized Map<Integer, List<Integer>> confusablesMap() {
    if (confusablesMap == null) confusablesMap = parseConfusables(readResource("confusables.txt"));
    return confusablesMap;
  }

  private static synchronized Map<Integer, List<Integer>> caseFoldingMap() {
    if (caseFoldingMap == null) caseFoldingMap = parseCaseFolding(readResource("CaseFolding.txt"));
    return caseFoldingMap;
  }

  private static synchronized BidiTable bidiTable() {
    if (bidiTable == null) bidiTable = parseDerivedBidi(readResource("DerivedBidiClass.txt"));
    return bidiTable;
  }

  // Mirrors Unicode.Generated.DerivedBidiClass.lookup. Explicit ranges come
  // from DATA lines `LO..HI ; SHORT # ...` or `CP ; SHORT # ...`; @missing
  // default ranges come from COMMENT lines `# @missing: LO..HI; Long_Name`.
  // Only the strong distinction (R, AL, L) is retained — every other
  // Bidi_Class collapses to OTHER.
  private static BidiTable parseDerivedBidi(String raw) {
    List<BidiRange> explicit = new ArrayList<>();
    List<BidiRange> defaults = new ArrayList<>();
    for (String line : raw.split("\n", -1)) {
      String missingMarker = "# @missing:";
      int missingIdx = line.indexOf(missingMarker);
      if (missingIdx >= 0) {
        // `# @missing: LO..HI; Long_Class_Name`
        String rest = line.substring(missingIdx + missingMarker.length());
        int semi = rest.indexOf(';');
        if (semi >= 0) {
          int[] range = parseRangeField(rest.substring(0, semi));
          if (range != null) {
            defaults.add(new BidiRange(range[0], range[1], strongOfLong(rest.substring(semi + 1).trim())));
          }
        }
        continue;
      }
      int hash = line.indexOf('#');
      String body = (hash >= 0 ? line.substring(0, hash) : line).trim();
      if (body.isEmpty()) continue;
      // `LO..HI ; SHORT` or `CP ; SHORT`
      int semi = body.indexOf(';');
      if (semi < 0) continue;
      int[] range = parseRangeField(body.substring(0, semi));
      if (range != null) {
        explicit.add(new BidiRange(range[0], range[1], strongOfShort(body.substring(semi + 1).trim())));
      }
    }
    explicit.sort(java.util.Comparator.comparingInt(BidiRange::lo));
    return new BidiTable(List.copyOf(explicit), List.copyOf(defaults));
  }

  private static BidiStrong strongOfShort(String token) {
    return switch (token) {
      case "R" -> BidiStrong.R;
      case "AL" -> BidiStrong.AL;
      case "L" -> BidiStrong.L;
      default -> BidiStrong.OTHER;
    };
  }

  private static BidiStrong strongOfLong(String token) {
    return switch (token) {
      case "Right_To_Left" -> BidiStrong.R;
      case "Arabic_Letter" -> BidiStrong.AL;
      case "Left_To_Right" -> BidiStrong.L;
      default -> BidiStrong.OTHER;
    };
  }

  // `LO..HI` or a single `CP`, both hex; null on malformed input.
  private static int[] parseRangeField(String s) {
    String t = s.trim();
    int dots = t.indexOf("..");
    try {
      if (dots >= 0) {
        int a = Integer.parseInt(t.substring(0, dots).trim(), 16);
        int b = Integer.parseInt(t.substring(dots + 2).trim(), 16);
        return new int[] {a, b};
      }
      int a = Integer.parseInt(t, 16);
      return new int[] {a, a};
    } catch (NumberFormatException ex) {
      return null;
    }
  }

  // Full Bidi_Class lookup (strong distinction only): binary-search the
  // sorted explicit ranges first, then the last matching @missing default,
  // then L. Mirrors Unicode.Generated.DerivedBidiClass.lookup.
  private static BidiStrong bidiStrong(int cp) {
    List<BidiRange> explicit = bidiTable().explicit();
    int lo = 0;
    int hi = explicit.size();
    while (lo < hi) {
      int mid = lo + (hi - lo) / 2;
      BidiRange row = explicit.get(mid);
      if (cp < row.lo()) {
        hi = mid;
      } else if (cp > row.hi()) {
        lo = mid + 1;
      } else {
        return row.cls();
      }
    }
    BidiStrong result = BidiStrong.L;
    for (BidiRange row : bidiTable().defaults()) {
      if (row.lo() <= cp && cp <= row.hi()) result = row.cls();
    }
    return result;
  }

  private static boolean isStrongRtl(int cp) {
    BidiStrong bidi = bidiStrong(cp);
    return bidi == BidiStrong.R || bidi == BidiStrong.AL;
  }

  private static boolean isStrongLtr(int cp) {
    return bidiStrong(cp) == BidiStrong.L;
  }

  private static synchronized List<String> knownTargets() {
    if (knownTargets == null) knownTargets = parseKnownTargets(readResource("KnownAttackTargets.txt"));
    return knownTargets;
  }

  private static synchronized Set<Long> legalVariationPairs() {
    if (legalVariationPairs == null) {
      legalVariationPairs = new HashSet<>();
      parseLegalVariationPairs(readResource("StandardizedVariants.txt"), legalVariationPairs);
      parseLegalVariationPairs(readResource("emoji-variation-sequences.txt"), legalVariationPairs);
    }
    return legalVariationPairs;
  }

  private static Map<Integer, List<Integer>> parseConfusables(String raw) {
    Map<Integer, List<Integer>> out = new HashMap<>();
    for (String rawLine : raw.split("\n")) {
      String body = rawLine.split("#", 2)[0].trim();
      if (body.isEmpty()) continue;
      String[] fields = body.split(";");
      if (fields.length < 2) continue;
      Integer src = parseHex(fields[0]);
      List<Integer> target = parseCodepointField(fields[1]);
      if (src != null && !target.isEmpty()) out.put(src, target);
    }
    return out;
  }

  private static Map<Integer, List<Integer>> parseCaseFolding(String raw) {
    Map<Integer, List<Integer>> out = new HashMap<>();
    for (String rawLine : raw.split("\n")) {
      String body = rawLine.split("#", 2)[0].trim();
      if (body.isEmpty()) continue;
      String[] fields = body.split(";");
      if (fields.length < 3) continue;
      String status = fields[1].trim();
      if (!status.equals("C") && !status.equals("F")) continue;
      Integer cp = parseHex(fields[0]);
      List<Integer> mapping = parseCodepointField(fields[2]);
      if (cp != null && !mapping.isEmpty()) out.put(cp, mapping);
    }
    return out;
  }

  private static List<String> parseKnownTargets(String raw) {
    List<String> out = new ArrayList<>();
    for (String line : raw.split("\n")) {
      String trimmed = line.trim();
      if (!trimmed.isEmpty() && !trimmed.startsWith("#")) out.add(trimmed);
    }
    return out;
  }

  private static void parseLegalVariationPairs(String raw, Set<Long> out) {
    for (String rawLine : raw.split("\n")) {
      String body = rawLine.split("#", 2)[0];
      String pairPart = body.split(";", 2)[0].trim();
      if (pairPart.isEmpty()) continue;
      String[] fields = pairPart.split("\\s+");
      if (fields.length != 2) continue;
      Integer base = parseHex(fields[0]);
      Integer vs = parseHex(fields[1]);
      if (base != null && vs != null) out.add(variationPairKey(base, vs));
    }
  }

  private static long variationPairKey(int base, int vs) {
    return ((long) base << 32) ^ (vs & 0xffffffffL);
  }

  private static List<Integer> parseCodepointField(String field) {
    List<Integer> out = new ArrayList<>();
    for (String token : field.trim().split("\\s+")) {
      Integer cp = parseHex(token);
      if (cp != null) out.add(cp);
    }
    return out;
  }

  private static Integer parseHex(String field) {
    try {
      return Integer.parseUnsignedInt(field.trim(), 16);
    } catch (NumberFormatException e) {
      return null;
    }
  }

  // Pinned SHA-256 digests of the vendored UCD-derived tables, embedded as code
  // constants so the code — not the co-located, swappable SHA256SUMS — is the
  // trust anchor. readResource hashes each table's raw bytes at load and refuses
  // to serve (throws) on any mismatch or unpinned table, so a rolled-back,
  // corrupted, or tampered resource on a deployed node fails closed instead of
  // silently mis-classifying. Keep in sync with the port resources' SHA256SUMS
  // and the canonical data/SHA256SUMS.
  private static final Map<String, String> PINNED_TABLE_DIGESTS = Map.of(
      "CaseFolding.txt", "ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183",
      "confusables.txt", "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a",
      "KnownAttackTargets.txt", "47acf87f48e23c2e3ddfb5aed877965fbe29142e61f6f85c4ee7db90c0684947",
      "StandardizedVariants.txt", "f55100b2fb11d3d75a37b8c1ab752192dbd1c4b12328c5ec6b38e3807c0ca597",
      "emoji-variation-sequences.txt", "bb3d09ef03f206012c7532dd52dc0a21c9efddba0135ea4cf0d9201b8b9bba7e",
      "DerivedBidiClass.txt", "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4");

  private static String sha256Hex(byte[] bytes) {
    try {
      byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes);
      StringBuilder sb = new StringBuilder(digest.length * 2);
      for (byte b : digest) sb.append(String.format("%02x", b));
      return sb.toString();
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private static String readResource(String name) {
    String expected = PINNED_TABLE_DIGESTS.get(name);
    if (expected == null) {
      throw new IllegalStateException("refusing to load unpinned data table: " + name + " (fail closed)");
    }
    String path = "/com/unicodesecurity/data/" + name;
    try (InputStream in = Security.class.getResourceAsStream(path)) {
      if (in == null) throw new IllegalStateException("missing resource: " + path);
      byte[] bytes = in.readAllBytes();
      String actual = sha256Hex(bytes);
      if (!actual.equals(expected)) {
        throw new IllegalStateException(
            "data table " + name + " failed integrity check (expected " + expected
                + ", got " + actual + "); refusing to load (fail closed)");
      }
      return new String(bytes, StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("cannot read resource: " + path, e);
    }
  }

  private static List<Integer> fullSpanPositions(List<Integer> input) {
    List<Integer> out = new ArrayList<>();
    for (int i = 0; i < input.size(); i++) out.add(i);
    return out;
  }

  private static boolean isMathAlphanumeric(int cp) {
    return cp >= 0x1D400 && cp <= 0x1D7FF;
  }

  private static boolean isFullwidthHalfwidth(int cp) {
    return cp >= 0xFF01 && cp <= 0xFFEF;
  }

  private static boolean isNoncharacter(int cp) {
    if (cp >= 0xFDD0 && cp <= 0xFDEF) return true;
    if (cp > 0x10FFFF) return false;
    int low16 = cp & 0xFFFF;
    return low16 == 0xFFFE || low16 == 0xFFFF;
  }

  private static boolean isC0Control(int cp) {
    return (cp <= 0x1F && cp != 0x09 && cp != 0x0A && cp != 0x0D) || cp == 0x7F;
  }

  private static boolean isC1Control(int cp) {
    return cp >= 0x80 && cp <= 0x9F;
  }

  private static boolean isCombiningMark(int cp) {
    return (cp >= 0x0300 && cp <= 0x036F) || (cp >= 0x1AB0 && cp <= 0x1AFF) ||
        (cp >= 0x1DC0 && cp <= 0x1DFF) || (cp >= 0x20D0 && cp <= 0x20FF) ||
        (cp >= 0xFE20 && cp <= 0xFE2F);
  }

  private static boolean hasDecompositionSwap(List<Integer> input) {
    for (int i = 1; i < input.size(); i++) {
      int previous = input.get(i - 1);
      int current = input.get(i);
      if (isCombiningMark(current) && !isCombiningMark(previous)) return true;
      if (isCombiningMark(previous) && isCombiningMark(current) && previous > current) return true;
      if (composeHangulPair(previous, current)) return true;
    }
    return false;
  }

  private static boolean composeHangulPair(int first, int second) {
    int sBase = 0xAC00, lBase = 0x1100, vBase = 0x1161, tBase = 0x11A7;
    int lCount = 19, vCount = 21, tCount = 28, nCount = vCount * tCount, sCount = lCount * nCount;
    boolean isL = first >= lBase && first < lBase + lCount;
    boolean isV = second >= vBase && second < vBase + vCount;
    if (isL && isV) return true;
    boolean isLV = first >= sBase && first < sBase + sCount && (first - sBase) % tCount == 0;
    boolean isT = second > tBase && second < tBase + tCount;
    return isLV && isT;
  }

  private static boolean hasCrossScriptMix(List<Integer> input) {
    Set<String> seen = new HashSet<>();
    for (int cp : input) {
      String script = scriptClass(cp);
      if (script != null) seen.add(script);
    }
    return seen.size() >= 2;
  }

  // The specific script-collision sub-threat, matching the Lean source of truth:
  // Latin/Cyrillic and Latin/Greek are named explicitly (Cyrillic before Greek);
  // every other multi-script mix is ScriptMixOther.
  private static String mixedScriptSubThreat(List<Integer> input) {
    Set<String> seen = new HashSet<>();
    for (int cp : input) {
      String script = scriptClass(cp);
      if (script != null) seen.add(script);
    }
    if (seen.contains("Latn") && seen.contains("Cyrl")) return "LatinCyrillic";
    if (seen.contains("Latn") && seen.contains("Grek")) return "LatinGreek";
    return "ScriptMixOther";
  }

  private static String scriptClass(int cp) {
    if ((cp >= 0x0041 && cp <= 0x005A) || (cp >= 0x0061 && cp <= 0x007A) || (cp >= 0x00C0 && cp <= 0x024F)) return "Latn";
    if ((cp >= 0x0370 && cp <= 0x03FF) || (cp >= 0x1F00 && cp <= 0x1FFF)) return "Grek";
    if (cp >= 0x0400 && cp <= 0x052F) return "Cyrl";
    return null;
  }

  private static boolean isDefaultIgnorableCodepoint(int cp) {
    return cp == 0x00AD || cp == 0x034F || cp == 0x061C ||
        (cp >= 0x115F && cp <= 0x1160) || (cp >= 0x17B4 && cp <= 0x17B5) ||
        (cp >= 0x180B && cp <= 0x180F) || (cp >= 0x200B && cp <= 0x200F) ||
        (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2060 && cp <= 0x206F) ||
        (cp >= 0xFE00 && cp <= 0xFE0F) || cp == 0xFEFF ||
        (cp >= 0xFFF0 && cp <= 0xFFF8) || (cp >= 0xE0000 && cp <= 0xE0FFF);
  }

  private static boolean isWhiteSpaceCodepoint(int cp) {
    return cp == 0x0009 || cp == 0x000A || cp == 0x000B || cp == 0x000C ||
        cp == 0x000D || cp == 0x0020 || cp == 0x0085 || cp == 0x00A0 ||
        cp == 0x1680 || (cp >= 0x2000 && cp <= 0x200A) || cp == 0x2028 ||
        cp == 0x2029 || cp == 0x202F || cp == 0x205F || cp == 0x3000;
  }

  private static Verdict scanUtf16(String profile, String mode, byte[] input, ByteOrder order) {
    DecodeResult result = decodeUtf16ToCodepoints(input, order);
    if (result.failure() != null) return malformedDecodeVerdict(profile, mode, Family.MALFORMED_UTF16, result.failure().subThreat(), result.failure().offset());
    return scan(profile, mode, result.codepoints());
  }

  private static DecodeResult decodeUtf16ToCodepoints(byte[] input, ByteOrder order) {
    List<Integer> out = new ArrayList<>();
    int offset = 0;
    while (offset < input.length) {
      if (offset + 2 > input.length) return new DecodeResult(List.of(), new DecodeFailure("TruncatedCodeUnit", input.length));
      int unitOffset = offset;
      int unit = readUint16(input, offset, order);
      offset += 2;
      if (unit >= 0xD800 && unit <= 0xDBFF) {
        if (offset + 2 > input.length) return new DecodeResult(List.of(), new DecodeFailure("TruncatedSurrogatePair", input.length));
        int low = readUint16(input, offset, order);
        if (low < 0xDC00 || low > 0xDFFF) return new DecodeResult(List.of(), new DecodeFailure("InvalidSurrogatePair", offset));
        out.add(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00));
        offset += 2;
      } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
        return new DecodeResult(List.of(), new DecodeFailure("LoneSurrogate", unitOffset));
      } else {
        out.add(unit);
      }
    }
    return new DecodeResult(out, null);
  }

  private static Verdict scanUtf32(String profile, String mode, byte[] input, ByteOrder order) {
    DecodeResult result = decodeUtf32ToCodepoints(input, order);
    if (result.failure() != null) return malformedDecodeVerdict(profile, mode, Family.MALFORMED_UTF32, result.failure().subThreat(), result.failure().offset());
    return scan(profile, mode, result.codepoints());
  }

  private static DecodeResult decodeUtf32ToCodepoints(byte[] input, ByteOrder order) {
    if (input.length % 4 != 0) return new DecodeResult(List.of(), new DecodeFailure("TruncatedCodeUnit", input.length));
    List<Integer> out = new ArrayList<>();
    for (int offset = 0; offset < input.length; offset += 4) {
      int cp = readUint32(input, offset, order);
      if (cp >= 0xD800 && cp <= 0xDFFF) return new DecodeResult(List.of(), new DecodeFailure("SurrogateCodepoint", offset));
      if (Integer.compareUnsigned(cp, 0x10FFFF) > 0) return new DecodeResult(List.of(), new DecodeFailure("CodepointBeyondMax", offset));
      out.add(cp);
    }
    return new DecodeResult(out, null);
  }

  private static DecodeFailure firstInvalidUtf8(byte[] input) {
    Utf8State state = new Utf8State(false, 0, 0, 0);
    int seqStart = 0;
    for (int index = 0; index < input.length; index++) {
      if (!state.inSequence()) seqStart = index;
      Utf8Step step = utf8DecodeStep(state, input[index] & 0xFF);
      if (step.rejected()) return new DecodeFailure(step.kind(), step.kind().equals("OverlongEncoding") ? seqStart : index);
      state = step.state();
    }
    if (state.inSequence()) return new DecodeFailure("TruncatedSequence", input.length);
    return null;
  }

  private static List<Integer> decodeUtf8ToCodepoints(byte[] input) {
    List<Integer> out = new ArrayList<>();
    Utf8State state = new Utf8State(false, 0, 0, 0);
    for (byte raw : input) {
      int b = raw & 0xFF;
      Utf8Step step = utf8DecodeStep(state, b);
      if (step.rejected()) return out;
      if (!step.state().inSequence() && (state.inSequence() || b < 0x80)) out.add(step.emitted());
      state = step.state();
    }
    return out;
  }

  private static Utf8Step utf8DecodeStep(Utf8State state, int n) {
    if (!state.inSequence()) {
      if (n < 0x80) return new Utf8Step(new Utf8State(false, 0, 0, 0), n, "", false);
      if (n < 0xC2) return new Utf8Step(state, 0, "InvalidStartByte", true);
      if (n < 0xE0) return new Utf8Step(new Utf8State(true, 1, n & 0x1F, 0x80), 0, "", false);
      if (n < 0xF0) return new Utf8Step(new Utf8State(true, 2, n & 0x0F, 0x800), 0, "", false);
      if (n < 0xF5) return new Utf8Step(new Utf8State(true, 3, n & 0x07, 0x10000), 0, "", false);
      return new Utf8Step(state, 0, "InvalidStartByte", true);
    }
    if (n < 0x80 || n >= 0xC0) return new Utf8Step(state, 0, "InvalidContinuationByte", true);
    int next = (state.accum() << 6) | (n & 0x3F);
    if (state.remaining() == 1) {
      if (next < state.minCp()) return new Utf8Step(state, 0, "OverlongEncoding", true);
      if (next >= 0xD800 && next <= 0xDFFF) return new Utf8Step(state, 0, "SurrogateCodepoint", true);
      if (next > 0x10FFFF) return new Utf8Step(state, 0, "CodepointBeyondMax", true);
      return new Utf8Step(new Utf8State(false, 0, 0, 0), next, "", false);
    }
    return new Utf8Step(new Utf8State(true, state.remaining() - 1, next, state.minCp()), 0, "", false);
  }

  private static int readUint16(byte[] input, int offset, ByteOrder order) {
    if (order == ByteOrder.BIG) return ((input[offset] & 0xFF) << 8) | (input[offset + 1] & 0xFF);
    return (input[offset] & 0xFF) | ((input[offset + 1] & 0xFF) << 8);
  }

  private static int readUint32(byte[] input, int offset, ByteOrder order) {
    if (order == ByteOrder.BIG) {
      return ((input[offset] & 0xFF) << 24) | ((input[offset + 1] & 0xFF) << 16) | ((input[offset + 2] & 0xFF) << 8) | (input[offset + 3] & 0xFF);
    }
    return (input[offset] & 0xFF) | ((input[offset + 1] & 0xFF) << 8) | ((input[offset + 2] & 0xFF) << 16) | ((input[offset + 3] & 0xFF) << 24);
  }

  private static List<Integer> codepointsFromString(String value) {
    return value.codePoints().boxed().toList();
  }

  private static int ensureCodepoint(int value) {
    if (value < 0 || value > 0x10FFFF) throw new IllegalArgumentException("invalid codepoint: " + value);
    return value;
  }

  private static void jsonField(StringBuilder out, String name, String value) {
    out.append('"').append(name).append("\":");
    appendJsonString(out, value);
  }

  private static void appendFinding(StringBuilder out, Finding finding) {
    out.append('{');
    jsonField(out, "code", finding.code());
    out.append(',');
    jsonField(out, "family", finding.family());
    out.append(',');
    out.append("\"severity\":").append(finding.severity()).append(',');
    out.append("\"positions\":");
    appendIntArray(out, finding.positions());
    out.append(',');
    jsonField(out, "sub_threat", finding.subThreat());
    out.append(',');
    jsonField(out, "detail", finding.detail());
    out.append('}');
  }

  private static void appendIntArray(StringBuilder out, List<Integer> values) {
    out.append('[');
    for (int i = 0; i < values.size(); i++) {
      if (i > 0) out.append(',');
      out.append(values.get(i));
    }
    out.append(']');
  }

  private static void appendJsonString(StringBuilder out, String value) {
    out.append('"');
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
    out.append('"');
  }

  @FunctionalInterface
  private interface IntPredicate {
    boolean test(int value);
  }
}
