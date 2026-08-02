package com.unicodesecurity;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * hash-input-stability — detection of inputs that are not in canonical
 * hash-input form. Per UTS #39 &sect;6.1 + RFC 4880 / 9580 + RFC 8785, an input
 * hashed by a signer must be byte-identical to the input hashed by the verifier;
 * if the two ends pick different canonical forms (NFC vs NFD, trim policy,
 * line-ending convention) the resulting hashes diverge silently while both sides
 * believe they signed the same content.
 *
 * <p>Direct port of {@code Unicode/Security/Crypto/HashInputStability.lean},
 * transliterated byte-faithfully from the verified Rust reference
 * {@code ports/rust/src/security/crypto/hash_input_stability.rs}. The canonical
 * (hash-stable) form is {@code trimTrailing(toNfc(input))}, where
 * {@code trimTrailing} strips only ASCII whitespace {U+0020, U+0009, U+000A,
 * U+000D}; Unicode whitespace (U+00A0, U+2000..U+200A, U+3000) is content and is
 * not stripped. NFC is the port's {@link Security#toNfc}, never a host
 * normalizer.
 *
 * <p>Six probes run in strict priority order (first hit wins):
 * <ol>
 *   <li>{@code encodingMismatch}         (context: {@code declaredEncoding})</li>
 *   <li>{@code webhookSignatureDrift}    (context: {@code serverBytes})</li>
 *   <li>{@code auditLogReinterpretation} (context: {@code asWritten})</li>
 *   <li>{@code signedMessageRule}        (context: {@code rfcRule})</li>
 *   <li>{@code trailingWhitespace}       (bare input)</li>
 *   <li>{@code normalizationDrift}       (bare input)</li>
 * </ol>
 * then clear. Context-specific probes fire first because they carry more precise
 * threat information than the generic probes. {@link #detect} is the convenience
 * wrapper {@code detectWithContext(Context.empty(), input)} that leaves the four
 * context-bearing probes silent.
 */
public final class HashInputStability {
  private HashInputStability() {}

  /** UTS #39 family key; the reason-code layer for this family is {@code K}. */
  public static final String FAMILY = "hash-input-stability";

  // ───────────────────────────────────────────────────────────────────────
  // §1 Types
  // ───────────────────────────────────────────────────────────────────────

  /**
   * RFC canonicalisation profiles that the {@code signedMessageRule} probe
   * checks against. Each variant names a specific canonicalisation rule from a
   * published RFC; callers pass one as {@link Context#rfcRule} to opt the probe
   * in.
   */
  public enum RfcRule {
    /** RFC 4880 &sect;5.2.4 — detached signatures normalise trailing whitespace. */
    PGP4880_TRAILING_WHITESPACE("pgp4880TrailingWhitespace"),
    /** RFC 9580 (current OpenPGP) — line-endings normalise to CRLF before signing. */
    PGP9580_LINE_ENDING("pgp9580LineEnding"),
    /** RFC 8785 &sect;3.2.5 — JCS requires strings to be in NFC before serialisation. */
    RFC8785_NFC_REQUIREMENT("rfc8785NfcRequirement"),
    /** RFC 8259 &sect;7 — JSON strings must escape control characters (U+0000..U+001F). */
    RFC8259_CONTROL_CHAR("rfc8259ControlChar"),
    /** RFC 7515 &sect;2 — JWS Base64URL; any char outside {@code [A-Za-z0-9_-]} violates. */
    RFC7515_JWS_BASE64URL("rfc7515JwsBase64Url"),
    /** RFC 6376 &sect;3.4.4 — DKIM relaxed body canonicalization collapses whitespace runs. */
    RFC6376_DKIM_RELAXED("rfc6376DkimRelaxed"),
    /** RFC 5751 &sect;3.1.1 — S/MIME canonical text; a bare LF or bare CR violates. */
    RFC5751_SMIME_LINE_ENDING("rfc5751SmimeLineEnding");

    private final String tag;

    RfcRule(String tag) {
      this.tag = tag;
    }

    /**
     * Fixture-string identifier for an {@code RfcRule} — used by the conformance
     * harness's attribution parser to round-trip rule selections.
     */
    public String tag() {
      return tag;
    }

    /** Inverse of {@link #tag}. Returns empty for unrecognised strings. */
    public static Optional<RfcRule> fromTag(String tag) {
      for (RfcRule rule : values()) {
        if (rule.tag.equals(tag)) {
          return Optional.of(rule);
        }
      }
      return Optional.empty();
    }
  }

  /**
   * Sub-threats this detector can fire. Two probes fire from the raw input alone
   * ({@code TrailingWhitespace}, {@code NormalizationDrift}); the other four
   * require the corresponding {@link Context} field to be set.
   */
  public sealed interface SubThreat
      permits NormalizationDrift, TrailingWhitespace, EncodingMismatch,
              SignedMessageRule, AuditLogReinterpretation, WebhookSignatureDrift {
    /** Human-facing classification tag for this sub-threat. */
    String tag();
  }

  /** Input diverges from its NFC form at {@code firstDivergentPos}. */
  public record NormalizationDrift(int firstDivergentPos) implements SubThreat {
    @Override
    public String tag() {
      return "NormalizationDrift";
    }
  }

  /** Input has {@code count} trailing ASCII-whitespace codepoints. */
  public record TrailingWhitespace(int count) implements SubThreat {
    @Override
    public String tag() {
      return "TrailingWhitespace";
    }
  }

  /** Declared encoding disagrees with the codepoint array (or holds an invalid scalar). */
  public record EncodingMismatch(String declaredEnc, String detectedEnc) implements SubThreat {
    @Override
    public String tag() {
      return "EncodingMismatch";
    }
  }

  /** Input violates the named RFC's canonicalisation rule at {@code firstPos}. */
  public record SignedMessageRule(String rfcRule, int firstPos) implements SubThreat {
    @Override
    public String tag() {
      return "SignedMessageRule";
    }
  }

  /** The re-read input differs from {@link Context#asWritten} at {@code firstDivergentPos}. */
  public record AuditLogReinterpretation(int firstDivergentPos) implements SubThreat {
    @Override
    public String tag() {
      return "AuditLogReinterpretation";
    }
  }

  /** The client input differs from {@link Context#serverBytes} at {@code firstPos}. */
  public record WebhookSignatureDrift(int firstPos) implements SubThreat {
    @Override
    public String tag() {
      return "WebhookSignatureDrift";
    }
  }

  /**
   * Context passed to {@link #detectWithContext} to enable the four
   * context-bearing probes. Each field is absent by default — the empty context
   * is the identity case: {@code detectWithContext(Context.empty(), input)}
   * equals {@code detect(input)}.
   */
  public static final class Context {
    private final String declaredEncoding;
    private final RfcRule rfcRule;
    private final List<Integer> asWritten;
    private final List<Integer> serverBytes;

    private Context(String declaredEncoding, RfcRule rfcRule,
                    List<Integer> asWritten, List<Integer> serverBytes) {
      this.declaredEncoding = declaredEncoding;
      this.rfcRule = rfcRule;
      this.asWritten = asWritten == null ? null : List.copyOf(asWritten);
      this.serverBytes = serverBytes == null ? null : List.copyOf(serverBytes);
    }

    /** The empty context — every field absent. */
    public static Context empty() {
      return new Context(null, null, null, null);
    }

    /** The encoding label the caller claims their input is in. */
    public Context withDeclaredEncoding(String label) {
      return new Context(label, rfcRule, asWritten, serverBytes);
    }

    /** The RFC canonicalisation rule the caller is operating under. */
    public Context withRfcRule(RfcRule rule) {
      return new Context(declaredEncoding, rule, asWritten, serverBytes);
    }

    /** The original "as-written" form of an audit-log entry whose re-read is {@code input}. */
    public Context withAsWritten(List<Integer> written) {
      return new Context(declaredEncoding, rfcRule, written, serverBytes);
    }

    /** The server-side recomputed bytes for a webhook signature. */
    public Context withServerBytes(List<Integer> server) {
      return new Context(declaredEncoding, rfcRule, asWritten, server);
    }

    public Optional<String> declaredEncoding() {
      return Optional.ofNullable(declaredEncoding);
    }

    public Optional<RfcRule> rfcRule() {
      return Optional.ofNullable(rfcRule);
    }

    public Optional<List<Integer>> asWritten() {
      return Optional.ofNullable(asWritten);
    }

    public Optional<List<Integer>> serverBytes() {
      return Optional.ofNullable(serverBytes);
    }
  }

  /** Top-level classification. */
  public sealed interface Classification permits Clear, Hazard {
    /** True iff the input is clear. */
    boolean isClear();

    /** Human-facing tag for a hazard, or {@code null} when clear. */
    String tag();

    /** Implicated positions (empty when clear). */
    List<Integer> positions();
  }

  /** The input is already hash-stable under every enabled probe. */
  public record Clear() implements Classification {
    @Override
    public boolean isClear() {
      return true;
    }

    @Override
    public String tag() {
      return null;
    }

    @Override
    public List<Integer> positions() {
      return List.of();
    }
  }

  /** A hazard was found: the sub-threat and its implicated positions. */
  public record Hazard(SubThreat sub, List<Integer> positions) implements Classification {
    @Override
    public boolean isClear() {
      return false;
    }

    @Override
    public String tag() {
      return sub.tag();
    }
  }

  /**
   * Verdict — the structured output of {@link #detect}. {@code stableSize} is the
   * codepoint count of the hash-stable canonical form; downstream callers compare
   * it against {@code input.size()} to size the byte-drift their hash sees.
   */
  public record Verdict(List<Integer> input, Classification classify,
                        List<Integer> stableForm, int stableSize) {}

  /**
   * The fixture reason code for a classification, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.K.hash-input-stability.<tag>}
   * scheme keyed by the sub-threat tag.
   */
  public static String reasonCode(Classification classify) {
    String tag = classify.tag();
    return tag == null ? null : "unicode.security.K." + FAMILY + "." + tag;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §3 Canonicalisation pipeline
  // ───────────────────────────────────────────────────────────────────────

  /**
   * True iff {@code cp} is an ASCII whitespace codepoint that line-oriented
   * hash-input protocols treat as framing rather than content: U+0020 SPACE,
   * U+0009 TAB, U+000A LF, U+000D CR.
   */
  private static boolean isAsciiWhitespace(int cp) {
    return cp == 0x0020 || cp == 0x0009 || cp == 0x000A || cp == 0x000D;
  }

  /** Count of trailing ASCII whitespace codepoints in {@code input}. */
  private static int countTrailingWhitespace(List<Integer> input) {
    int count = 0;
    for (int i = input.size() - 1; i >= 0; i--) {
      if (isAsciiWhitespace(input.get(i))) {
        count++;
      } else {
        break;
      }
    }
    return count;
  }

  /** Strip trailing ASCII whitespace. */
  private static List<Integer> trimTrailing(List<Integer> input) {
    int keep = input.size() - countTrailingWhitespace(input);
    return new ArrayList<>(input.subList(0, keep));
  }

  /** The hash-stable form of an input: NFC then trim, in spec order. */
  public static List<Integer> hashStable(List<Integer> input) {
    return trimTrailing(Security.toNfc(input));
  }

  // ───────────────────────────────────────────────────────────────────────
  // §5 Priority position-finder
  // ───────────────────────────────────────────────────────────────────────

  /**
   * First position at which {@code a} and {@code b} diverge, or the length of the
   * shared prefix when one strictly extends the other. {@code null} when
   * identical.
   */
  private static Integer firstArrayDivergence(List<Integer> a, List<Integer> b) {
    int common = Math.min(a.size(), b.size());
    for (int i = 0; i < common; i++) {
      if (!a.get(i).equals(b.get(i))) {
        return i;
      }
    }
    if (a.size() != b.size()) {
      return common;
    }
    return null;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §6 Context-bearing probes
  // ───────────────────────────────────────────────────────────────────────

  /** Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A). */
  private static int asciiLower(int cp) {
    if (cp >= 0x41 && cp <= 0x5A) {
      return cp + 0x20;
    }
    return cp;
  }

  /**
   * True iff {@code label} (after ASCII case-fold) names UTF-8: accepts "utf-8",
   * "UTF-8", "UTF8", "utf8". Non-ASCII characters pass through unchanged.
   */
  private static boolean isUtf8Label(String label) {
    StringBuilder normalised = new StringBuilder();
    label.codePoints().forEach(c -> normalised.appendCodePoint(asciiLower(c)));
    String result = normalised.toString();
    return result.equals("utf-8") || result.equals("utf8");
  }

  /**
   * True iff {@code cp} is a valid Unicode scalar value: in {@code [0, 0x10FFFF]}
   * and not a surrogate {@code [0xD800, 0xDFFF]}.
   */
  private static boolean isValidScalar(int cp) {
    return cp >= 0 && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);
  }

  /**
   * First position in {@code input} holding a codepoint that is not a valid
   * Unicode scalar, or {@code null} if every codepoint is valid.
   */
  private static Integer firstInvalidScalar(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      if (!isValidScalar(input.get(i))) {
        return i;
      }
    }
    return null;
  }

  /** A firing {@code encodingMismatch} probe: declared/detected label and position. */
  private record EncodingHit(String declared, String detected, int firstPos) {}

  /**
   * Probe: {@code encodingMismatch}. Validity is dispatched first — an invalid
   * scalar fires with {@code detectedEnc = "invalid"} regardless of the declared
   * label; otherwise a non-UTF-8 label fires with {@code detectedEnc = "utf-8"}
   * at position 0. Returns {@code null} when clean.
   */
  private static EncodingHit encodingMismatchProbe(String declared, List<Integer> input) {
    Integer pos = firstInvalidScalar(input);
    if (pos != null) {
      return new EncodingHit(declared, "invalid", pos);
    }
    if (isUtf8Label(declared)) {
      return null;
    }
    return new EncodingHit(declared, "utf-8", 0);
  }

  /**
   * Probe: {@code signedMessageRule} for {@code pgp4880TrailingWhitespace}. Same
   * condition as {@code trailingWhitespace}; returns the first position of the
   * trailing run.
   */
  private static Integer pgp4880Violation(List<Integer> input) {
    int trailing = countTrailingWhitespace(input);
    if (trailing > 0) {
      return input.size() - trailing;
    }
    return null;
  }

  /**
   * Probe: {@code signedMessageRule} for {@code pgp9580LineEnding}. First bare LF
   * (U+000A not preceded by CR) or bare CR (U+000D not followed by LF).
   */
  private static Integer pgp9580Violation(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      int cp = input.get(i);
      if (cp == 0x000A) {
        boolean precededByCr = i > 0 && input.get(i - 1) == 0x000D;
        if (!precededByCr) {
          return i;
        }
      } else if (cp == 0x000D) {
        boolean followedByLf = i + 1 < input.size() && input.get(i + 1) == 0x000A;
        if (!followedByLf) {
          return i;
        }
      }
    }
    return null;
  }

  /**
   * Probe: {@code signedMessageRule} for {@code rfc8785NfcRequirement}. Same
   * condition as {@code normalizationDrift}; returns the first NFC divergence
   * position.
   */
  private static Integer rfc8785Violation(List<Integer> input) {
    List<Integer> nfc = Security.toNfc(input);
    if (input.equals(nfc)) {
      return null;
    }
    return firstArrayDivergence(input, nfc);
  }

  /**
   * Probe: {@code signedMessageRule} for {@code rfc8259ControlChar}. First C0
   * control (U+0000..U+001F).
   */
  private static Integer rfc8259Violation(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      if (input.get(i) <= 0x1F) {
        return i;
      }
    }
    return null;
  }

  /** True iff {@code cp} is in the JWS Base64URL alphabet {@code [A-Za-z0-9_-]}. */
  private static boolean isBase64Url(int cp) {
    return (cp >= 0x41 && cp <= 0x5A)      // A-Z
        || (cp >= 0x61 && cp <= 0x7A)      // a-z
        || (cp >= 0x30 && cp <= 0x39)      // 0-9
        || cp == 0x2D                      // '-'
        || cp == 0x5F;                     // LOW LINE
  }

  /**
   * Probe: {@code signedMessageRule} for {@code rfc7515JwsBase64Url}. First
   * codepoint outside {@code [A-Za-z0-9_-]}.
   */
  private static Integer rfc7515Violation(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      if (!isBase64Url(input.get(i))) {
        return i;
      }
    }
    return null;
  }

  /** True iff {@code cp} is DKIM whitespace: U+0020 SPACE or U+0009 HTAB. */
  private static boolean isDkimWhitespace(int cp) {
    return cp == 0x20 || cp == 0x09;
  }

  /**
   * Probe: {@code signedMessageRule} for {@code rfc6376DkimRelaxed}. Position of
   * the second whitespace codepoint in the first internal whitespace run longer
   * than one.
   */
  private static Integer rfc6376Violation(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      if (isDkimWhitespace(input.get(i)) && i > 0 && isDkimWhitespace(input.get(i - 1))) {
        return i;
      }
    }
    return null;
  }

  /**
   * Probe: {@code signedMessageRule} for {@code rfc5751SmimeLineEnding}. Reuses
   * the PGP 9580 bare-line-ending rule.
   */
  private static Integer rfc5751Violation(List<Integer> input) {
    return pgp9580Violation(input);
  }

  /** Dispatch the RFC-rule probe. First violation position, or {@code null} if clean. */
  private static Integer rfcRuleViolation(RfcRule rule, List<Integer> input) {
    return switch (rule) {
      case PGP4880_TRAILING_WHITESPACE -> pgp4880Violation(input);
      case PGP9580_LINE_ENDING -> pgp9580Violation(input);
      case RFC8785_NFC_REQUIREMENT -> rfc8785Violation(input);
      case RFC8259_CONTROL_CHAR -> rfc8259Violation(input);
      case RFC7515_JWS_BASE64URL -> rfc7515Violation(input);
      case RFC6376_DKIM_RELAXED -> rfc6376Violation(input);
      case RFC5751_SMIME_LINE_ENDING -> rfc5751Violation(input);
    };
  }

  /** A firing {@code signedMessageRule} probe: the rule and its first position. */
  private record RfcHit(RfcRule rule, int firstPos) {}

  // ───────────────────────────────────────────────────────────────────────
  // §7 Top-level detection
  // ───────────────────────────────────────────────────────────────────────

  /**
   * The full detection function. Runs all six probes in priority order, with the
   * context-bearing probes ahead of the generic ones.
   */
  public static Verdict detectWithContext(Context ctx, List<Integer> input) {
    List<Integer> stable = hashStable(input);

    // Probe 1: encodingMismatch.
    EncodingHit encodingHit = null;
    if (ctx.declaredEncoding().isPresent()) {
      encodingHit = encodingMismatchProbe(ctx.declaredEncoding().get(), input);
    }

    // Probe 2: webhookSignatureDrift.
    Integer webhookHit = null;
    if (ctx.serverBytes().isPresent()) {
      webhookHit = firstArrayDivergence(input, ctx.serverBytes().get());
    }

    // Probe 3: auditLogReinterpretation.
    Integer auditHit = null;
    if (ctx.asWritten().isPresent()) {
      auditHit = firstArrayDivergence(ctx.asWritten().get(), input);
    }

    // Probe 4: signedMessageRule.
    RfcHit rfcHit = null;
    if (ctx.rfcRule().isPresent()) {
      RfcRule rule = ctx.rfcRule().get();
      Integer pos = rfcRuleViolation(rule, input);
      if (pos != null) {
        rfcHit = new RfcHit(rule, pos);
      }
    }

    // Probe 5: trailingWhitespace.
    int trailingCount = countTrailingWhitespace(input);

    // Probe 6: normalizationDrift.
    List<Integer> nfc = Security.toNfc(input);
    Integer nonNfcPos = input.equals(nfc) ? null : firstArrayDivergence(input, nfc);

    Classification classification = classify(
        encodingHit, webhookHit, auditHit, rfcHit, trailingCount, input.size(), nonNfcPos);

    return new Verdict(new ArrayList<>(input), classification, stable, stable.size());
  }

  /** The priority resolver: first hit wins, in the fixed spec order. */
  private static Classification classify(
      EncodingHit encodingHit,
      Integer webhookHit,
      Integer auditHit,
      RfcHit rfcHit,
      int trailingCount,
      int inputLen,
      Integer nonNfcPos) {
    if (encodingHit != null) {
      return new Hazard(
          new EncodingMismatch(encodingHit.declared(), encodingHit.detected()),
          List.of(encodingHit.firstPos()));
    }
    if (webhookHit != null) {
      return new Hazard(new WebhookSignatureDrift(webhookHit), List.of(webhookHit));
    }
    if (auditHit != null) {
      return new Hazard(new AuditLogReinterpretation(auditHit), List.of(auditHit));
    }
    if (rfcHit != null) {
      return new Hazard(
          new SignedMessageRule(rfcHit.rule().tag(), rfcHit.firstPos()),
          List.of(rfcHit.firstPos()));
    }
    if (trailingCount > 0) {
      int p = inputLen - trailingCount;
      return new Hazard(new TrailingWhitespace(trailingCount), List.of(p));
    }
    if (nonNfcPos != null) {
      return new Hazard(new NormalizationDrift(nonNfcPos), List.of(nonNfcPos));
    }
    return new Clear();
  }

  /**
   * Convenience wrapper over {@link #detectWithContext} with the empty context —
   * equivalent to running only the two bare-input probes
   * ({@code trailingWhitespace}, {@code normalizationDrift}).
   */
  public static Verdict detect(List<Integer> input) {
    return detectWithContext(Context.empty(), input);
  }
}
