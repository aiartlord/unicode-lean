package com.unicodesecurity;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * ai-watermark-detectability — character-level detector for inputs carrying
 * codepoint patterns consistent with a known AI watermark scheme. Answers the
 * question: does this input contain markers attributable to a watermarking
 * protocol?
 *
 * <p>Direct port of {@code Unicode/Security/Crypto/AiWatermarkDetectability.lean},
 * transliterated byte-faithfully from the verified Rust reference
 * {@code ports/rust/src/security/crypto/ai_watermark_detectability.rs}.
 *
 * <p>Threat model — provenance-attribution attacker. An input either (a) carries
 * an AI provider's watermark codepoints (a legitimate provenance marker) or
 * (b) carries injected markers that impersonate a provider's scheme to
 * discredit the content as AI-generated. Character-level detection alone cannot
 * distinguish (a) from (b); the detector reports the matched scheme and leaves
 * provider-specific authentication to downstream code.
 *
 * <p>Probe inventory (priority order, first match wins):
 * <ol>
 *   <li>{@code adversarial}              — NNBSP count &ge; 3 at arithmetic-progression positions.</li>
 *   <li>{@code gpt5ZwspModulo}           — ZWSP count &ge; 3 at arithmetic-progression positions.</li>
 *   <li>{@code unknown}                  — invisible markers from &ge; 2 distinct categories.</li>
 *   <li>{@code nnbspBoundary}            — single-category NNBSP.</li>
 *   <li>{@code variationSelectorCarrier} — VS NOT adjacent to an emoji codepoint.</li>
 *   <li>{@code zwjNonEmoji}              — ZWJ NOT adjacent to an emoji codepoint.</li>
 *   <li>{@code smartQuoteAlternation}    — paired curly quotes, no ASCII straight quotes.</li>
 *   <li>{@code emDashPattern}            — em-dashes, no ASCII hyphen-minus.</li>
 *   <li>{@code statisticalTokenChoice}   — input contains an AI-favored lexical pattern.</li>
 *   <li>{@code defaultIgnorableCarrier}  — single-category residual Default_Ignorable.</li>
 * </ol>
 *
 * <p>The Emoji property table is bundled in the port's own {@code data/emoji-data.txt}
 * (UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
 * adjacency probe parses the {@code Emoji} rows from it via the port's own
 * SHA-pinned {@link Security#readResource} loader, never a host emoji library.
 * The residual Default_Ignorable probe reuses the port's own
 * {@link Security#isDefaultIgnorableCodepoint}, never a host normalizer.
 */
public final class AiWatermarkDetectability {
  private AiWatermarkDetectability() {}

  /** UTS #39 family key; the reason-code layer for this family is {@code K}. */
  public static final String FAMILY = "ai-watermark-detectability";

  // ───────────────────────────────────────────────────────────────────────
  // §1 Types
  // ───────────────────────────────────────────────────────────────────────

  /**
   * The conceptual watermark cue class a sub-threat probes for, drawn from the
   * fixed vocabulary in {@code Unicode.Generated.WatermarkSchemes.CueClass}.
   * Ported here because the port exposes no generated watermark-schemes module.
   */
  public enum CueClass {
    /** A codepoint-frequency bias toward a pinned "green list" of tokens. */
    GREEN_LIST_BIAS,
    /** A fixed-period or carrier-byte channel surfacing a pseudorandom function. */
    PSEUDORANDOM_SEQ,
    /** A stylistic-distribution drift away from natural human writing. */
    SEMANTIC_DRIFT
  }

  /**
   * Sub-threats this detector can fire. Each variant has a corresponding probe
   * in {@link #detectWithContext}; the argument carries the position payload the
   * conformance harness's attribution column reads back.
   */
  public sealed interface SubThreat
      permits NnbspBoundary, VariationSelectorCarrier, ZwjNonEmoji, DefaultIgnorableCarrier,
              Gpt5ZwspModulo, EmDashPattern, SmartQuoteAlternation, StatisticalTokenChoice,
              Adversarial, Unknown {
    /** Human-facing classification tag for this sub-threat. */
    String tag();

    /**
     * Map this sub-threat to the conceptual watermark cue class it probes for.
     * Marker-encoded sub-threats route to {@code PSEUDORANDOM_SEQ}; vocabulary-bias
     * to {@code GREEN_LIST_BIAS}; stylistic-distribution to {@code SEMANTIC_DRIFT};
     * {@code Unknown} (multi-category mixing) implicates no single scheme.
     */
    Optional<CueClass> cueClass();
  }

  /** Single-category NNBSP (U+202F) markers; {@code markerCount} is how many. */
  public record NnbspBoundary(int markerCount) implements SubThreat {
    @Override
    public String tag() {
      return "NnbspBoundary";
    }

    @Override
    public Optional<CueClass> cueClass() {
      return Optional.of(CueClass.PSEUDORANDOM_SEQ);
    }
  }

  /** Variation selector(s) not adjacent to an emoji; {@code markerCount} is how many. */
  public record VariationSelectorCarrier(int markerCount) implements SubThreat {
    @Override
    public String tag() {
      return "VariationSelectorCarrier";
    }

    @Override
    public Optional<CueClass> cueClass() {
      return Optional.of(CueClass.PSEUDORANDOM_SEQ);
    }
  }

  /** ZWJ(s) not adjacent to an emoji; {@code markerCount} is how many. */
  public record ZwjNonEmoji(int markerCount) implements SubThreat {
    @Override
    public String tag() {
      return "ZwjNonEmoji";
    }

    @Override
    public Optional<CueClass> cueClass() {
      return Optional.of(CueClass.PSEUDORANDOM_SEQ);
    }
  }

  /** Residual Default_Ignorable markers; {@code markerCount} is how many. */
  public record DefaultIgnorableCarrier(int markerCount) implements SubThreat {
    @Override
    public String tag() {
      return "DefaultIgnorableCarrier";
    }

    @Override
    public Optional<CueClass> cueClass() {
      return Optional.of(CueClass.PSEUDORANDOM_SEQ);
    }
  }

  /**
   * ZWSP (U+200B) markers at arithmetic-progression positions; {@code firstPos}
   * is the first ZWSP position.
   */
  public record Gpt5ZwspModulo(int firstPos) implements SubThreat {
    @Override
    public String tag() {
      return "Gpt5ZwspModulo";
    }

    @Override
    public Optional<CueClass> cueClass() {
      return Optional.of(CueClass.PSEUDORANDOM_SEQ);
    }
  }

  /** Em-dash (U+2014) stylistic signature; {@code firstPos} is the first em-dash. */
  public record EmDashPattern(int firstPos) implements SubThreat {
    @Override
    public String tag() {
      return "EmDashPattern";
    }

    @Override
    public Optional<CueClass> cueClass() {
      return Optional.of(CueClass.SEMANTIC_DRIFT);
    }
  }

  /** Paired curly-quote stylistic signature; {@code firstPos} is the first quote. */
  public record SmartQuoteAlternation(int firstPos) implements SubThreat {
    @Override
    public String tag() {
      return "SmartQuoteAlternation";
    }

    @Override
    public Optional<CueClass> cueClass() {
      return Optional.of(CueClass.SEMANTIC_DRIFT);
    }
  }

  /** AI-favored lexical pattern hit; {@code firstPos} is the match start. */
  public record StatisticalTokenChoice(int firstPos) implements SubThreat {
    @Override
    public String tag() {
      return "StatisticalTokenChoice";
    }

    @Override
    public Optional<CueClass> cueClass() {
      return Optional.of(CueClass.GREEN_LIST_BIAS);
    }
  }

  /**
   * Over-regular marker placement impersonating a scheme; {@code impersonatedScheme}
   * names the surfaced scheme, {@code firstPos} the first marker position.
   */
  public record Adversarial(String impersonatedScheme, int firstPos) implements SubThreat {
    @Override
    public String tag() {
      return "Adversarial";
    }

    @Override
    public Optional<CueClass> cueClass() {
      return Optional.of(CueClass.PSEUDORANDOM_SEQ);
    }
  }

  /**
   * Multi-category invisible-marker mixing; {@code anomalyMarker} is the total
   * invisible-marker count (attribution to a single scheme fails).
   */
  public record Unknown(int anomalyMarker) implements SubThreat {
    @Override
    public String tag() {
      return "Unknown";
    }

    @Override
    public Optional<CueClass> cueClass() {
      return Optional.empty();
    }
  }

  /** Top-level AiWatermarkDetectability classification. */
  public sealed interface Classification permits Clear, Hazard {
    /** True iff no watermark marker was detected. */
    boolean isClear();

    /** Human-facing tag for a hazard, or {@code null} when clear. */
    String tag();

    /** Implicated positions (empty when clear). */
    List<Integer> positions();
  }

  /** No watermark marker detected (semantically {@code noWatermark}). */
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

  /** A hazard: the fired sub-threat plus the implicated marker positions. */
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
   * Verdict — the structured output of {@link #detect}. {@code markerCount} is the
   * count of codepoints matching the fired scheme's probe (0 when clear).
   */
  public record Verdict(List<Integer> input, Classification classify, int markerCount) {}

  /**
   * Optional context for the modulo-probe tolerances. Each field controls how
   * strictly the corresponding probe checks its arithmetic-progression
   * condition; the defaults of {@code 0} require exact equality of consecutive
   * gaps. The empty context is the identity case:
   * {@code detectWithContext(Context.empty(), input)} equals {@code detect(input)}.
   */
  public static final class Context {
    private final int zwspModuloTolerance;
    private final int adversarialTolerance;

    private Context(int zwspModuloTolerance, int adversarialTolerance) {
      this.zwspModuloTolerance = zwspModuloTolerance;
      this.adversarialTolerance = adversarialTolerance;
    }

    /** The empty context — exact-arithmetic settings (both tolerances {@code 0}). */
    public static Context empty() {
      return new Context(0, 0);
    }

    /**
     * ZWSP-modulo tolerance. {@code 0} requires the ZWSP-position arithmetic
     * progression to be exact; {@code k > 0} accepts position gaps within +/- k
     * of the first gap, catching modulo schedules with light jitter.
     */
    public Context withZwspModuloTolerance(int tolerance) {
      return new Context(tolerance, adversarialTolerance);
    }

    /**
     * NNBSP-arithmetic tolerance (the {@code adversarial} probe). Same semantic
     * as {@link #withZwspModuloTolerance} but for the NNBSP positions.
     */
    public Context withAdversarialTolerance(int tolerance) {
      return new Context(zwspModuloTolerance, tolerance);
    }

    public int zwspModuloTolerance() {
      return zwspModuloTolerance;
    }

    public int adversarialTolerance() {
      return adversarialTolerance;
    }
  }

  /**
   * The fixture reason code for a classification, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.K.ai-watermark-detectability.<tag>}
   * scheme keyed by the sub-threat tag.
   */
  public static String reasonCode(Classification classify) {
    String tag = classify.tag();
    return tag == null ? null : "unicode.security.K." + FAMILY + "." + tag;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §2 Emoji property table (bundled data/emoji-data.txt, Emoji rows)
  // ───────────────────────────────────────────────────────────────────────

  private static volatile List<int[]> emojiRanges;

  /**
   * Parse the {@code Emoji} ({@code Emoji=Yes}) closed intervals from
   * emoji-data.txt. Each non-comment row is {@code <range> ; <property> #
   * <comment>}; only rows whose property is exactly {@code Emoji} are kept. The
   * raw bytes are served by the port's SHA-pinned {@link Security#readResource}.
   */
  private static List<int[]> parseEmojiRanges() {
    List<int[]> out = new ArrayList<>();
    String raw = Security.readResource("emoji-data.txt");
    for (String rawLine : raw.split("\n", -1)) {
      int hash = rawLine.indexOf('#');
      String body = hash >= 0 ? rawLine.substring(0, hash) : rawLine;
      String stripped = body.trim();
      if (stripped.isEmpty()) {
        continue;
      }
      String[] fields = stripped.split(";", -1);
      if (fields.length < 2) {
        continue;
      }
      if (!fields[1].trim().equals("Emoji")) {
        continue;
      }
      String range = fields[0].trim();
      int dots = range.indexOf("..");
      if (dots >= 0) {
        Integer lo = parseHex(range.substring(0, dots).trim());
        Integer hi = parseHex(range.substring(dots + 2).trim());
        if (lo == null || hi == null) {
          continue;
        }
        out.add(new int[] {lo, hi});
      } else {
        Integer single = parseHex(range);
        if (single == null) {
          continue;
        }
        out.add(new int[] {single, single});
      }
    }
    return out;
  }

  private static Integer parseHex(String hex) {
    try {
      return Integer.parseInt(hex, 16);
    } catch (NumberFormatException parseError) {
      return null;
    }
  }

  private static List<int[]> emojiRanges() {
    List<int[]> local = emojiRanges;
    if (local == null) {
      synchronized (AiWatermarkDetectability.class) {
        local = emojiRanges;
        if (local == null) {
          local = parseEmojiRanges();
          emojiRanges = local;
        }
      }
    }
    return local;
  }

  /** True iff {@code cp} has the {@code Emoji = Yes} property per emoji-data.txt. */
  private static boolean isEmoji(int cp) {
    for (int[] range : emojiRanges()) {
      if (range[0] <= cp && cp <= range[1]) {
        return true;
      }
    }
    return false;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §3 Codepoint probes
  // ───────────────────────────────────────────────────────────────────────

  /** True iff {@code cp} is U+202F NARROW NO-BREAK SPACE. */
  private static boolean isNnbsp(int cp) {
    return cp == 0x202F;
  }

  /** True iff {@code cp} is U+200D ZERO WIDTH JOINER. */
  private static boolean isZwj(int cp) {
    return cp == 0x200D;
  }

  /**
   * True iff {@code cp} is a Variation Selector — the basic block U+FE00..U+FE0F
   * (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
   */
  private static boolean isVariationSelector(int cp) {
    return (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
  }

  /**
   * True iff {@code cp} is Default_Ignorable_Code_Point. Reuses the port's own
   * UCD-derived predicate {@link Security#isDefaultIgnorableCodepoint}, never a
   * host normalizer.
   */
  private static boolean isDefaultIgnorable(int cp) {
    return Security.isDefaultIgnorableCodepoint(cp);
  }

  /** True iff {@code cp} is U+200B ZERO WIDTH SPACE. */
  private static boolean isZwsp(int cp) {
    return cp == 0x200B;
  }

  /** True iff {@code cp} is U+2014 EM DASH. */
  private static boolean isEmDash(int cp) {
    return cp == 0x2014;
  }

  /** True iff {@code cp} is U+002D HYPHEN-MINUS (ASCII). */
  private static boolean isHyphenMinus(int cp) {
    return cp == 0x002D;
  }

  /**
   * True iff {@code cp} is one of the four "curly" quotation marks: U+2018 /
   * U+2019 (single open/close) and U+201C / U+201D (double open/close).
   */
  private static boolean isCurlyQuote(int cp) {
    return cp == 0x2018 || cp == 0x2019 || cp == 0x201C || cp == 0x201D;
  }

  /**
   * True iff {@code cp} is an ASCII straight quote — U+0022 (double) or U+0027
   * (single / apostrophe).
   */
  private static boolean isStraightQuote(int cp) {
    return cp == 0x0022 || cp == 0x0027;
  }

  /**
   * True iff {@code input[i]} is adjacent (immediate predecessor OR immediate
   * successor) to an emoji codepoint. Two-sided check, single pass. Used by the
   * VS and ZWJ probes to exclude legitimate emoji-context occurrences.
   */
  private static boolean isAdjacentToEmoji(List<Integer> input, int i) {
    boolean prevIsEmoji = i > 0 && isEmoji(input.get(i - 1));
    boolean nextIsEmoji = i + 1 < input.size() && isEmoji(input.get(i + 1));
    return prevIsEmoji || nextIsEmoji;
  }

  /** Functional predicate over a codepoint, for {@link #allPositions}. */
  private interface CpPredicate {
    boolean test(int cp);
  }

  /** All positions in {@code input} matching predicate {@code p}. */
  private static List<Integer> allPositions(CpPredicate p, List<Integer> input) {
    List<Integer> out = new ArrayList<>();
    for (int i = 0; i < input.size(); i++) {
      if (p.test(input.get(i))) {
        out.add(i);
      }
    }
    return out;
  }

  /**
   * True iff {@code positions} forms an arithmetic progression with all
   * consecutive gaps within {@code tolerance} of the first gap. Empty and
   * singleton lists are vacuously arithmetic. {@code positions} is assumed
   * ascending (produced by {@link #allPositions}), so gaps are non-negative.
   */
  private static boolean positionsAreArithmeticWithin(List<Integer> positions, int tolerance) {
    if (positions.size() < 2) {
      return true;
    }
    int firstGap = positions.get(1) - positions.get(0);
    for (int i = 0; i < positions.size() - 1; i++) {
      int gap = positions.get(i + 1) - positions.get(i);
      if (!(gap <= firstGap + tolerance && firstGap <= gap + tolerance)) {
        return false;
      }
    }
    return true;
  }

  /**
   * First start-position at which {@code pattern} appears as a contiguous
   * sub-slice of {@code input}, or {@code null} if absent.
   */
  private static Integer containsSublist(int[] pattern, List<Integer> input) {
    if (pattern.length == 0 || pattern.length > input.size()) {
      return null;
    }
    int maxStart = input.size() - pattern.length;
    for (int start = 0; start <= maxStart; start++) {
      boolean match = true;
      for (int j = 0; j < pattern.length; j++) {
        if (input.get(start + j) != pattern[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        return start;
      }
    }
    return null;
  }

  /**
   * The "AI-favored" lexical-pattern catalog (each word as its codepoint
   * sequence), transcribed verbatim from the pinned {@code aiFavoredVocabulary}
   * literal in the Lean spec (parsed from {@code Ucd/Security/AiFavoredVocabulary.txt}
   * and drift-gated there against a fresh parse).
   */
  private static final int[][] AI_FAVORED_VOCABULARY = {
    {100, 101, 108, 118, 101},
    {100, 101, 108, 118, 105, 110, 103},
    {116, 97, 112, 101, 115, 116, 114, 121},
    {105, 110, 116, 114, 105, 99, 97, 116, 101},
    {110, 117, 97, 110, 99, 101, 100},
    {109, 111, 114, 101, 111, 118, 101, 114},
    {102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101},
    {114, 101, 97, 108, 109},
    {101, 108, 117, 99, 105, 100, 97, 116, 101},
    {115, 104, 111, 119, 99, 97, 115, 105, 110, 103},
    {117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115},
    {117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100},
    {112, 105, 118, 111, 116, 97, 108},
    {98, 111, 108, 115, 116, 101, 114},
    {109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100},
    {116, 101, 115, 116, 97, 109, 101, 110, 116},
    {102, 111, 115, 116, 101, 114},
    {104, 111, 108, 105, 115, 116, 105, 99},
    {112, 97, 114, 97, 100, 105, 103, 109},
    {116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101},
    {115, 112, 101, 97, 114, 104, 101, 97, 100},
    {109, 101, 116, 105, 99, 117, 108, 111, 117, 115},
    {109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121},
    {101, 109, 112, 111, 119, 101, 114},
    {101, 109, 112, 111, 119, 101, 114, 105, 110, 103},
    {112, 114, 111, 102, 111, 117, 110, 100},
    {112, 114, 111, 102, 111, 117, 110, 100, 108, 121},
    {99, 111, 109, 112, 101, 108, 108, 105, 110, 103},
    {99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101},
    {99, 114, 117, 99, 105, 97, 108},
    {100, 97, 117, 110, 116, 105, 110, 103},
    {114, 111, 98, 117, 115, 116},
    {115, 116, 114, 101, 97, 109, 108, 105, 110, 101},
    {101, 110, 114, 105, 99, 104},
    {101, 120, 101, 109, 112, 108, 105, 102, 121},
    {99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103},
    {100, 105, 115, 99, 101, 114, 110, 105, 110, 103},
    {109, 101, 115, 109, 101, 114, 105, 122, 101},
    {105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121},
    {105, 109, 98, 117, 101},
    {112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108, 101},
    {112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111, 108, 101},
    {105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111, 32, 110, 111, 116, 101},
    {105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103},
    {105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110},
    {105, 110, 32, 101, 115, 115, 101, 110, 99, 101},
    {100, 101, 108, 118, 101, 32, 105, 110, 116, 111},
    {100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111},
    {116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102},
    {114, 101, 97, 108, 109, 32, 111, 102}
  };

  // ───────────────────────────────────────────────────────────────────────
  // §4 Top-level detection
  // ───────────────────────────────────────────────────────────────────────

  /**
   * The detection function. Runs every probe in the fixed priority order
   * (most-specific first); the first hit wins. See the class header for the
   * probe inventory and the ordering rationale.
   */
  public static Verdict detectWithContext(Context ctx, List<Integer> input) {
    List<Integer> nnbspPositions = allPositions(AiWatermarkDetectability::isNnbsp, input);
    int nnbspCount = nnbspPositions.size();

    // Probe 1: adversarial — NNBSP too-regular.
    boolean adversarialFires = nnbspCount >= 3
        && positionsAreArithmeticWithin(nnbspPositions, ctx.adversarialTolerance());

    // Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
    List<Integer> zwspPositions = allPositions(AiWatermarkDetectability::isZwsp, input);
    int zwspCount = zwspPositions.size();
    boolean zwspModuloFires = zwspCount >= 3
        && positionsAreArithmeticWithin(zwspPositions, ctx.zwspModuloTolerance());

    List<Integer> vsAllPos = allPositions(AiWatermarkDetectability::isVariationSelector, input);
    List<Integer> vsNonEmojiPos = new ArrayList<>();
    for (int i : vsAllPos) {
      if (!isAdjacentToEmoji(input, i)) {
        vsNonEmojiPos.add(i);
      }
    }
    int vsNonEmojiCount = vsNonEmojiPos.size();

    List<Integer> zwjAllPos = allPositions(AiWatermarkDetectability::isZwj, input);
    List<Integer> zwjNonEmojiPos = new ArrayList<>();
    for (int i : zwjAllPos) {
      if (!isAdjacentToEmoji(input, i)) {
        zwjNonEmojiPos.add(i);
      }
    }
    int zwjNonEmojiCount = zwjNonEmojiPos.size();

    // Probe 7: smartQuoteAlternation — curly quotes only.
    List<Integer> curlyPositions = allPositions(AiWatermarkDetectability::isCurlyQuote, input);
    int curlyCount = curlyPositions.size();
    boolean hasStraightQuote = anyMatch(input, AiWatermarkDetectability::isStraightQuote);
    boolean smartQuoteFires = curlyCount >= 2 && !hasStraightQuote;

    // Probe 8: emDashPattern — em-dashes without hyphen-minus.
    List<Integer> emDashPositions = allPositions(AiWatermarkDetectability::isEmDash, input);
    int emDashCount = emDashPositions.size();
    boolean hasHyphenMinus = anyMatch(input, AiWatermarkDetectability::isHyphenMinus);
    boolean emDashFires = emDashCount >= 2 && !hasHyphenMinus;

    // Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word is
    // compared as a contiguous sub-slice of the input.
    Integer vocabHit = null;
    for (int[] pattern : AI_FAVORED_VOCABULARY) {
      Integer pos = containsSublist(pattern, input);
      if (pos != null) {
        vocabHit = pos;
        break;
      }
    }

    // Residual default-ignorables (excluding VS and ZWJ, handled above).
    CpPredicate isResidualDi =
        cp -> isDefaultIgnorable(cp) && !isVariationSelector(cp) && !isZwj(cp);
    List<Integer> diPositions = allPositions(isResidualDi, input);
    int diCount = diPositions.size();

    // Probe 3: unknown — invisible markers from >= 2 distinct categories.
    int categoryCount = boolToInt(nnbspCount > 0)
        + boolToInt(vsNonEmojiCount > 0)
        + boolToInt(zwjNonEmojiCount > 0)
        + boolToInt(diCount > 0);
    boolean unknownFires = categoryCount >= 2;
    int totalInvisibleCount = nnbspCount + vsNonEmojiCount + zwjNonEmojiCount + diCount;

    Classification classification;
    int firedCount;
    if (adversarialFires) {
      int firstPos = nnbspPositions.isEmpty() ? 0 : nnbspPositions.get(0);
      classification = new Hazard(new Adversarial("nnbspBoundary", firstPos), nnbspPositions);
      firedCount = nnbspCount;
    } else if (zwspModuloFires) {
      int firstPos = zwspPositions.isEmpty() ? 0 : zwspPositions.get(0);
      classification = new Hazard(new Gpt5ZwspModulo(firstPos), zwspPositions);
      firedCount = zwspCount;
    } else if (unknownFires) {
      List<Integer> allInvisiblePos = new ArrayList<>();
      for (int i = 0; i < input.size(); i++) {
        int cp = input.get(i);
        if (isNnbsp(cp) || isVariationSelector(cp) || isZwj(cp) || isDefaultIgnorable(cp)) {
          allInvisiblePos.add(i);
        }
      }
      classification = new Hazard(new Unknown(totalInvisibleCount), allInvisiblePos);
      firedCount = totalInvisibleCount;
    } else if (nnbspCount > 0) {
      classification = new Hazard(new NnbspBoundary(nnbspCount), nnbspPositions);
      firedCount = nnbspCount;
    } else if (vsNonEmojiCount > 0) {
      classification = new Hazard(new VariationSelectorCarrier(vsNonEmojiCount), vsNonEmojiPos);
      firedCount = vsNonEmojiCount;
    } else if (zwjNonEmojiCount > 0) {
      classification = new Hazard(new ZwjNonEmoji(zwjNonEmojiCount), zwjNonEmojiPos);
      firedCount = zwjNonEmojiCount;
    } else if (smartQuoteFires) {
      int firstPos = curlyPositions.isEmpty() ? 0 : curlyPositions.get(0);
      classification = new Hazard(new SmartQuoteAlternation(firstPos), curlyPositions);
      firedCount = curlyCount;
    } else if (emDashFires) {
      int firstPos = emDashPositions.isEmpty() ? 0 : emDashPositions.get(0);
      classification = new Hazard(new EmDashPattern(firstPos), emDashPositions);
      firedCount = emDashCount;
    } else if (vocabHit != null) {
      classification = new Hazard(new StatisticalTokenChoice(vocabHit), List.of(vocabHit));
      firedCount = 1;
    } else if (diCount > 0) {
      classification = new Hazard(new DefaultIgnorableCarrier(diCount), diPositions);
      firedCount = diCount;
    } else {
      classification = new Clear();
      firedCount = 0;
    }

    return new Verdict(new ArrayList<>(input), classification, firedCount);
  }

  private static boolean anyMatch(List<Integer> input, CpPredicate p) {
    for (int cp : input) {
      if (p.test(cp)) {
        return true;
      }
    }
    return false;
  }

  private static int boolToInt(boolean condition) {
    return condition ? 1 : 0;
  }

  /**
   * Convenience wrapper over {@link #detectWithContext} with the empty context —
   * exact-arithmetic settings ({@code zwspModuloTolerance = 0},
   * {@code adversarialTolerance = 0}).
   */
  public static Verdict detect(List<Integer> input) {
    return detectWithContext(Context.empty(), input);
  }
}
