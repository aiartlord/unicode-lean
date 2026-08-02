package com.unicodesecurity;

import java.util.ArrayList;
import java.util.List;

/**
 * RendererDivergence — detection of codepoint/sequence shapes known to render
 * differently across font + terminal + browser stacks (display-layer detector).
 *
 * <p>Byte-faithful transliteration of the verified Rust reference
 * {@code ports/rust/src/security/display/renderer_divergence.rs}, itself a
 * transliteration of {@code Unicode/Security/Display/RendererDivergence.lean}.
 *
 * <p>Threat model. An adversary crafts content that renders one way in the
 * auditor's renderer (a benign glyph or an empty span) and a different way in
 * the consumer's renderer (a misleading glyph, a wider glyph, or a different
 * sequence). This is the "fingerprint stability" family — clear inputs render
 * the same across the renderer cohort the Standard documents as stable.
 *
 * <p>What the detector draws. A heuristic three-value split, surfaced through
 * the universal clear/hazard carrier: an input is clear when none of the
 * documented variance triggers fire, and otherwise is classified by the first
 * trigger in priority order — combining-mark stack overflow, variation-selector
 * presence, an unregistered ZWJ shape, fullwidth/halfwidth display, or mixed
 * direction. It reuses the port's own tables (variation-selector set, grapheme
 * Extend class, the RGI ZWJ registry, and strong-bidi classes), never a host
 * rendering or shaping library.
 *
 * <p>Sub-threats (priority order):
 * <ol>
 *   <li>{@code CombiningStackOverflow} — Zalgo-like combining-mark stack &ge; 4
 *       on a base.</li>
 *   <li>{@code VariationSelectorVariance} — any variation selector present.</li>
 *   <li>{@code UnregisteredZwjVariance} — ZWJ-containing input not in the RGI
 *       ZWJ set.</li>
 *   <li>{@code FullwidthVariance} — a fullwidth/halfwidth codepoint present.</li>
 *   <li>{@code MixedDirectionVariance} — both strong-LTR and strong-RTL
 *       codepoints.</li>
 * </ol>
 */
public final class RendererDivergence {
  private RendererDivergence() {}

  /** UTS #39-adjacent family key; the reason-code layer for this family is {@code D}. */
  public static final String FAMILY = "renderer-divergence";

  // ───────────────────────────────────────────────────────────────────────
  // §1 Constants
  // ───────────────────────────────────────────────────────────────────────

  /**
   * The combining-mark stack depth (on a single base) at or beyond which the
   * input is treated as a Zalgo-style rendering-variance hazard.
   */
  public static final int MIN_COMBINING_STACK = 4;

  /** The ZERO WIDTH JOINER codepoint. */
  public static final int ZWJ = 0x200D;

  // ───────────────────────────────────────────────────────────────────────
  // §2 Types
  // ───────────────────────────────────────────────────────────────────────

  /** Sub-threat enumeration for RendererDivergence, in priority order. */
  public sealed interface SubThreat
      permits CombiningStackOverflow,
          VariationSelectorVariance,
          UnregisteredZwjVariance,
          FullwidthVariance,
          MixedDirectionVariance {
    /** Fixture-row tag string for this sub-threat. */
    String tag();
  }

  /** A combining-mark stack of {@code stackLen} marks on the base at {@code basePos}. */
  public record CombiningStackOverflow(int basePos, int stackLen) implements SubThreat {
    @Override
    public String tag() {
      return "CombiningStackOverflow";
    }
  }

  /** A variation selector at {@code firstVsPos} (codepoint {@code firstVsCp}). */
  public record VariationSelectorVariance(int firstVsPos, int firstVsCp) implements SubThreat {
    @Override
    public String tag() {
      return "VariationSelectorVariance";
    }
  }

  /** A ZWJ-containing input not present in the registered RGI ZWJ set. */
  public record UnregisteredZwjVariance(int firstZwjPos) implements SubThreat {
    @Override
    public String tag() {
      return "UnregisteredZwjVariance";
    }
  }

  /** A fullwidth/halfwidth codepoint at {@code firstFwPos} (codepoint {@code firstFwCp}). */
  public record FullwidthVariance(int firstFwPos, int firstFwCp) implements SubThreat {
    @Override
    public String tag() {
      return "FullwidthVariance";
    }
  }

  /** Both strong-LTR and strong-RTL codepoints in one input. */
  public record MixedDirectionVariance(int ltrCount, int rtlCount) implements SubThreat {
    @Override
    public String tag() {
      return "MixedDirectionVariance";
    }
  }

  /** Top-level classification (stable = {@link Clear}). */
  public sealed interface Classification permits Clear, Hazard {
    /** True iff this classification is {@code Clear} (i.e. stable). */
    boolean isClear();

    /** Human-facing tag for a hazard, or {@code null} when clear. */
    String tag();

    /** Implicated positions (empty when clear). */
    List<Integer> positions();
  }

  /** Rendering is consistent across the documented renderer cohort. */
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

  /** A documented variance mode fired. */
  public record Hazard(SubThreat sub, List<Integer> positions, List<Integer> decoded)
      implements Classification {
    @Override
    public boolean isClear() {
      return false;
    }

    @Override
    public String tag() {
      return sub.tag();
    }
  }

  /** The structured output of {@link #detect} (mirrors the Lean {@code Verdict}). */
  public record Verdict(
      List<Integer> input,
      Classification classify,
      int vsCount,
      int combiningCount,
      int fullwidthCount,
      boolean hasZwj,
      int strongLtrCount,
      int strongRtlCount) {}

  /**
   * The fixture reason code for a classification, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.D.renderer-divergence.<tag>}
   * scheme keyed by the sub-threat tag.
   */
  public static String reasonCode(Classification classify) {
    String tag = classify.tag();
    return tag == null ? null : "unicode.security.D." + FAMILY + "." + tag;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §3 Core predicates (each reuses the port's own table, never a host library)
  // ───────────────────────────────────────────────────────────────────────

  /** True iff {@code cp} is a variation selector (reuses Security's own predicate). */
  public static boolean isVariationSelector(int cp) {
    return Security.isVariationSelector(cp);
  }

  /** True iff {@code cp} is the ZWJ codepoint. */
  public static boolean isZwj(int cp) {
    return cp == ZWJ;
  }

  /** True iff {@code cp} is in the Halfwidth/Fullwidth Forms block. */
  public static boolean isFullwidthHalfwidth(int cp) {
    return cp >= 0xFF01 && cp <= 0xFFEF;
  }

  /**
   * True iff {@code cp} has {@code Grapheme_Cluster_Break = Extend} (reuses the
   * port's own {@link Security#isGraphemeExtend}, derived from the bundled
   * Grapheme_Extend property unioned with the emoji modifiers).
   */
  public static boolean isGraphemeExtend(int cp) {
    return Security.isGraphemeExtend(cp);
  }

  // ───────────────────────────────────────────────────────────────────────
  // §4 Sub-detectors
  // ───────────────────────────────────────────────────────────────────────

  private static int countVs(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (isVariationSelector(cp)) count++;
    }
    return count;
  }

  private static int countCombining(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (isGraphemeExtend(cp)) count++;
    }
    return count;
  }

  private static int countFullwidth(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (isFullwidthHalfwidth(cp)) count++;
    }
    return count;
  }

  private static boolean inputHasZwj(List<Integer> input) {
    for (int cp : input) {
      if (isZwj(cp)) return true;
    }
    return false;
  }

  private static int countStrongLtr(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (Security.isStrongLtr(cp)) count++;
    }
    return count;
  }

  private static int countStrongRtl(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (Security.isStrongRtl(cp)) count++;
    }
    return count;
  }

  /** Position and codepoint of the first variation selector, or {@code null}. */
  private static int[] firstVsPos(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      int cp = input.get(i);
      if (isVariationSelector(cp)) return new int[] {i, cp};
    }
    return null;
  }

  /** Position of the first ZWJ, or -1. */
  private static int firstZwjPos(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      if (isZwj(input.get(i))) return i;
    }
    return -1;
  }

  /** Position and codepoint of the first fullwidth/halfwidth codepoint, or {@code null}. */
  private static int[] firstFullwidthPos(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      int cp = input.get(i);
      if (isFullwidthHalfwidth(cp)) return new int[] {i, cp};
    }
    return null;
  }

  /**
   * The first base position (a non-Extend codepoint) immediately followed by
   * exactly {@code minStack} consecutive Extend codepoints. Returns
   * {@code {basePos, minStack}} on hit, or {@code null}.
   */
  private static int[] firstCombiningStack(List<Integer> input, int minStack) {
    for (int idx = 0; idx < input.size(); idx++) {
      if (!isGraphemeExtend(input.get(idx))) {
        int available = 0;
        boolean allExtend = true;
        for (int j = idx + 1; j < input.size() && available < minStack; j++) {
          available++;
          if (!isGraphemeExtend(input.get(j))) {
            allExtend = false;
            break;
          }
        }
        if (available == minStack && allExtend) {
          return new int[] {idx, minStack};
        }
      }
    }
    return null;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §5 Top-level detection
  // ───────────────────────────────────────────────────────────────────────

  /** The RendererDivergence detection function. */
  public static Verdict detect(List<Integer> input) {
    List<Integer> cps = List.copyOf(input);
    int vsCount = countVs(cps);
    int combiningCount = countCombining(cps);
    int fullwidthCount = countFullwidth(cps);
    boolean hasZwj = inputHasZwj(cps);
    int ltrCount = countStrongLtr(cps);
    int rtlCount = countStrongRtl(cps);

    Classification classification = classify(cps, hasZwj, ltrCount, rtlCount);

    return new Verdict(
        cps, classification, vsCount, combiningCount, fullwidthCount, hasZwj, ltrCount, rtlCount);
  }

  private static Classification classify(
      List<Integer> input, boolean hasZwj, int ltrCount, int rtlCount) {
    // Priority 1: combining-mark stack overflow (Zalgo).
    int[] stack = firstCombiningStack(input, MIN_COMBINING_STACK);
    if (stack != null) {
      return new Hazard(
          new CombiningStackOverflow(stack[0], stack[1]), positionList(stack[0]), List.of());
    }

    // Priority 2: any variation selector triggers presentation variance.
    int[] vs = firstVsPos(input);
    if (vs != null) {
      return new Hazard(
          new VariationSelectorVariance(vs[0], vs[1]), positionList(vs[0]), List.of());
    }

    // Priority 3: ZWJ-containing input not in the registered RGI set.
    if (hasZwj && !EmojiZwjIntegrity.isRegisteredZwjSequence(input)) {
      int zwjPos = firstZwjPos(input);
      if (zwjPos >= 0) {
        return new Hazard(new UnregisteredZwjVariance(zwjPos), positionList(zwjPos), List.of());
      }
      return new Clear();
    }

    // Priority 4: fullwidth/halfwidth.
    int[] fw = firstFullwidthPos(input);
    if (fw != null) {
      return new Hazard(new FullwidthVariance(fw[0], fw[1]), positionList(fw[0]), List.of());
    }

    // Priority 5: mixed direction.
    if (ltrCount > 0 && rtlCount > 0) {
      return new Hazard(new MixedDirectionVariance(ltrCount, rtlCount), List.of(), List.of());
    }

    return new Clear();
  }

  private static List<Integer> positionList(int position) {
    List<Integer> out = new ArrayList<>();
    out.add(position);
    return List.copyOf(out);
  }
}
