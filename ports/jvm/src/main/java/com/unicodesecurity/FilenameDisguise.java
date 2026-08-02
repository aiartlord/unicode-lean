package com.unicodesecurity;

import java.util.ArrayList;
import java.util.List;

/**
 * FilenameDisguise — detection of filename/extension disguise attacks where the
 * visible extension differs from the byte extension (display-layer detector).
 *
 * <p>Byte-faithful transliteration of the verified Rust reference
 * implementation, itself a transliteration of
 * {@code Unicode/Security/Display/FilenameDisguise.lean}.
 *
 * <p>Threat model. An adversary delivers a file whose rendered name looks like a
 * benign type ({@code document.txt}) but whose actual byte extension is
 * executable — the canonical attack inserts {@code U+202E} RIGHT-TO-LEFT
 * OVERRIDE so {@code document<RLO>txt.exe} renders as {@code document exe.txt}.
 *
 * <p>Detection is presentation- and language-agnostic: it surfaces every
 * codepoint that could cause display-vs-byte divergence in the filename — any
 * bidi format-control anywhere, and any fullwidth/halfwidth or combining
 * (grapheme Extend) codepoint in the extension region (after the last
 * {@code .}). Native-RTL names with no bidi controls clear. It reuses the port's
 * own predicates (the bidi-format-control set, the grapheme Extend class, the
 * fullwidth range), never a host filesystem or rendering library.
 *
 * <p>Sub-threats (priority order):
 * <ol>
 *   <li>{@code RloFlip} — any bidi format-control in the input.</li>
 *   <li>{@code WidthClassExt} — a fullwidth/halfwidth codepoint in the
 *       extension.</li>
 *   <li>{@code CombiningInExt} — a combining (Extend) codepoint in the
 *       extension.</li>
 *   <li>{@code MultipleExtensions} — three or more dots (advisory; e.g.
 *       legitimate {@code .tar.gz.sig}).</li>
 * </ol>
 */
public final class FilenameDisguise {
  private FilenameDisguise() {}

  /** UTS #39-adjacent family key; the reason-code layer for this family is {@code D}. */
  public static final String FAMILY = "filename-disguise";

  // ───────────────────────────────────────────────────────────────────────
  // §1 Constants
  // ───────────────────────────────────────────────────────────────────────

  /** {@code U+002E FULL STOP} — the extension separator. */
  public static final int ASCII_DOT = 0x002E;

  /** The dot count at or beyond which the input is treated as a multi-extension advisory. */
  public static final int MIN_MULTIPLE_EXTENSIONS = 3;

  // ───────────────────────────────────────────────────────────────────────
  // §2 Types
  // ───────────────────────────────────────────────────────────────────────

  /** Sub-threat enumeration for FilenameDisguise, in priority order. */
  public sealed interface SubThreat
      permits RloFlip, WidthClassExt, CombiningInExt, MultipleExtensions {
    /** Fixture-row tag string for this sub-threat. */
    String tag();
  }

  /** A bidi format-control at {@code position} (codepoint {@code controlCp}). */
  public record RloFlip(int position, int controlCp) implements SubThreat {
    @Override
    public String tag() {
      return "RloFlip";
    }
  }

  /** A fullwidth/halfwidth codepoint in the extension, at {@code position} (codepoint {@code cp}). */
  public record WidthClassExt(int position, int cp) implements SubThreat {
    @Override
    public String tag() {
      return "WidthClassExt";
    }
  }

  /** A combining (grapheme Extend) codepoint in the extension, at {@code position} (codepoint {@code cp}). */
  public record CombiningInExt(int position, int cp) implements SubThreat {
    @Override
    public String tag() {
      return "CombiningInExt";
    }
  }

  /** Three or more {@code .} separators (advisory), {@code dotCount} of them. */
  public record MultipleExtensions(int dotCount) implements SubThreat {
    @Override
    public String tag() {
      return "MultipleExtensions";
    }
  }

  /** Top-level classification (safe = {@link Clear}). */
  public sealed interface Classification permits Clear, Hazard {
    /** True iff this classification is {@code Clear}. */
    boolean isClear();

    /** Human-facing tag for a hazard, or {@code null} when clear. */
    String tag();

    /** Implicated positions (empty when clear). */
    List<Integer> positions();
  }

  /** No disguise trigger present. */
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

  /** A disguise trigger fired. */
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
      List<Integer> dotPositions,
      Integer lastDotPos,
      int bidiControlCount,
      int fullwidthInExt,
      int combiningInExt) {}

  /**
   * The fixture reason code for a classification, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.D.filename-disguise.<tag>} scheme
   * keyed by the sub-threat tag.
   */
  public static String reasonCode(Classification classify) {
    String tag = classify.tag();
    return tag == null ? null : "unicode.security.D." + FAMILY + "." + tag;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §3 Core predicates (each reuses the port's own table, never a host library)
  // ───────────────────────────────────────────────────────────────────────

  /** True iff {@code cp} is {@code U+002E FULL STOP} (the extension separator). */
  public static boolean isAsciiDot(int cp) {
    return cp == ASCII_DOT;
  }

  /** True iff {@code cp} is in the Halfwidth and Fullwidth Forms block. */
  public static boolean isFullwidthHalfwidth(int cp) {
    return cp >= 0xFF01 && cp <= 0xFFEF;
  }

  /** True iff {@code cp} is a bidi format-control (reuses {@link Security#isBidiFormatControl}). */
  public static boolean isBidiFormatControl(int cp) {
    return Security.isBidiFormatControl(cp);
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

  /** Positions of every {@code .} in {@code input}. */
  private static List<Integer> dotPositions(List<Integer> input) {
    List<Integer> out = new ArrayList<>();
    for (int i = 0; i < input.size(); i++) {
      if (isAsciiDot(input.get(i))) out.add(i);
    }
    return List.copyOf(out);
  }

  private static int countBidiControl(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (isBidiFormatControl(cp)) count++;
    }
    return count;
  }

  /** Position and codepoint of the first bidi format-control, or {@code null}. */
  private static int[] firstBidiControl(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      int cp = input.get(i);
      if (isBidiFormatControl(cp)) return new int[] {i, cp};
    }
    return null;
  }

  /** Position and codepoint of the first fullwidth/halfwidth codepoint at or after {@code start}, or {@code null}. */
  private static int[] firstFullwidthFrom(List<Integer> input, int start) {
    for (int i = start; i < input.size(); i++) {
      int cp = input.get(i);
      if (isFullwidthHalfwidth(cp)) return new int[] {i, cp};
    }
    return null;
  }

  /** Position and codepoint of the first Extend codepoint at or after {@code start}, or {@code null}. */
  private static int[] firstExtendFrom(List<Integer> input, int start) {
    for (int i = start; i < input.size(); i++) {
      int cp = input.get(i);
      if (isGraphemeExtend(cp)) return new int[] {i, cp};
    }
    return null;
  }

  /** Count of fullwidth/halfwidth codepoints at or after {@code start}. */
  private static int countFullwidthFrom(List<Integer> input, int start) {
    int count = 0;
    for (int i = start; i < input.size(); i++) {
      if (isFullwidthHalfwidth(input.get(i))) count++;
    }
    return count;
  }

  /** Count of Extend codepoints at or after {@code start}. */
  private static int countExtendFrom(List<Integer> input, int start) {
    int count = 0;
    for (int i = start; i < input.size(); i++) {
      if (isGraphemeExtend(input.get(i))) count++;
    }
    return count;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §5 Top-level detection
  // ───────────────────────────────────────────────────────────────────────

  /** The FilenameDisguise detection function. */
  public static Verdict detect(List<Integer> input) {
    List<Integer> cps = List.copyOf(input);
    List<Integer> dots = dotPositions(cps);
    Integer lastDot = dots.isEmpty() ? null : dots.get(dots.size() - 1);
    int extStart = lastDot == null ? cps.size() : lastDot + 1;
    int bidiCount = countBidiControl(cps);
    int fwInExt = countFullwidthFrom(cps, extStart);
    int extInExt = countExtendFrom(cps, extStart);

    Classification classification = classify(cps, dots, extStart);

    return new Verdict(cps, classification, dots, lastDot, bidiCount, fwInExt, extInExt);
  }

  private static Classification classify(List<Integer> input, List<Integer> dots, int extStart) {
    // Priority 1: any bidi format-control anywhere in the input.
    int[] bidi = firstBidiControl(input);
    if (bidi != null) {
      return new Hazard(new RloFlip(bidi[0], bidi[1]), positionList(bidi[0]), List.of());
    }

    // Priority 2: a fullwidth/halfwidth codepoint in the extension region.
    int[] fw = firstFullwidthFrom(input, extStart);
    if (fw != null) {
      return new Hazard(new WidthClassExt(fw[0], fw[1]), positionList(fw[0]), List.of());
    }

    // Priority 3: a combining (Extend) codepoint in the extension region.
    int[] ext = firstExtendFrom(input, extStart);
    if (ext != null) {
      return new Hazard(new CombiningInExt(ext[0], ext[1]), positionList(ext[0]), List.of());
    }

    // Priority 4: three or more extensions (advisory).
    if (dots.size() >= MIN_MULTIPLE_EXTENSIONS) {
      return new Hazard(new MultipleExtensions(dots.size()), List.copyOf(dots), List.of());
    }

    return new Clear();
  }

  private static List<Integer> positionList(int position) {
    List<Integer> out = new ArrayList<>();
    out.add(position);
    return List.copyOf(out);
  }
}
