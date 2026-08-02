package com.unicodesecurity;

import java.util.ArrayList;
import java.util.List;

/**
 * Case-expansion-mismatch detection — codepoints whose UAX #21 default-locale
 * case mapping changes the codepoint count (form-layer detector).
 *
 * <p>Direct port of {@code Unicode/Security/Form/CaseExpansionMismatch.lean},
 * transliterated byte-faithfully from the verified Rust reference
 * implementation.
 *
 * <p>Threat model (Tier A&#8321;..A&#8322;). An attacker submits text whose
 * case-mapped form has a different codepoint count than the input. A receiver
 * that fixes a 16-byte username column and stores {@code toUpper(username)}
 * overflows when the user picks "&szlig;&szlig;&szlig;&szlig;&szlig;&szlig;&szlig;&szlig;"
 * (8 in &rarr; 16 stored); a receiver that checks {@code len(stored) == len(input)}
 * rejects valid case-insensitive logins whose names expand under folding.
 * Examples: U+00DF &szlig; toUpper &rarr; "SS", U+FB01 &#64257; toUpper &rarr;
 * "FI", U+0130 &#304; toLower &rarr; "i&#775;" (i + U+0307).
 *
 * <p>Distinct from LocaleCaseInversion (case mapping that changes ACROSS
 * locales): this fires on shapes whose mapping is locale-stable but
 * length-changing under the default locale itself.
 *
 * <p>It reuses the port's own UAX #21 case mapping ({@link
 * Security#upperCodepoint} / {@link Security#lowerCodepoint}, which evaluate the
 * SpecialCasing context predicates), never a host casing library.
 *
 * <p>Sub-threats (priority order):
 * <ol>
 *   <li>{@code UpperExpansion} — first position whose default {@code
 *       upperCodepoint} yields &gt; 1 codepoint.</li>
 *   <li>{@code LowerExpansion} — first position whose default {@code
 *       lowerCodepoint} yields &gt; 1 codepoint (reached only when no upper
 *       expansion fires first).</li>
 * </ol>
 */
public final class CaseExpansionMismatch {
  private CaseExpansionMismatch() {}

  /** Form-layer family key; the reason-code layer for this family is {@code F}. */
  public static final String FAMILY = "case-expansion-mismatch";

  // ───────────────────────────────────────────────────────────────────────
  // §1 Types
  // ───────────────────────────────────────────────────────────────────────

  /** Sub-threats this detector can fire, in priority order. */
  public sealed interface SubThreat permits UpperExpansion, LowerExpansion {
    /** Human-facing classification tag for this sub-threat. */
    String tag();
  }

  /**
   * A codepoint whose default uppercase mapping expands. {@code basePos} is the
   * index of the expanding codepoint, {@code cp} the codepoint itself, and
   * {@code expansionLen} the length of the uppercase expansion (&gt; 1).
   */
  public record UpperExpansion(int basePos, int cp, int expansionLen) implements SubThreat {
    @Override
    public String tag() {
      return "UpperExpansion";
    }
  }

  /**
   * A codepoint whose default lowercase mapping expands. {@code basePos} is the
   * index of the expanding codepoint, {@code cp} the codepoint itself, and
   * {@code expansionLen} the length of the lowercase expansion (&gt; 1).
   */
  public record LowerExpansion(int basePos, int cp, int expansionLen) implements SubThreat {
    @Override
    public String tag() {
      return "LowerExpansion";
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

  /** No case-mapped expansion present. */
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

  /**
   * An expansion fired: the sub-threat, its implicated positions, and any
   * decoded bytes (always empty for this detector — the field mirrors the spec's
   * {@code Classification.hazard} shape).
   */
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

  /**
   * Verdict — the structured output of {@link #detect}. Mirrors the Lean {@code
   * Verdict}: the scanned input, the classification, the per-position expansion
   * counts, and the maximum case-mapped expansion length across all positions
   * (the max of the upper and lower mapped lengths at each position; 0 for empty
   * input).
   */
  public record Verdict(List<Integer> input, Classification classify,
                        int upperExpansionCount, int lowerExpansionCount,
                        int maxExpansionLen) {}

  /**
   * The fixture reason code for a classification, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.F.case-expansion-mismatch.<tag>}
   * scheme keyed by the sub-threat tag.
   */
  public static String reasonCode(Classification classify) {
    String tag = classify.tag();
    return tag == null ? null : "unicode.security.F." + FAMILY + "." + tag;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §2 Per-position expansion scan
  // ───────────────────────────────────────────────────────────────────────

  /** The preceding codepoints of {@code input} before index {@code i}, reversed
   *  (nearest-first) — the {@code revPrefix} context for the SpecialCasing
   *  predicates. */
  private static List<Integer> revPrefix(List<Integer> input, int i) {
    List<Integer> out = new ArrayList<>();
    for (int j = i - 1; j >= 0; j--) {
      out.add(input.get(j));
    }
    return out;
  }

  /**
   * The default-locale uppercase expansion length at position {@code i},
   * evaluating the SpecialCasing context (preceding codepoints nearest-first,
   * following ones) via the port's own {@link Security#upperCodepoint}.
   */
  private static int upperLenAt(List<Integer> input, int i) {
    List<Integer> suffix = input.subList(i + 1, input.size());
    return Security.upperCodepoint(Security.CasingLocale.DEFAULT, revPrefix(input, i), suffix, input.get(i))
        .size();
  }

  /** The default-locale lowercase expansion length at position {@code i}. */
  private static int lowerLenAt(List<Integer> input, int i) {
    List<Integer> suffix = input.subList(i + 1, input.size());
    return Security.lowerCodepoint(Security.CasingLocale.DEFAULT, revPrefix(input, i), suffix, input.get(i))
        .size();
  }

  /** An expanding position: its index, codepoint, and expansion length. */
  private record Expansion(int pos, int cp, int len) {}

  /** First position whose default uppercase mapping expands to &gt; 1 codepoint,
   *  or {@code null} when none does. */
  private static Expansion firstUpperExpansion(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      int len = upperLenAt(input, i);
      if (len > 1) {
        return new Expansion(i, input.get(i), len);
      }
    }
    return null;
  }

  /** First position whose default lowercase mapping expands to &gt; 1 codepoint,
   *  or {@code null} when none does. */
  private static Expansion firstLowerExpansion(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      int len = lowerLenAt(input, i);
      if (len > 1) {
        return new Expansion(i, input.get(i), len);
      }
    }
    return null;
  }

  private static int upperExpansionCount(List<Integer> input) {
    int acc = 0;
    for (int i = 0; i < input.size(); i++) {
      if (upperLenAt(input, i) > 1) {
        acc += 1;
      }
    }
    return acc;
  }

  private static int lowerExpansionCount(List<Integer> input) {
    int acc = 0;
    for (int i = 0; i < input.size(); i++) {
      if (lowerLenAt(input, i) > 1) {
        acc += 1;
      }
    }
    return acc;
  }

  private static int maxExpansionLen(List<Integer> input) {
    int acc = 0;
    for (int i = 0; i < input.size(); i++) {
      int len = Math.max(upperLenAt(input, i), lowerLenAt(input, i));
      if (len > acc) {
        acc = len;
      }
    }
    return acc;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §3 Top-level detection
  // ───────────────────────────────────────────────────────────────────────

  /**
   * The detection function. Priority 1: an uppercase expansion. Priority 2: a
   * lowercase expansion, reached only when no upper expansion fires first. Else
   * {@code Clear}.
   */
  public static Verdict detect(List<Integer> input) {
    Classification classification;
    Expansion upper = firstUpperExpansion(input);
    if (upper != null) {
      classification = new Hazard(
          new UpperExpansion(upper.pos(), upper.cp(), upper.len()),
          List.of(upper.pos()),
          List.of());
    } else {
      Expansion lower = firstLowerExpansion(input);
      if (lower != null) {
        classification = new Hazard(
            new LowerExpansion(lower.pos(), lower.cp(), lower.len()),
            List.of(lower.pos()),
            List.of());
      } else {
        classification = new Clear();
      }
    }
    return new Verdict(new ArrayList<>(input), classification,
        upperExpansionCount(input), lowerExpansionCount(input), maxExpansionLen(input));
  }
}
