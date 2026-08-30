package com.unicodesecurity;

import java.util.List;

/**
 * IdentifierFormDrift — cross-layer identifier × form drift (boundary-layer
 * detector).
 *
 * <p>Byte-faithful transliteration of the verified Rust reference
 * implementation, itself a transliteration of
 * {@code Unicode/Security/Boundary/IdentifierFormDrift.lean}.
 *
 * <p>Threat model. Tier A₂ two-system bypass. An identity validator and a form
 * normalizer disagree about a codepoint: stage A runs the UTS #39
 * {@code Identifier_Status} check before normalisation and rejects, say,
 * U+1D44E MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and
 * then runs the same check, seeing U+0061 'a' (Allowed) and accepting. The
 * attacker controls which stage processes the input and exploits the
 * disagreement. The same shape covers fullwidth (U+FF21), circled (U+24B6),
 * ligature (U+FB01), and Roman-numeral (U+2163) compatibility forms.
 *
 * <p>The detector fires on the <em>form transition</em> itself — it reports every
 * input position whose {@code Identifier_Status} differs from the
 * {@code Identifier_Status} of that codepoint's NFKD head. This is orthogonal to
 * the single-form identity-spoofing detectors (which examine the input under one
 * form) and stronger than a form-of-input fold (it asks whether the identifier
 * verdict changes, not whether any output bit changes).
 *
 * <p>Note on Hangul: precomposed syllables are Allowed while their NFKD-head
 * jamos are Restricted, so pure Korean text fires; callers intending to accept
 * Korean identifiers should apply NFC before evaluating admissibility.
 *
 * <p>It reuses the port's own UTS #39 {@code Identifier_Status} predicate
 * ({@link Security#isIdAllowed}) and NFKD pipeline ({@link Security#toNfkd}),
 * never a host normalization or identifier library.
 *
 * <p>Sub-threat (direction-agnostic):
 * <ul>
 *   <li>{@code IdentifierStatusShift} — the first input position whose
 *       {@code Identifier_Status} differs from its NFKD-head's. The verdict
 *       carries the total shift count.</li>
 * </ul>
 */
public final class IdentifierFormDrift {
  private IdentifierFormDrift() {}

  /** UTS #39-adjacent family key; the reason-code layer for this family is {@code X}. */
  public static final String FAMILY = "identifier-form-drift";

  // ───────────────────────────────────────────────────────────────────────
  // §1 Types
  // ───────────────────────────────────────────────────────────────────────

  /** Sub-threat enumeration for IdentifierFormDrift. */
  public sealed interface SubThreat permits IdentifierStatusShift {
    /** Fixture-row tag string for this sub-threat. */
    String tag();
  }

  /**
   * A codepoint at {@code basePos} whose {@code Identifier_Status} differs from
   * its NFKD-head's (codepoint {@code cp}).
   */
  public record IdentifierStatusShift(int basePos, int cp) implements SubThreat {
    @Override
    public String tag() {
      return "IdentifierStatusShift";
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

  /** No status shift present. */
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

  /** A status shift fired. */
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
  public record Verdict(List<Integer> input, Classification classify, int shiftCount) {}

  /**
   * The fixture reason code for a classification, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.X.identifier-form-drift.<tag>}
   * scheme keyed by the sub-threat tag.
   */
  public static String reasonCode(Classification classify) {
    String tag = classify.tag();
    return tag == null ? null : "unicode.security.X." + FAMILY + "." + tag;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §2 Core predicates
  // ───────────────────────────────────────────────────────────────────────

  /**
   * {@code Identifier_Status = Allowed} of the first codepoint of {@code cp}'s
   * NFKD form, or {@code cp}'s own status when NFKD is empty (defensive —
   * {@link Security#toNfkd} is total and returns at least {@code [cp]}). Reuses
   * the port's own UTS #39 predicate and NFKD pipeline.
   */
  public static boolean nfkdHeadAllowed(int cp) {
    List<Integer> nfkd = Security.toNfkd(List.of(cp));
    if (nfkd.isEmpty()) {
      return Security.isIdAllowed(cp);
    }
    return Security.isIdAllowed(nfkd.get(0));
  }

  // ───────────────────────────────────────────────────────────────────────
  // §3 Sub-detectors
  // ───────────────────────────────────────────────────────────────────────

  /** True iff {@code cp}'s own status differs from its NFKD-head's. */
  private static boolean statusShifts(int cp) {
    return !Security.isIdAllowed(cp) && nfkdHeadAllowed(cp);
  }

  /**
   * Position and codepoint of the first input position whose {@code isIdAllowed}
   * differs from its NFKD-head's, or {@code null}.
   */
  private static int[] firstStatusShift(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      int cp = input.get(i);
      if (statusShifts(cp)) return new int[] {i, cp};
    }
    return null;
  }

  /** Total count of input positions where the per-cp status shifts under NFKD. */
  private static int statusShiftCount(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (statusShifts(cp)) count++;
    }
    return count;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §4 Top-level detection
  // ───────────────────────────────────────────────────────────────────────

  /** The IdentifierFormDrift detection function. */
  public static Verdict detect(List<Integer> input) {
    List<Integer> cps = List.copyOf(input);
    int[] shift = firstStatusShift(cps);
    Classification classification;
    if (shift != null) {
      classification =
          new Hazard(new IdentifierStatusShift(shift[0], shift[1]), List.of(shift[0]), List.of());
    } else {
      classification = new Clear();
    }
    return new Verdict(cps, classification, statusShiftCount(cps));
  }
}
