package com.unicodesecurity;

import java.util.List;

/**
 * AdmissibilityFormDrift — cross-layer identifier-admissibility × form drift
 * (boundary-layer detector).
 *
 * <p>Byte-faithful transliteration of the verified Rust reference
 * implementation, itself a transliteration of
 * {@code Unicode/Security/Boundary/AdmissibilityFormDrift.lean}.
 *
 * <p>Fires on inputs whose UTS #39 whole-string admissibility verdict differs
 * between the input and its NFKC form. This is the string-level complement of
 * {@link IdentifierFormDrift} (which scans {@code Identifier_Status} against the
 * per-codepoint NFKD head): here the whole-string admissibility predicate is
 * evaluated twice — once on the input, once on {@code toNfkc(input)}. The two are
 * not redundant. In particular, a sequence of decomposed Hangul jamos passes the
 * per-codepoint scan cleanly (each jamo has identity NFKD and Restricted status
 * on both sides) but fires here: the jamo sequence is rejected by
 * {@code isAllowedIdentifier}, while its NFKC composition into a precomposed
 * Hangul syllable is accepted.
 *
 * <p>It reuses the port's own UTS #39 admissibility predicate
 * ({@link Security#isAllowedIdentifier} = UAX #31 default identifier ∧ every
 * codepoint Allowed) and NFKC pipeline ({@link Security#toNfkc}), never a host
 * normalization or identifier library.
 *
 * <p>Sub-threat (direction-agnostic):
 * <ul>
 *   <li>{@code AdmissibilityFormDrift} — {@code isAllowedIdentifier(input) !=
 *       isAllowedIdentifier(toNfkc(input))}. The pair of booleans is carried so
 *       the verdict records which direction the drift goes; no position is
 *       reported because the predicate is whole-string.</li>
 * </ul>
 */
public final class AdmissibilityFormDrift {
  private AdmissibilityFormDrift() {}

  /** UTS #39-adjacent family key; the reason-code layer for this family is {@code X}. */
  public static final String FAMILY = "admissibility-form-drift";

  // ───────────────────────────────────────────────────────────────────────
  // §1 Types
  // ───────────────────────────────────────────────────────────────────────

  /** Sub-threat enumeration for AdmissibilityFormDrift. */
  public sealed interface SubThreat permits Drift {
    /** Fixture-row tag string for this sub-threat. */
    String tag();
  }

  /**
   * The whole-string admissibility verdict differs between the input
   * ({@code inputAdmissible}) and its NFKC form ({@code nfkcAdmissible}).
   */
  public record Drift(boolean inputAdmissible, boolean nfkcAdmissible) implements SubThreat {
    @Override
    public String tag() {
      return "AdmissibilityFormDrift";
    }
  }

  /** Top-level classification (safe = {@link Clear}). */
  public sealed interface Classification permits Clear, Hazard {
    /** True iff this classification is {@code Clear}. */
    boolean isClear();

    /** Human-facing tag for a hazard, or {@code null} when clear. */
    String tag();

    /** Implicated positions (always empty — the predicate is whole-string). */
    List<Integer> positions();
  }

  /** The admissibility verdict agrees across forms. */
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

  /** The admissibility verdict drifts across forms. */
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
      List<Integer> input, Classification classify, boolean inputAdmissible, boolean nfkcAdmissible) {}

  /**
   * The fixture reason code for a classification, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.X.admissibility-form-drift.<tag>}
   * scheme keyed by the sub-threat tag.
   */
  public static String reasonCode(Classification classify) {
    String tag = classify.tag();
    return tag == null ? null : "unicode.security.X." + FAMILY + "." + tag;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §2 Top-level detection
  // ───────────────────────────────────────────────────────────────────────

  /** The AdmissibilityFormDrift detection function. */
  public static Verdict detect(List<Integer> input) {
    List<Integer> cps = List.copyOf(input);
    List<Integer> nfkc = Security.toNfkc(cps);
    boolean inOk = Security.isAllowedIdentifier(cps);
    boolean nfkcOk = Security.isAllowedIdentifier(nfkc);

    Classification classification;
    if (inOk == nfkcOk) {
      classification = new Clear();
    } else {
      classification = new Hazard(new Drift(inOk, nfkcOk), List.of(), List.of());
    }
    return new Verdict(cps, classification, inOk, nfkcOk);
  }
}
