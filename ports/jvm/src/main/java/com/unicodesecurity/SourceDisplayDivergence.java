package com.unicodesecurity;

import java.util.ArrayList;
import java.util.List;

/**
 * SourceDisplayDivergence — the aggregate "what a reviewer sees differs from
 * what the machine runs" detector (display-layer aggregator).
 *
 * <p>Byte-faithful transliteration of the verified Rust reference
 * implementation, itself a transliteration of
 * {@code Unicode/Security/Display/SourceDisplayDivergence.lean}
 * ({@code detect} + {@code buildClassification}).
 *
 * <p>Threat model. A single covert or identity trick may be individually
 * benign-looking, but any hit means the rendered source diverges from its
 * logical content; two or more is a strong compound signal. This detector runs
 * the five constituent detectors on the same codepoint stream and aggregates:
 * zero fire &rarr; clear, exactly one &rarr; pass-through that family's tag, two
 * or more &rarr; {@code Compound}. Every constituent fires region-agnostically —
 * payloads inside string literals or comments count.
 *
 * <p>Constituent families, in canonical aggregation order, with their tags:
 * <ol>
 *   <li>tag-block-payload &rarr; {@code TagBlock}</li>
 *   <li>variation-selector-payload &rarr; {@code VariationSelector}</li>
 *   <li>zero-width-payload &rarr; {@code ZeroWidth}</li>
 *   <li>bidi-control-balance &rarr; {@code BidiControl}</li>
 *   <li>homoglyph-confusable &rarr; {@code IdentifierHomoglyph}</li>
 * </ol>
 *
 * <p>The five constituents are the port's own core-family detectors, reused
 * through {@link Security}'s package-private {@code *Fired} accessors (each of
 * which delegates to the exact detector logic the main scan runs), never a
 * re-implementation and never a host library. No positions are carried at this
 * layer — by the spec the per-family verdicts carry them.
 *
 * <p>This is a STANDALONE detector: it is not part of the default policy scan,
 * matching the Rust reference.
 */
public final class SourceDisplayDivergence {
  private SourceDisplayDivergence() {}

  /** UTS #39-adjacent family key; the reason-code layer for this family is {@code D}. */
  public static final String FAMILY = "source-display-divergence";

  /** The {@code Compound} sub-threat tag, used when two or more constituents fire. */
  public static final String COMPOUND = "Compound";

  // ───────────────────────────────────────────────────────────────────────
  // §1 Types
  // ───────────────────────────────────────────────────────────────────────

  /**
   * One source-display-divergence scan result. {@code sub} is {@code null} for a
   * clear input; a single constituent hit passes through its family tag; two or
   * more yield {@code "Compound"}. Positions are empty at this layer by the spec
   * (the per-family verdicts carry them).
   */
  public record Detection(String sub) {
    /** True iff this scan found no divergence (no constituent fired). */
    public boolean isClear() {
      return sub == null;
    }
  }

  /**
   * The fixture reason code for a detection, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.D.source-display-divergence.<tag>}
   * scheme keyed by the sub-threat tag.
   */
  public static String reasonCode(Detection detection) {
    String sub = detection.sub();
    return sub == null ? null : "unicode.security.D." + FAMILY + "." + sub;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §2 Aggregation
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Aggregate the five constituent detectors into a single display-layer
   * verdict. The constituents are consulted in canonical order; their firing
   * tags are collected, then zero &rarr; clear, one &rarr; pass-through, two or
   * more &rarr; {@code Compound}.
   */
  public static Detection detect(List<Integer> input) {
    List<Integer> cps = List.copyOf(input);
    List<String> fires = new ArrayList<>();
    if (Security.tagBlockPayloadFired(cps)) fires.add("TagBlock");
    if (Security.variationSelectorPayloadFired(cps)) fires.add("VariationSelector");
    if (Security.zeroWidthPayloadFired(cps)) fires.add("ZeroWidth");
    if (Security.bidiControlBalanceFired(cps)) fires.add("BidiControl");
    if (Security.homoglyphConfusableFired(cps)) fires.add("IdentifierHomoglyph");

    return switch (fires.size()) {
      case 0 -> new Detection(null);
      case 1 -> new Detection(fires.get(0));
      default -> new Detection(COMPOUND);
    };
  }
}
