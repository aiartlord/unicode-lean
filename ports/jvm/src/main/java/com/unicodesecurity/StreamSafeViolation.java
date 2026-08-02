package com.unicodesecurity;

import java.util.ArrayList;
import java.util.List;

/**
 * Stream-Safe-Text-Format-violation detection — inputs whose consecutive
 * non-starter run exceeds the UAX #15 &sect;13 {@code streamSafeLimit} of 30.
 * Such an input (the canonical "Zalgo" shape, a single base codepoint followed
 * by a long combining-mark run) forces unbounded combining-mark buffers in
 * receiver-side streaming normalization ({@code toNFC} / {@code toNFD} /
 * {@code toNFKC} / {@code toNFKD}) and is a known DoS vector.
 *
 * <p>Direct port of {@code Unicode/Security/Form/StreamSafeViolation.lean},
 * transliterated byte-faithfully from the verified Rust reference
 * implementation. UAX #15
 * &sect;13 defines Stream-Safe Text Format as the remediation: insert U+034F
 * COMBINING GRAPHEME JOINER (a starter) after every 30 consecutive
 * non-starters, which bounds the normalization buffer. {@code
 * StreamSafeViolation} is the security verdict over the same property —
 * distinct from {@code RendererDivergence}'s {@code combiningStackOverflow}
 * (the cosmetic 4-mark threshold), this is the spec-mandated DoS-prevention
 * bound.
 *
 * <p>A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
 * (UAX #15 D49). This module reads CCC from the port's own bundled UCD table via
 * {@link Security#combiningClass}, never a host normalizer.
 *
 * <p>Sub-threat: {@code streamSafeOverrun (basePos, runLen)} — the first
 * non-starter run whose length exceeds {@code streamSafeLimit}. {@code basePos}
 * is the index of that run's first non-starter codepoint.
 */
public final class StreamSafeViolation {
  private StreamSafeViolation() {}

  /** UTS #39 / UAX #15 family key; the reason-code layer for this family is {@code F}. */
  public static final String FAMILY = "stream-safe-violation";

  // ───────────────────────────────────────────────────────────────────────
  // §1 Run inventory
  // ───────────────────────────────────────────────────────────────────────

  /**
   * UAX #15 &sect;13 Stream-Safe limit: the maximum number of consecutive
   * non-starters permitted before a COMBINING GRAPHEME JOINER must be inserted.
   */
  public static final int STREAM_SAFE_LIMIT = 30;

  /**
   * True iff {@code cp} is a non-starter — a codepoint with non-zero
   * Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0. Reads the
   * port's own CCC via {@link Security#combiningClass}, never {@code java.text}.
   */
  private static boolean isNonStarter(int cp) {
    return Security.combiningClass(cp) != 0;
  }

  /** A maximal non-starter run: its start index and its length. */
  private record Run(int start, int length) {}

  /**
   * Inventory of {@code (start, length)} for every maximal non-starter run in
   * {@code input}. Mirrors {@code collectRunsGo}: a run opens on the first
   * non-starter, its start index is fixed to that codepoint's absolute index,
   * and it closes (emitting its {@code (start, length)} pair) on the next
   * starter or at end of input.
   */
  private static List<Run> nonStarterRuns(List<Integer> input) {
    List<Run> runs = new ArrayList<>();
    Integer curStart = null;
    int curLen = 0;
    for (int i = 0; i < input.size(); i++) {
      if (isNonStarter(input.get(i))) {
        if (curStart == null) {
          curStart = i;
        }
        curLen += 1;
      } else {
        if (curStart != null) {
          runs.add(new Run(curStart, curLen));
        }
        curStart = null;
        curLen = 0;
      }
    }
    if (curStart != null) {
      runs.add(new Run(curStart, curLen));
    }
    return runs;
  }

  /**
   * First non-starter run whose length exceeds {@code STREAM_SAFE_LIMIT}, or
   * {@code null} when no run overruns.
   */
  private static Run firstOverrun(List<Integer> input) {
    for (Run run : nonStarterRuns(input)) {
      if (run.length() > STREAM_SAFE_LIMIT) {
        return run;
      }
    }
    return null;
  }

  /** Longest non-starter run length in {@code input}. */
  private static int maxRunLen(List<Integer> input) {
    int acc = 0;
    for (Run run : nonStarterRuns(input)) {
      if (run.length() > acc) {
        acc = run.length();
      }
    }
    return acc;
  }

  /** Number of distinct non-starter runs that exceed {@code STREAM_SAFE_LIMIT}. */
  private static int overrunCount(List<Integer> input) {
    int acc = 0;
    for (Run run : nonStarterRuns(input)) {
      if (run.length() > STREAM_SAFE_LIMIT) {
        acc += 1;
      }
    }
    return acc;
  }

  /** Total non-starter codepoints in {@code input} (sum of all run lengths). */
  private static int totalNonStarters(List<Integer> input) {
    int acc = 0;
    for (Run run : nonStarterRuns(input)) {
      acc += run.length();
    }
    return acc;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §2 Types
  // ───────────────────────────────────────────────────────────────────────

  /** Sub-threats this detector can fire. */
  public sealed interface SubThreat permits StreamSafeOverrun {
    /** Human-facing classification tag for this sub-threat. */
    String tag();
  }

  /**
   * The first non-starter run whose length exceeds {@code STREAM_SAFE_LIMIT}.
   * {@code basePos} is the index of the run's first non-starter codepoint;
   * {@code runLen} is the run's length.
   */
  public record StreamSafeOverrun(int basePos, int runLen) implements SubThreat {
    @Override
    public String tag() {
      return "StreamSafeOverrun";
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

  /** No non-starter run exceeds the Stream-Safe limit. */
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
   * A hazard was found: the sub-threat, its implicated positions, and any
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
   * Verdict — the structured output of {@link #detect}. The run-inventory
   * summaries ({@code maxRunLen}, {@code overrunCount}, {@code totalNonStarters})
   * are exposed so downstream callers can size the buffer pressure a streaming
   * normalizer would see.
   */
  public record Verdict(List<Integer> input, Classification classify,
                        int maxRunLen, int overrunCount, int totalNonStarters) {}

  /**
   * The fixture reason code for a classification, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.F.stream-safe-violation.<tag>}
   * scheme keyed by the sub-threat tag.
   */
  public static String reasonCode(Classification classify) {
    String tag = classify.tag();
    return tag == null ? null : "unicode.security.F." + FAMILY + "." + tag;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §3 Top-level detection
  // ───────────────────────────────────────────────────────────────────────

  /**
   * The detection function. Fires {@code StreamSafeOverrun} on the first
   * non-starter run whose length exceeds {@code STREAM_SAFE_LIMIT}.
   */
  public static Verdict detect(List<Integer> input) {
    Run overrun = firstOverrun(input);
    Classification classification;
    if (overrun != null) {
      classification = new Hazard(
          new StreamSafeOverrun(overrun.start(), overrun.length()),
          List.of(overrun.start()),
          List.of());
    } else {
      classification = new Clear();
    }
    return new Verdict(new ArrayList<>(input), classification,
        maxRunLen(input), overrunCount(input), totalNonStarters(input));
  }
}
