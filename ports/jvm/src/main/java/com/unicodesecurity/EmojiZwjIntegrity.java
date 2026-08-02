package com.unicodesecurity;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * emoji-zwj-integrity — identity-layer detector I3 for malformed / unsanctioned
 * emoji ZWJ-sequence shapes per UTS #51. Answers the question: does this
 * emoji-shaped codepoint sequence carry a {@code U+200D} ZERO WIDTH JOINER in a
 * shape that departs from the sanctioned RGI ZWJ-sequence set, and if so, how?
 *
 * <p>Direct port of {@code Unicode/Security/Identity/EmojiZwjIntegrity.lean},
 * transliterated byte-faithfully from the verified Rust reference
 * implementation.
 *
 * <p>Threat model. An adversary crafts an emoji-shaped codepoint sequence
 * containing one or more {@code U+200D} ZERO WIDTH JOINERs but violating the
 * sanctioned RGI ZWJ-sequence shape — by exceeding the RGI length cap, by
 * joining a non-emoji codepoint, by emitting adjacent ZWJ pairs, or by
 * overflowing the skin-tone count. Any non-RGI ZWJ-containing sequence is
 * renderer-dependent, and that renderer divergence is the attack surface.
 *
 * <p>Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
 * {@code emoji-zwj-sequences.txt}, bundled in the port's own SHA-pinned
 * {@code data/emoji-zwj-sequences.txt} and parsed via the port's own
 * {@link Security#readResource} loader (never a host emoji library, never
 * String normalization). The registered set gives both the exact-match
 * membership test ({@link #isRegisteredZwjSequence}) and the ZWJ <em>alphabet</em>
 * — every distinct codepoint occurring at any position of any registered
 * sequence, excluding the joiner — which is the canonical "what may flank a
 * ZWJ?" predicate.
 *
 * <p>Algorithm (one pass over {@code input}).
 * <ol>
 *   <li>Phase 1 — collect ZWJ positions and the skin-tone count.</li>
 *   <li>Phase 2 — short-circuit {@code Clear} if there are no ZWJs and the
 *       skin-tone count is at most 1.</li>
 *   <li>Phase 3 — a registered RGI sequence is always {@code Clear}.</li>
 *   <li>Phase 4 — check sub-threats by priority: {@code DoubleZWJ},
 *       {@code NonEmojiInjection}, {@code OverLength}, {@code SkinToneOverflow},
 *       {@code UnregisteredSequence}.</li>
 * </ol>
 */
public final class EmojiZwjIntegrity {
  private EmojiZwjIntegrity() {}

  /** UTS #39 family key; the reason-code layer for this family is {@code I}. */
  public static final String FAMILY = "emoji-zwj-integrity";

  // ───────────────────────────────────────────────────────────────────────
  // §1 Constants
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Conservative cap on the length of a sanctioned RGI ZWJ sequence
   * ({@code maxRgiLength} in the Lean spec). The longest current entry (a
   * four-person family with skin tones) reaches ~13-14 codepoints; 16 is a safe
   * upper bound.
   */
  public static final int MAX_RGI_LENGTH = 16;

  /** The ZERO WIDTH JOINER codepoint. */
  public static final int ZWJ = 0x200D;

  // ───────────────────────────────────────────────────────────────────────
  // §2 Types
  // ───────────────────────────────────────────────────────────────────────

  /** Sub-threats this detector can fire, in priority order. */
  public sealed interface SubThreat
      permits DoubleZwj, NonEmojiInjection, OverLength, SkinToneOverflow, UnregisteredSequence {
    /** Fixture-row tag string for this sub-threat (matches {@code SubThreat.tag}). */
    String tag();
  }

  /** ZWJ-ZWJ adjacency; {@code positions} are the first ZWJ of each adjacent pair. */
  public record DoubleZwj(List<Integer> positions) implements SubThreat {
    @Override
    public String tag() {
      return "DoubleZWJ";
    }
  }

  /**
   * A ZWJ flanked by a non-emoji codepoint (or sitting at an input edge).
   * {@code zwjPos} is the offending ZWJ position; {@code nonEmojiCp} is the
   * non-emoji codepoint that flanks it (0 for an edge ZWJ).
   */
  public record NonEmojiInjection(int zwjPos, int nonEmojiCp) implements SubThreat {
    @Override
    public String tag() {
      return "NonEmojiInjection";
    }
  }

  /**
   * The sequence is longer than {@link #MAX_RGI_LENGTH}. {@code length} is the
   * observed sequence length; {@code maxLength} is the cap that was exceeded.
   */
  public record OverLength(int length, int maxLength) implements SubThreat {
    @Override
    public String tag() {
      return "OverLength";
    }
  }

  /**
   * Five or more skin-tone modifiers (the family-emoji maximum is four).
   * {@code count} is the observed skin-tone modifier count.
   */
  public record SkinToneOverflow(int count) implements SubThreat {
    @Override
    public String tag() {
      return "SkinToneOverflow";
    }
  }

  /**
   * ZWJs are present and no other sub-threat matched, but the sequence is not a
   * registered RGI ZWJ sequence. {@code chainLen} is the length of the
   * unregistered ZWJ chain.
   */
  public record UnregisteredSequence(int chainLen) implements SubThreat {
    @Override
    public String tag() {
      return "UnregisteredSequence";
    }
  }

  /** Top-level classification for EmojiZwjIntegrity. */
  public sealed interface Classification permits Clear, Hazard {
    /** True iff the classification is {@code Clear}. */
    boolean isClear();

    /** Human-facing tag for a hazard, or {@code null} when clear. */
    String tag();

    /** Implicated positions (empty when clear). */
    List<Integer> positions();
  }

  /** A well-formed or non-ZWJ input. */
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
   * A hazard: the fired sub-threat, the implicated positions, and the
   * (always-empty for this detector) decoded-byte projection — kept for shape
   * parity with the Lean {@code Classification.hazard}.
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

  /** The structured output of {@link #detect} (mirrors the Lean {@code Verdict}). */
  public record Verdict(
      List<Integer> input,
      Classification classify,
      List<Integer> zwjPositions,
      int chainLength,
      boolean isRegisteredRgi,
      int skinToneCount) {}

  /**
   * The fixture reason code for a classification, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.I.emoji-zwj-integrity.<tag>}
   * scheme keyed by the sub-threat tag.
   */
  public static String reasonCode(Classification classify) {
    String tag = classify.tag();
    return tag == null ? null : "unicode.security.I." + FAMILY + "." + tag;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §3 RGI ZWJ-sequence data (bundled data/emoji-zwj-sequences.txt)
  // ───────────────────────────────────────────────────────────────────────

  private static volatile List<List<Integer>> zwjSequences;
  private static volatile Set<Integer> zwjAlphabet;

  /**
   * Parse the registered RGI ZWJ sequences from {@code emoji-zwj-sequences.txt}.
   * Each non-comment row is {@code <cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ;
   * <desc> # <cmt>}; the codepoint list is the field before the first {@code ;}.
   * The raw bytes are served by the port's SHA-pinned {@link Security#readResource}.
   */
  private static List<List<Integer>> parseZwjSequences() {
    List<List<Integer>> out = new ArrayList<>();
    String raw = Security.readResource("emoji-zwj-sequences.txt");
    for (String rawLine : raw.split("\n", -1)) {
      int hash = rawLine.indexOf('#');
      String body = hash >= 0 ? rawLine.substring(0, hash) : rawLine;
      String stripped = body.trim();
      if (stripped.isEmpty()) {
        continue;
      }
      int semi = stripped.indexOf(';');
      String seqField = semi >= 0 ? stripped.substring(0, semi) : stripped;
      List<Integer> seq = new ArrayList<>();
      boolean parsedOk = true;
      for (String token : seqField.trim().split("\\s+")) {
        if (token.isEmpty()) {
          continue;
        }
        Integer cp = parseHex(token);
        if (cp == null) {
          parsedOk = false;
          break;
        }
        seq.add(cp);
      }
      if (parsedOk && !seq.isEmpty()) {
        out.add(seq);
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

  private static List<List<Integer>> zwjSequences() {
    List<List<Integer>> local = zwjSequences;
    if (local == null) {
      synchronized (EmojiZwjIntegrity.class) {
        local = zwjSequences;
        if (local == null) {
          local = parseZwjSequences();
          zwjSequences = local;
        }
      }
    }
    return local;
  }

  /**
   * The ZWJ alphabet: every distinct codepoint occurring at any position of any
   * registered RGI ZWJ sequence, excluding the joiner U+200D itself.
   */
  private static Set<Integer> buildZwjAlphabet() {
    Set<Integer> set = new HashSet<>();
    for (List<Integer> seq : zwjSequences()) {
      for (int cp : seq) {
        if (cp != ZWJ) {
          set.add(cp);
        }
      }
    }
    return set;
  }

  private static Set<Integer> zwjAlphabet() {
    Set<Integer> local = zwjAlphabet;
    if (local == null) {
      synchronized (EmojiZwjIntegrity.class) {
        local = zwjAlphabet;
        if (local == null) {
          local = buildZwjAlphabet();
          zwjAlphabet = local;
        }
      }
    }
    return local;
  }

  /** True iff {@code cps} is exactly a registered RGI ZWJ sequence. */
  public static boolean isRegisteredZwjSequence(List<Integer> cps) {
    for (List<Integer> seq : zwjSequences()) {
      if (seq.equals(cps)) {
        return true;
      }
    }
    return false;
  }

  /**
   * True iff {@code cp} appears at some position of a registered RGI ZWJ
   * sequence (the canonical "what may flank a ZWJ?" predicate).
   */
  public static boolean isEmojiTarget(int cp) {
    return zwjAlphabet().contains(cp);
  }

  // ───────────────────────────────────────────────────────────────────────
  // §4 Core predicates
  // ───────────────────────────────────────────────────────────────────────

  /** True iff {@code cp} is the ZWJ codepoint. */
  public static boolean isZwj(int cp) {
    return cp == ZWJ;
  }

  /** True iff {@code cp} is an emoji skin-tone modifier (U+1F3FB..U+1F3FF). */
  public static boolean isEmojiModifier(int cp) {
    return cp >= 0x1F3FB && cp <= 0x1F3FF;
  }

  /** Positions of every ZWJ in {@code input}. */
  private static List<Integer> zwjPositions(List<Integer> input) {
    List<Integer> out = new ArrayList<>();
    for (int i = 0; i < input.size(); i++) {
      if (isZwj(input.get(i))) {
        out.add(i);
      }
    }
    return out;
  }

  /** Count of skin-tone modifier codepoints. */
  private static int skinToneCount(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (isEmojiModifier(cp)) {
        count++;
      }
    }
    return count;
  }

  /** Positions of the first ZWJ in each ZWJ-ZWJ adjacent pair. */
  private static List<Integer> doubleZwjPositions(List<Integer> input) {
    List<Integer> out = new ArrayList<>();
    for (int idx = 0; idx < input.size(); idx++) {
      int cp = input.get(idx);
      if (idx + 1 < input.size()) {
        int nextCp = input.get(idx + 1);
        if (isZwj(cp) && isZwj(nextCp)) {
          out.add(idx);
        }
      }
    }
    return out;
  }

  /** {@code (zwjPos, offendingCp)} of a non-emoji injection, or null. */
  private record Injection(int zwjPos, int nonEmojiCp) {}

  /**
   * The first ZWJ position where either neighbour is a non-emoji codepoint, as
   * {@code (zwjPos, offendingCp)}. A ZWJ at an input edge (no preceding or no
   * following codepoint) is itself an injection-class hazard, reported with
   * offending codepoint 0.
   */
  private static Injection firstNonEmojiInjection(List<Integer> input) {
    for (int idx = 0; idx < input.size(); idx++) {
      if (!isZwj(input.get(idx))) {
        continue;
      }
      boolean hasPrev = idx != 0;
      boolean hasNext = idx + 1 < input.size();
      if (hasPrev && hasNext) {
        int prevCp = input.get(idx - 1);
        int nextCp = input.get(idx + 1);
        if (!isEmojiTarget(prevCp)) {
          return new Injection(idx, prevCp);
        } else if (!isEmojiTarget(nextCp)) {
          return new Injection(idx, nextCp);
        }
      } else {
        // No preceding OR no following codepoint: an edge ZWJ.
        return new Injection(idx, 0);
      }
    }
    return null;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §5 Top-level detection
  // ───────────────────────────────────────────────────────────────────────

  /** The EmojiZwjIntegrity detection function. */
  public static Verdict detect(List<Integer> input) {
    List<Integer> zwjs = zwjPositions(input);
    int stCount = skinToneCount(input);
    boolean isRgi = isRegisteredZwjSequence(input);
    int chainLen = zwjs.isEmpty() ? 0 : input.size();

    if (zwjs.isEmpty() && stCount <= 1) {
      return new Verdict(new ArrayList<>(input), new Clear(), new ArrayList<>(), 0, isRgi, stCount);
    }

    Classification classification;
    if (isRgi) {
      // Phase 3: a registered RGI sequence is always clear.
      classification = new Clear();
    } else {
      // Phase 4.1: ZWJ-ZWJ adjacency.
      List<Integer> dzwj = doubleZwjPositions(input);
      if (!dzwj.isEmpty()) {
        classification = new Hazard(new DoubleZwj(new ArrayList<>(dzwj)), dzwj, List.of());
      } else {
        // Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
        Injection injection = firstNonEmojiInjection(input);
        if (injection != null) {
          List<Integer> positions = new ArrayList<>();
          positions.add(injection.zwjPos());
          classification =
              new Hazard(
                  new NonEmojiInjection(injection.zwjPos(), injection.nonEmojiCp()),
                  positions,
                  List.of());
        } else if (input.size() > MAX_RGI_LENGTH) {
          // Phase 4.3: length cap.
          classification =
              new Hazard(new OverLength(input.size(), MAX_RGI_LENGTH), new ArrayList<>(), List.of());
        } else if (stCount >= 5) {
          // Phase 4.4: skin-tone overflow.
          classification = new Hazard(new SkinToneOverflow(stCount), new ArrayList<>(), List.of());
        } else if (!zwjs.isEmpty()) {
          // Phase 4.5: catch-all for unregistered ZWJ sequences.
          classification =
              new Hazard(new UnregisteredSequence(input.size()), new ArrayList<>(zwjs), List.of());
        } else {
          classification = new Clear();
        }
      }
    }

    return new Verdict(new ArrayList<>(input), classification, zwjs, chainLen, isRgi, stCount);
  }
}
