package com.unicodesecurity;

import java.util.ArrayList;
import java.util.List;

/**
 * skin-tone-variation-forgery — identity-layer detector for skin-tone modifier
 * and variation-selector abuse on emoji bases per UTS #51. Answers the question:
 * does this codepoint sequence place a skin-tone modifier on a codepoint that
 * cannot bear one, stack multiple skin tones on a single base, or force a
 * text-style render on an emoji-default codepoint?
 *
 * <p>Direct port of {@code Unicode/Security/Identity/SkinToneVariationForgery.lean},
 * transliterated byte-faithfully from the verified Rust reference implementation.
 *
 * <p>Threat model. An adversary places a skin-tone modifier on a codepoint that
 * does NOT bear {@code Emoji_Modifier_Base}, stacks multiple skin tones on one
 * base, or forces a text-style render on an emoji-default codepoint via
 * {@code U+FE0E} (VS15) — sometimes to hide a payload-bearing glyph in plain
 * sight. Distinct from a pair-aligned variation-selector payload run that decodes
 * to bytes: this catches the orthogonal case of <em>semantic</em> variation-selector
 * / skin-tone misuse on a single base.
 *
 * <p>Emoji property data. The skin-tone modifier predicate reuses the port's own
 * {@link EmojiZwjIntegrity#isEmojiModifier} (the {@code U+1F3FB..U+1F3FF} set).
 * The {@code Emoji_Modifier_Base} and {@code Emoji_Presentation} property rows are
 * parsed from the port's already-bundled SHA-pinned {@code data/emoji-data.txt}
 * via the port's own {@link Security#readResource} loader (the same file the
 * {@link AiWatermarkDetectability} probe reads its {@code Emoji} rows from), never
 * a host emoji library and never String normalization.
 *
 * <p>Sub-threats (priority order, first match wins):
 * <ol>
 *   <li>{@code StackedSkinTones}      — a base immediately followed by &ge; 2 skin-tone modifiers.</li>
 *   <li>{@code InvalidSkinToneTarget} — a skin-tone modifier on a non-{@code Emoji_Modifier_Base}.</li>
 *   <li>{@code ForcedTextStyle}       — {@code U+FE0E} on an {@code Emoji_Presentation} codepoint.</li>
 * </ol>
 */
public final class SkinToneVariationForgery {
  private SkinToneVariationForgery() {}

  /** UTS #39 family key; the reason-code layer for this family is {@code I}. */
  public static final String FAMILY = "skin-tone-variation-forgery";

  /** The text-style variation selector VS15. */
  public static final int VS15 = 0xFE0E;

  /** The emoji-style variation selector VS16. */
  public static final int VS16 = 0xFE0F;

  // ───────────────────────────────────────────────────────────────────────
  // §1 Types
  // ───────────────────────────────────────────────────────────────────────

  /** Sub-threats this detector can fire, in priority order. */
  public sealed interface SubThreat
      permits StackedSkinTones, InvalidSkinToneTarget, ForcedTextStyle {
    /** Fixture-row tag string for this sub-threat (matches {@code SubThreat.tag}). */
    String tag();
  }

  /**
   * A base at {@code basePos} followed by &ge; 2 skin-tone modifiers.
   * {@code modifiers} carries the first two stacked skin-tone modifiers.
   */
  public record StackedSkinTones(int basePos, List<Integer> modifiers) implements SubThreat {
    @Override
    public String tag() {
      return "StackedSkinTones";
    }
  }

  /**
   * A skin-tone {@code modifierCp} at {@code basePos + 1} on a non-modifier-base
   * {@code baseCp}.
   */
  public record InvalidSkinToneTarget(int basePos, int baseCp, int modifierCp) implements SubThreat {
    @Override
    public String tag() {
      return "InvalidSkinToneTarget";
    }
  }

  /**
   * A {@code U+FE0E} at {@code basePos + 1} forcing text style on an
   * {@code Emoji_Presentation} {@code baseCp}.
   */
  public record ForcedTextStyle(int basePos, int baseCp) implements SubThreat {
    @Override
    public String tag() {
      return "ForcedTextStyle";
    }
  }

  /** Top-level classification for SkinToneVariationForgery. */
  public sealed interface Classification permits Clear, Hazard {
    /** True iff the classification is {@code Clear}. */
    boolean isClear();

    /** Human-facing tag for a hazard, or {@code null} when clear. */
    String tag();

    /** Implicated positions (empty when clear). */
    List<Integer> positions();
  }

  /** No skin-tone / variation-selector abuse present. */
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
      int skinToneCount,
      int variationSelector15Count,
      int variationSelector16Count) {}

  /**
   * The fixture reason code for a classification, or {@code null} when clear.
   * Mirrors the shared {@code unicode.security.I.skin-tone-variation-forgery.<tag>}
   * scheme keyed by the sub-threat tag.
   */
  public static String reasonCode(Classification classify) {
    String tag = classify.tag();
    return tag == null ? null : "unicode.security.I." + FAMILY + "." + tag;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §2 Emoji property tables (bundled data/emoji-data.txt)
  // ───────────────────────────────────────────────────────────────────────

  private static volatile List<int[]> emojiModifierBaseRanges;
  private static volatile List<int[]> emojiPresentationRanges;

  /**
   * Parse the closed intervals for a single emoji property from emoji-data.txt.
   * Each non-comment row is {@code <range> ; <property> # <comment>}; only rows
   * whose property field is exactly {@code property} are kept. The raw bytes are
   * served by the port's SHA-pinned {@link Security#readResource}.
   */
  private static List<int[]> parseEmojiProperty(String property) {
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
      if (!fields[1].trim().equals(property)) {
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

  private static List<int[]> emojiModifierBaseRanges() {
    List<int[]> local = emojiModifierBaseRanges;
    if (local == null) {
      synchronized (SkinToneVariationForgery.class) {
        local = emojiModifierBaseRanges;
        if (local == null) {
          local = parseEmojiProperty("Emoji_Modifier_Base");
          emojiModifierBaseRanges = local;
        }
      }
    }
    return local;
  }

  private static List<int[]> emojiPresentationRanges() {
    List<int[]> local = emojiPresentationRanges;
    if (local == null) {
      synchronized (SkinToneVariationForgery.class) {
        local = emojiPresentationRanges;
        if (local == null) {
          local = parseEmojiProperty("Emoji_Presentation");
          emojiPresentationRanges = local;
        }
      }
    }
    return local;
  }

  private static boolean inRanges(List<int[]> ranges, int cp) {
    for (int[] range : ranges) {
      if (range[0] <= cp && cp <= range[1]) {
        return true;
      }
    }
    return false;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §3 Core predicates
  // ───────────────────────────────────────────────────────────────────────

  /**
   * True iff {@code cp} is an emoji skin-tone modifier. Reuses the port's own
   * {@link EmojiZwjIntegrity#isEmojiModifier} ({@code U+1F3FB..U+1F3FF}).
   */
  public static boolean isSkinTone(int cp) {
    return EmojiZwjIntegrity.isEmojiModifier(cp);
  }

  /** True iff {@code cp} has {@code Emoji_Modifier_Base} per emoji-data.txt. */
  public static boolean isSkinToneBase(int cp) {
    return inRanges(emojiModifierBaseRanges(), cp);
  }

  /** True iff {@code cp} has {@code Emoji_Presentation} per emoji-data.txt. */
  public static boolean isEmojiPresentation(int cp) {
    return inRanges(emojiPresentationRanges(), cp);
  }

  /** True iff {@code cp} is {@code U+FE0E} (VS15, text-style variation selector). */
  public static boolean isVs15(int cp) {
    return cp == VS15;
  }

  /** True iff {@code cp} is {@code U+FE0F} (VS16, emoji-style variation selector). */
  public static boolean isVs16(int cp) {
    return cp == VS16;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §4 Sub-detectors
  // ───────────────────────────────────────────────────────────────────────

  /**
   * First position whose next two codepoints are both skin-tone modifiers, as a
   * {@link StackedSkinTones} with {@code base_pos} and the first two modifiers, or
   * {@code null} when none exists.
   */
  private static StackedSkinTones firstStackedSkinTones(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      if (i + 2 < input.size()) {
        int m1 = input.get(i + 1);
        int m2 = input.get(i + 2);
        if (isSkinTone(m1) && isSkinTone(m2)) {
          List<Integer> modifiers = new ArrayList<>();
          modifiers.add(m1);
          modifiers.add(m2);
          return new StackedSkinTones(i, modifiers);
        }
      }
    }
    return null;
  }

  /**
   * First skin-tone modifier whose preceding codepoint is NOT
   * {@code Emoji_Modifier_Base}, as an {@link InvalidSkinToneTarget}, or
   * {@code null} when none exists.
   */
  private static InvalidSkinToneTarget firstInvalidSkinToneTarget(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      if (i + 1 < input.size()) {
        int cp = input.get(i + 1);
        if (isSkinTone(cp) && !isSkinToneBase(input.get(i))) {
          return new InvalidSkinToneTarget(i, input.get(i), cp);
        }
      }
    }
    return null;
  }

  /**
   * First {@code U+FE0E} whose preceding codepoint has {@code Emoji_Presentation},
   * as a {@link ForcedTextStyle}, or {@code null} when none exists.
   */
  private static ForcedTextStyle firstForcedTextStyle(List<Integer> input) {
    for (int i = 0; i < input.size(); i++) {
      if (i + 1 < input.size()) {
        int cp = input.get(i + 1);
        if (isVs15(cp) && isEmojiPresentation(input.get(i))) {
          return new ForcedTextStyle(i, input.get(i));
        }
      }
    }
    return null;
  }

  private static int skinToneCount(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (isSkinTone(cp)) {
        count++;
      }
    }
    return count;
  }

  private static int vs15Count(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (isVs15(cp)) {
        count++;
      }
    }
    return count;
  }

  private static int vs16Count(List<Integer> input) {
    int count = 0;
    for (int cp : input) {
      if (isVs16(cp)) {
        count++;
      }
    }
    return count;
  }

  // ───────────────────────────────────────────────────────────────────────
  // §5 Top-level detection
  // ───────────────────────────────────────────────────────────────────────

  /** The SkinToneVariationForgery detection function. */
  public static Verdict detect(List<Integer> input) {
    int stc = skinToneCount(input);
    int v15 = vs15Count(input);
    int v16 = vs16Count(input);

    Classification classification;
    StackedSkinTones stacked = firstStackedSkinTones(input);
    if (stacked != null) {
      // Priority 1: a base followed by two stacked skin tones.
      List<Integer> positions = new ArrayList<>();
      for (int i = 0; i < stacked.modifiers().size(); i++) {
        positions.add(stacked.basePos() + 1 + i);
      }
      classification = new Hazard(stacked, positions, List.of());
    } else {
      InvalidSkinToneTarget invalid = firstInvalidSkinToneTarget(input);
      if (invalid != null) {
        // Priority 2: a skin tone on a non-modifier-base.
        List<Integer> positions = new ArrayList<>();
        positions.add(invalid.basePos() + 1);
        classification = new Hazard(invalid, positions, List.of());
      } else {
        ForcedTextStyle forced = firstForcedTextStyle(input);
        if (forced != null) {
          // Priority 3: VS15 forcing text style on an emoji-presentation cp.
          List<Integer> positions = new ArrayList<>();
          positions.add(forced.basePos() + 1);
          classification = new Hazard(forced, positions, List.of());
        } else {
          classification = new Clear();
        }
      }
    }

    return new Verdict(new ArrayList<>(input), classification, stc, v15, v16);
  }
}
