<?php

declare(strict_types=1);

// SkinToneVariationForgery — skin-tone modifier and variation-selector abuse on
// emoji bases per UTS #51 (the identity-layer detector).
//
// Byte-faithful port of the verified rust reference implementation and of
// `Unicode/Security/Identity/SkinToneVariationForgery.lean`.
//
// Threat model. Tier A1. An adversary places a skin-tone modifier on a codepoint
// that does NOT bear Emoji_Modifier_Base, stacks multiple skin-tones on one base,
// or forces a text-style render on an emoji-default codepoint via U+FE0E (VS15) —
// sometimes to hide a payload-bearing glyph in plain sight.
//
// Distinct from VariationSelectorPayload (pair-aligned VS runs that decode to
// bytes): this catches the orthogonal case of *semantic* VS / skin-tone misuse on
// a single base. Both can fire on the same input; SourceDisplayDivergence
// aggregates.
//
// It reuses the port's own emoji property tables (the bundled emoji-data.txt),
// never a host emoji library. The skin-tone modifier predicate is the port's own
// EmojiZwjIntegrity::isEmojiModifier (U+1F3FB..U+1F3FF); the Emoji_Modifier_Base
// and Emoji_Presentation predicates parse the already-bundled emoji-data.txt with
// the port's own interval-parsing idiom.
//
// Sub-threats (priority order):
//   1. StackedSkinTones      a base immediately followed by >= 2 skin-tone modifiers.
//   2. InvalidSkinToneTarget a skin-tone modifier on a non-Emoji_Modifier_Base.
//   3. ForcedTextStyle       U+FE0E on an Emoji_Presentation codepoint.
//
// PHP has no module system, so the support types the rust reference keeps in a
// dedicated module (SubThreat, Classification, Verdict) are carried here under a
// `SkinToneVariationForgery` class-name prefix — the identity namespace already
// binds bare names for the sibling homoglyph / emoji-zwj detectors' helpers. The
// tag strings, variant order, and priority all mirror the reference exactly.

namespace UnicodePhp\Security\Identity;

use UnicodePhp\Data;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/**
 * A sub-threat this detector can fire, in priority order. Each variant carries
 * only the payload the rust reference records for it; the unused payload fields
 * are null. The tag is the human-facing classification string, mirrored verbatim
 * from the rust reference.
 */
final class SkinToneVariationForgerySubThreat
{
    /**
     * @param list<int>|null $modifiers The first two stacked skin-tone modifiers (StackedSkinTones only).
     */
    private function __construct(
        public readonly string $kind,
        public readonly int $basePos,
        public readonly ?array $modifiers,
        public readonly ?int $baseCp,
        public readonly ?int $modifierCp,
    ) {
    }

    /**
     * A base at $basePos followed by >= 2 skin-tone modifiers ($modifiers holds
     * the first two).
     *
     * @param list<int> $modifiers
     */
    public static function stackedSkinTones(int $basePos, array $modifiers): SkinToneVariationForgerySubThreat
    {
        return new SkinToneVariationForgerySubThreat('StackedSkinTones', $basePos, $modifiers, null, null);
    }

    /**
     * A skin-tone $modifierCp at $basePos + 1 on a non-modifier-base $baseCp.
     */
    public static function invalidSkinToneTarget(int $basePos, int $baseCp, int $modifierCp): SkinToneVariationForgerySubThreat
    {
        return new SkinToneVariationForgerySubThreat('InvalidSkinToneTarget', $basePos, null, $baseCp, $modifierCp);
    }

    /**
     * A U+FE0E at $basePos + 1 forcing text-style on an Emoji_Presentation $baseCp.
     */
    public static function forcedTextStyle(int $basePos, int $baseCp): SkinToneVariationForgerySubThreat
    {
        return new SkinToneVariationForgerySubThreat('ForcedTextStyle', $basePos, null, $baseCp, null);
    }

    /** Fixture-row / wire tag string for this sub-threat (matches `SubThreat.tag`). */
    public function tag(): string
    {
        return match ($this->kind) {
            'StackedSkinTones' => 'StackedSkinTones',
            'InvalidSkinToneTarget' => 'InvalidSkinToneTarget',
            'ForcedTextStyle' => 'ForcedTextStyle',
            default => throw new \RuntimeException("SkinToneVariationForgerySubThreat: unknown kind '{$this->kind}'"),
        };
    }
}

/**
 * Top-level classification for SkinToneVariationForgery: Clear, or a Hazard
 * carrying the fired sub-threat, the implicated positions, and the (always-empty
 * for this detector) decoded-byte projection kept for shape parity with the Lean
 * `Classification.hazard`.
 */
final class SkinToneVariationForgeryClassification
{
    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    private function __construct(
        public readonly ?SkinToneVariationForgerySubThreat $sub,
        public readonly array $positions,
        public readonly array $decoded,
    ) {
    }

    public static function clear(): SkinToneVariationForgeryClassification
    {
        return new SkinToneVariationForgeryClassification(null, [], []);
    }

    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    public static function hazard(SkinToneVariationForgerySubThreat $sub, array $positions, array $decoded): SkinToneVariationForgeryClassification
    {
        return new SkinToneVariationForgeryClassification($sub, $positions, $decoded);
    }

    /** True iff the classification is Clear. */
    public function isClear(): bool
    {
        return $this->sub === null;
    }

    /** Human-facing tag for a hazard, or null when clear. */
    public function tag(): ?string
    {
        return $this->sub?->tag();
    }

    /** @return list<int> Implicated positions (empty when clear). */
    public function positions(): array
    {
        return $this->positions;
    }
}

/**
 * The structured output of `detect` (mirrors the Lean `Verdict`). $skinToneCount
 * counts skin-tone modifier codepoints; $variationSelector15Count counts U+FE0E;
 * $variationSelector16Count counts U+FE0F.
 */
final class SkinToneVariationForgeryVerdict
{
    /**
     * @param list<int> $input
     */
    public function __construct(
        public readonly array $input,
        public readonly SkinToneVariationForgeryClassification $classify,
        public readonly int $skinToneCount,
        public readonly int $variationSelector15Count,
        public readonly int $variationSelector16Count,
    ) {
    }
}

final class SkinToneVariationForgery
{
    /** @var list<array{0:int,1:int}>|null Cached Emoji_Modifier_Base closed intervals. */
    private static ?array $modifierBaseRanges = null;

    /** @var list<array{0:int,1:int}>|null Cached Emoji_Presentation closed intervals. */
    private static ?array $presentationRanges = null;

    // ─────────────────────────────────────────────────────────────────
    // §2 Core predicates (reuse the port's own emoji tables)
    // ─────────────────────────────────────────────────────────────────

    /**
     * Parse the closed intervals for a single emoji property from emoji-data.txt.
     * Each non-comment row is `<range> ; <property> # <comment>`; we keep only
     * rows whose property field matches $property exactly. Mirrors the port's own
     * emoji-data.txt interval parser (as used for the Emoji rows elsewhere).
     *
     * @return list<array{0:int,1:int}>
     */
    private static function parseEmojiProperty(string $property): array
    {
        $out = [];
        foreach (Data::lines('emoji-data.txt') as $rawLine) {
            $hash = strpos($rawLine, '#');
            $body = $hash === false ? $rawLine : substr($rawLine, 0, $hash);
            $stripped = trim($body);
            if ($stripped === '') {
                continue;
            }
            $fields = explode(';', $stripped);
            if (count($fields) < 2) {
                continue;
            }
            if (trim($fields[1]) !== $property) {
                continue;
            }
            $range = trim($fields[0]);
            $dots = strpos($range, '..');
            if ($dots !== false) {
                $lo = self::parseHex(substr($range, 0, $dots));
                $hi = self::parseHex(substr($range, $dots + 2));
            } else {
                $lo = self::parseHex($range);
                $hi = $lo;
            }
            if ($lo === null || $hi === null) {
                continue;
            }
            $out[] = [$lo, $hi];
        }
        return $out;
    }

    /** Parse a trimmed hexadecimal codepoint field, or null if malformed. */
    private static function parseHex(string $s): ?int
    {
        $s = trim($s);
        if ($s === '' || !ctype_xdigit($s)) {
            return null;
        }
        return intval($s, 16);
    }

    /** @return list<array{0:int,1:int}> */
    private static function modifierBaseRanges(): array
    {
        if (self::$modifierBaseRanges === null) {
            self::$modifierBaseRanges = self::parseEmojiProperty('Emoji_Modifier_Base');
        }
        return self::$modifierBaseRanges;
    }

    /** @return list<array{0:int,1:int}> */
    private static function presentationRanges(): array
    {
        if (self::$presentationRanges === null) {
            self::$presentationRanges = self::parseEmojiProperty('Emoji_Presentation');
        }
        return self::$presentationRanges;
    }

    /** True iff $cp is an emoji skin-tone modifier (reuses the port's own predicate). */
    public static function isSkinTone(int $cp): bool
    {
        return EmojiZwjIntegrity::isEmojiModifier($cp);
    }

    /** True iff $cp has Emoji_Modifier_Base per emoji-data.txt. */
    public static function isSkinToneBase(int $cp): bool
    {
        foreach (self::modifierBaseRanges() as [$lo, $hi]) {
            if ($lo <= $cp && $cp <= $hi) {
                return true;
            }
        }
        return false;
    }

    /** True iff $cp has Emoji_Presentation per emoji-data.txt. */
    public static function isEmojiPresentation(int $cp): bool
    {
        foreach (self::presentationRanges() as [$lo, $hi]) {
            if ($lo <= $cp && $cp <= $hi) {
                return true;
            }
        }
        return false;
    }

    /** True iff $cp is U+FE0E (VS15, text-style variation selector). */
    public static function isVs15(int $cp): bool
    {
        return $cp === 0xFE0E;
    }

    /** True iff $cp is U+FE0F (VS16, emoji-style variation selector). */
    public static function isVs16(int $cp): bool
    {
        return $cp === 0xFE0F;
    }

    // ─────────────────────────────────────────────────────────────────
    // §3 Sub-detectors
    // ─────────────────────────────────────────────────────────────────

    /**
     * First position $i whose next two codepoints are both skin-tone modifiers, as
     * `[$basePos, [$mod1, $mod2]]`, or null when none.
     *
     * @param list<int> $input
     * @return array{0:int,1:list<int>}|null
     */
    private static function firstStackedSkinTones(array $input): ?array
    {
        $len = count($input);
        for ($i = 0; $i < $len; $i++) {
            if ($i + 2 >= $len) {
                continue;
            }
            $m1 = $input[$i + 1];
            $m2 = $input[$i + 2];
            if (self::isSkinTone($m1) && self::isSkinTone($m2)) {
                return [$i, [$m1, $m2]];
            }
        }
        return null;
    }

    /**
     * First skin-tone modifier whose preceding codepoint is NOT Emoji_Modifier_Base,
     * as `[$basePos, $baseCp, $modifierCp]`, or null when none.
     *
     * @param list<int> $input
     * @return array{0:int,1:int,2:int}|null
     */
    private static function firstInvalidSkinToneTarget(array $input): ?array
    {
        $len = count($input);
        for ($i = 0; $i < $len; $i++) {
            if ($i + 1 >= $len) {
                continue;
            }
            $cp = $input[$i + 1];
            if (self::isSkinTone($cp) && !self::isSkinToneBase($input[$i])) {
                return [$i, $input[$i], $cp];
            }
        }
        return null;
    }

    /**
     * First U+FE0E whose preceding codepoint has Emoji_Presentation, as
     * `[$basePos, $baseCp]`, or null when none.
     *
     * @param list<int> $input
     * @return array{0:int,1:int}|null
     */
    private static function firstForcedTextStyle(array $input): ?array
    {
        $len = count($input);
        for ($i = 0; $i < $len; $i++) {
            if ($i + 1 >= $len) {
                continue;
            }
            $cp = $input[$i + 1];
            if (self::isVs15($cp) && self::isEmojiPresentation($input[$i])) {
                return [$i, $input[$i]];
            }
        }
        return null;
    }

    /**
     * Count of skin-tone modifier codepoints.
     *
     * @param list<int> $input
     */
    private static function skinToneCount(array $input): int
    {
        $count = 0;
        foreach ($input as $cp) {
            if (self::isSkinTone($cp)) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Count of U+FE0E (VS15) codepoints.
     *
     * @param list<int> $input
     */
    private static function vs15Count(array $input): int
    {
        $count = 0;
        foreach ($input as $cp) {
            if (self::isVs15($cp)) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Count of U+FE0F (VS16) codepoints.
     *
     * @param list<int> $input
     */
    private static function vs16Count(array $input): int
    {
        $count = 0;
        foreach ($input as $cp) {
            if (self::isVs16($cp)) {
                $count++;
            }
        }
        return $count;
    }

    // ─────────────────────────────────────────────────────────────────
    // §4 Top-level detection
    // ─────────────────────────────────────────────────────────────────

    /**
     * The SkinToneVariationForgery detection function. Runs the priority ladder;
     * the first sub-threat wins. See the file header for the ordering rationale.
     *
     * @param list<int> $input
     */
    public static function detect(array $input): SkinToneVariationForgeryVerdict
    {
        $input = array_values($input);

        $stc = self::skinToneCount($input);
        $v15 = self::vs15Count($input);
        $v16 = self::vs16Count($input);

        $stacked = self::firstStackedSkinTones($input);
        if ($stacked !== null) {
            // Priority 1: a base followed by two stacked skin tones.
            [$basePos, $modifiers] = $stacked;
            $positions = [];
            $modCount = count($modifiers);
            for ($k = 0; $k < $modCount; $k++) {
                $positions[] = $basePos + 1 + $k;
            }
            $classification = SkinToneVariationForgeryClassification::hazard(
                SkinToneVariationForgerySubThreat::stackedSkinTones($basePos, $modifiers),
                $positions,
                [],
            );
        } else {
            $invalid = self::firstInvalidSkinToneTarget($input);
            if ($invalid !== null) {
                // Priority 2: a skin tone on a non-modifier-base.
                [$basePos, $baseCp, $modifierCp] = $invalid;
                $classification = SkinToneVariationForgeryClassification::hazard(
                    SkinToneVariationForgerySubThreat::invalidSkinToneTarget($basePos, $baseCp, $modifierCp),
                    [$basePos + 1],
                    [],
                );
            } else {
                $forced = self::firstForcedTextStyle($input);
                if ($forced !== null) {
                    // Priority 3: VS15 forcing text style on an emoji-presentation cp.
                    [$basePos, $baseCp] = $forced;
                    $classification = SkinToneVariationForgeryClassification::hazard(
                        SkinToneVariationForgerySubThreat::forcedTextStyle($basePos, $baseCp),
                        [$basePos + 1],
                        [],
                    );
                } else {
                    $classification = SkinToneVariationForgeryClassification::clear();
                }
            }
        }

        return new SkinToneVariationForgeryVerdict($input, $classification, $stc, $v15, $v16);
    }
}
