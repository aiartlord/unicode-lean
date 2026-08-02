<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Form;

use UnicodePhp\Security\Identity\Locale;
use UnicodePhp\Security\Identity\Ucd;

// CaseExpansionMismatch — codepoints whose UAX #21 default-locale case mapping
// changes the codepoint count (form-layer detector).
//
// Byte-faithful transliteration of the verified reference implementation,
// itself a mirror of the Lean specification for this family.
//
// Threat model. Tier A₁..A₂. An attacker submits text whose case-mapped form has
// a different codepoint count than the input. A receiver that fixes a 16-byte
// username column and stores toUpper(username) overflows when the user picks
// "ßßßßßßßß" (8 in → 16 stored); a receiver that checks len(stored) == len(input)
// rejects valid case-insensitive logins whose names expand under folding.
// Examples: U+00DF ß → "SS", U+FB01 ﬁ → "FI", U+0130 İ → toLower "i̇" (i + U+0307).
//
// Distinct from LocaleCaseInversion (case mapping that changes ACROSS locales):
// this fires on shapes whose mapping is locale-stable but length-changing under
// the default locale itself.
//
// It reuses the port's own UAX #21 case mapping (Ucd::upperCodepoint /
// Ucd::lowerCodepoint, which evaluate the SpecialCasing context predicates),
// never a host casing library.
//
// Sub-threats (priority order):
//   1. UpperExpansion — first position whose default upperCodepoint yields > 1 cp.
//   2. LowerExpansion — first position whose default lowerCodepoint yields > 1 cp
//      (reached only when no upper expansion fires first).

/**
 * Sub-threat carrier for CaseExpansionMismatch, in priority order. A single
 * class holds every variant's observation fields, mirroring the reference
 * `SubThreat` enum's associated data.
 */
final class CaseExpansionMismatchSubThreat
{
    private function __construct(
        public readonly string $kind,
        public readonly int $basePos,
        public readonly int $cp,
        public readonly int $expansionLen,
    ) {
    }

    public static function upperExpansion(int $basePos, int $cp, int $expansionLen): CaseExpansionMismatchSubThreat
    {
        return new CaseExpansionMismatchSubThreat('UpperExpansion', $basePos, $cp, $expansionLen);
    }

    public static function lowerExpansion(int $basePos, int $cp, int $expansionLen): CaseExpansionMismatchSubThreat
    {
        return new CaseExpansionMismatchSubThreat('LowerExpansion', $basePos, $cp, $expansionLen);
    }

    /** Fixture-row tag string for this sub-threat (matches `SubThreat.tag`). */
    public function tag(): string
    {
        return match ($this->kind) {
            'UpperExpansion' => 'UpperExpansion',
            'LowerExpansion' => 'LowerExpansion',
            default => throw new \RuntimeException("CaseExpansionMismatchSubThreat: unknown kind '{$this->kind}'"),
        };
    }
}

/**
 * Top-level classification (Clear when no case-mapped expansion present), or a
 * Hazard carrying the fired sub-threat, the implicated positions, and the
 * (always-empty for this detector) decoded-byte projection kept for shape parity
 * with the Lean `Classification.hazard`.
 */
final class CaseExpansionMismatchClassification
{
    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    private function __construct(
        public readonly ?CaseExpansionMismatchSubThreat $sub,
        public readonly array $positions,
        public readonly array $decoded,
    ) {
    }

    public static function clear(): CaseExpansionMismatchClassification
    {
        return new CaseExpansionMismatchClassification(null, [], []);
    }

    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    public static function hazard(CaseExpansionMismatchSubThreat $sub, array $positions, array $decoded): CaseExpansionMismatchClassification
    {
        return new CaseExpansionMismatchClassification($sub, $positions, $decoded);
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

/** The structured output of `detect` (mirrors the Lean/reference `Verdict`). */
final class CaseExpansionMismatchVerdict
{
    /** @param list<int> $input */
    public function __construct(
        public readonly array $input,
        public readonly CaseExpansionMismatchClassification $classify,
        public readonly int $upperExpansionCount,
        public readonly int $lowerExpansionCount,
        public readonly int $maxExpansionLen,
    ) {
    }
}

final class CaseExpansionMismatch
{
    /**
     * The default-locale uppercase expansion length at position `$i`, evaluating
     * the SpecialCasing context (preceding codepoints nearest-first, following).
     * @param list<int> $input
     */
    private static function upperLenAt(array $input, int $i): int
    {
        $revPrefix = array_reverse(array_slice($input, 0, $i));
        $suffix = array_slice($input, $i + 1);
        return count(Ucd::upperCodepoint(Locale::Default, $revPrefix, $suffix, $input[$i]));
    }

    /**
     * The default-locale lowercase expansion length at position `$i`.
     * @param list<int> $input
     */
    private static function lowerLenAt(array $input, int $i): int
    {
        $revPrefix = array_reverse(array_slice($input, 0, $i));
        $suffix = array_slice($input, $i + 1);
        return count(Ucd::lowerCodepoint(Locale::Default, $revPrefix, $suffix, $input[$i]));
    }

    /**
     * First position whose default uppercase mapping expands to > 1 codepoint.
     * @param list<int> $input @return array{0:int,1:int,2:int}|null
     */
    private static function firstUpperExpansion(array $input): ?array
    {
        $count = count($input);
        for ($i = 0; $i < $count; $i++) {
            $len = self::upperLenAt($input, $i);
            if ($len > 1) {
                return [$i, $input[$i], $len];
            }
        }
        return null;
    }

    /**
     * First position whose default lowercase mapping expands to > 1 codepoint.
     * @param list<int> $input @return array{0:int,1:int,2:int}|null
     */
    private static function firstLowerExpansion(array $input): ?array
    {
        $count = count($input);
        for ($i = 0; $i < $count; $i++) {
            $len = self::lowerLenAt($input, $i);
            if ($len > 1) {
                return [$i, $input[$i], $len];
            }
        }
        return null;
    }

    /** @param list<int> $input */
    private static function upperExpansionCount(array $input): int
    {
        $n = 0;
        $count = count($input);
        for ($i = 0; $i < $count; $i++) {
            if (self::upperLenAt($input, $i) > 1) {
                $n++;
            }
        }
        return $n;
    }

    /** @param list<int> $input */
    private static function lowerExpansionCount(array $input): int
    {
        $n = 0;
        $count = count($input);
        for ($i = 0; $i < $count; $i++) {
            if (self::lowerLenAt($input, $i) > 1) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * Maximum case-mapped expansion length across all positions (upper or lower);
     * 0 for empty input.
     * @param list<int> $input
     */
    private static function maxExpansionLen(array $input): int
    {
        $max = 0;
        $count = count($input);
        for ($i = 0; $i < $count; $i++) {
            $upper = self::upperLenAt($input, $i);
            $lower = self::lowerLenAt($input, $i);
            $per = $upper > $lower ? $upper : $lower;
            if ($per > $max) {
                $max = $per;
            }
        }
        return $max;
    }

    /**
     * The CaseExpansionMismatch detection function.
     * @param list<int> $input
     */
    public static function detect(array $input): CaseExpansionMismatchVerdict
    {
        $input = array_values($input);

        // Priority 1: an uppercase expansion.
        $upper = self::firstUpperExpansion($input);
        if ($upper !== null) {
            [$pos, $cp, $len] = $upper;
            $classification = CaseExpansionMismatchClassification::hazard(
                CaseExpansionMismatchSubThreat::upperExpansion($pos, $cp, $len),
                [$pos],
                [],
            );
        } else {
            // Priority 2: a lowercase expansion.
            $lower = self::firstLowerExpansion($input);
            if ($lower !== null) {
                [$pos, $cp, $len] = $lower;
                $classification = CaseExpansionMismatchClassification::hazard(
                    CaseExpansionMismatchSubThreat::lowerExpansion($pos, $cp, $len),
                    [$pos],
                    [],
                );
            } else {
                $classification = CaseExpansionMismatchClassification::clear();
            }
        }

        return new CaseExpansionMismatchVerdict(
            $input,
            $classification,
            self::upperExpansionCount($input),
            self::lowerExpansionCount($input),
            self::maxExpansionLen($input),
        );
    }
}
