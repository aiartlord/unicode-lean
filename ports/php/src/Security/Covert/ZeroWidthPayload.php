<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Covert;

use UnicodePhp\Security\ClassificationKind;
use UnicodePhp\Security\Identity\Ucd;

interface ZeroWidthSubThreat
{
    public function tag(): string;
}

final class ZwAnnotationMisuse implements ZeroWidthSubThreat
{
    public function __construct(public readonly int $count)
    {
    }

    public function tag(): string
    {
        return 'AnnotationMisuse';
    }
}

final class ZwWordJoinerInjection implements ZeroWidthSubThreat
{
    public function __construct(public readonly int $count)
    {
    }

    public function tag(): string
    {
        return 'WordJoinerInjection';
    }
}

final class ZwAiWatermarkNNBSP implements ZeroWidthSubThreat
{
    public function __construct(public readonly int $count)
    {
    }

    public function tag(): string
    {
        return 'AiWatermarkNNBSP';
    }
}

final class ZwBinaryPayload implements ZeroWidthSubThreat
{
    public function __construct(public readonly int $pairCount)
    {
    }

    public function tag(): string
    {
        return 'BinaryPayload';
    }
}

final class ZwBareZeroWidth implements ZeroWidthSubThreat
{
    public function __construct(public readonly int $cp)
    {
    }

    public function tag(): string
    {
        return 'BareZeroWidth';
    }
}

final class ZeroWidthVerdict
{
    /**
     * @param list<int> $zeroWidthPositions
     */
    public function __construct(
        public readonly ClassificationKind $kind,
        public readonly ?ZeroWidthSubThreat $sub,
        public readonly array $zeroWidthPositions,
    ) {
    }
}

/// Detection of payloads encoded in zero-width and near-zero-width Unicode
/// codepoints. Every zero-width occurrence is reportable; sibling-detector
/// ranges (variation selectors, tag block, bidi push/pop controls) are excluded
/// to avoid double-counting.
final class ZeroWidthPayload
{
    /// Sibling-detector codepoint ranges excluded from the ZW set.
    private static function isSiblingHandled(int $cp): bool
    {
        return ($cp >= 0xFE00 && $cp <= 0xFE0F)
            || ($cp >= 0xE0100 && $cp <= 0xE01EF)
            || ($cp >= 0xE0000 && $cp <= 0xE007F)
            || ($cp >= 0x202A && $cp <= 0x202E)
            || ($cp >= 0x2066 && $cp <= 0x2069);
    }

    /// True iff `cp` renders as nothing or is in the explicit tracked
    /// zero-width set; the UAX #44 Default_Ignorable predicate catches the rest.
    public static function isZeroWidth(int $cp): bool
    {
        if (
            ($cp >= 0x200B && $cp <= 0x200F)
            || ($cp >= 0x2060 && $cp <= 0x2064)
            || $cp === 0x202F
            || $cp === 0xFEFF
            || ($cp >= 0xFFF9 && $cp <= 0xFFFB)
        ) {
            return true;
        }
        return Ucd::isDefaultIgnorable($cp) && !self::isSiblingHandled($cp);
    }

    public static function isNnbsp(int $cp): bool
    {
        return $cp === 0x202F;
    }

    public static function isWordJoiner(int $cp): bool
    {
        return $cp === 0x2060;
    }

    public static function isAnnotation(int $cp): bool
    {
        return $cp >= 0xFFF9 && $cp <= 0xFFFB;
    }

    public static function isZwjOrZwsp(int $cp): bool
    {
        return $cp === 0x200B || $cp === 0x200D;
    }

    /**
     * @param list<int> $input
     */
    public static function detect(array $input): ZeroWidthVerdict
    {
        $positions = [];
        $annotationCount = 0;
        $wordJoinerCount = 0;
        $nnbspCount = 0;
        $zwjZwspCount = 0;

        foreach ($input as $i => $cp) {
            if (!self::isZeroWidth($cp)) {
                continue;
            }
            $positions[] = $i;
            if (self::isAnnotation($cp)) {
                $annotationCount++;
            } elseif (self::isWordJoiner($cp)) {
                $wordJoinerCount++;
            } elseif (self::isNnbsp($cp)) {
                $nnbspCount++;
            } elseif (self::isZwjOrZwsp($cp)) {
                $zwjZwspCount++;
            }
        }

        if ($positions === []) {
            return new ZeroWidthVerdict(ClassificationKind::Clear, null, []);
        }

        if ($annotationCount > 0) {
            $sub = new ZwAnnotationMisuse($annotationCount);
        } elseif ($wordJoinerCount > 0) {
            $sub = new ZwWordJoinerInjection($wordJoinerCount);
        } elseif ($nnbspCount >= 2) {
            $sub = new ZwAiWatermarkNNBSP($nnbspCount);
        } elseif ($zwjZwspCount >= 2) {
            $sub = new ZwBinaryPayload(intdiv($zwjZwspCount, 2));
        } else {
            $sub = new ZwBareZeroWidth($input[$positions[0]]);
        }

        return new ZeroWidthVerdict(ClassificationKind::Hazard, $sub, $positions);
    }
}
