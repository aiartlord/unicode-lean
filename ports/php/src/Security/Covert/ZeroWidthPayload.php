<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Covert;

use UnicodePhp\Security\ClassificationKind;
use UnicodePhp\Security\Identity\EmojiZwjIntegrity;
use UnicodePhp\Security\Identity\JoiningType;
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
    /// True iff the ZWJ at index `i` is flanked by two codepoints that both
    /// participate in some registered RGI emoji ZWJ sequence. Strictly narrower
    /// than "is an emoji": a codepoint carrying the Emoji property but
    /// appearing in no registered sequence does not sanction a ZWJ beside it. A
    /// ZWJ in head or tail position is never legitimate.
    ///
    /// @param list<int> $input
    private static function isLegitimateZwjContext(array $input, int $i): bool
    {
        if ($i === 0 || $i + 1 >= count($input)) {
            return false;
        }
        return EmojiZwjIntegrity::isEmojiTarget($input[$i - 1])
            && EmojiZwjIntegrity::isEmojiTarget($input[$i + 1]);
    }

    /// The `Joining_Type` of the first non-Transparent codepoint before `i`.
    ///
    /// @param list<int> $input
    private static function joiningTypeBefore(array $input, int $i): ?JoiningType
    {
        $j = $i;
        while ($j > 0) {
            $j--;
            $jt = Ucd::joiningType($input[$j]);
            if ($jt !== JoiningType::Transparent) {
                return $jt;
            }
        }
        return null;
    }

    /// The `Joining_Type` of the first non-Transparent codepoint after `i`.
    ///
    /// @param list<int> $input
    private static function joiningTypeAfter(array $input, int $i): ?JoiningType
    {
        $j = $i + 1;
        $n = count($input);
        while ($j < $n) {
            $jt = Ucd::joiningType($input[$j]);
            if ($jt !== JoiningType::Transparent) {
                return $jt;
            }
            $j++;
        }
        return null;
    }

    /// True iff the ZWNJ at index `i` occupies a position where it is
    /// orthographically required, by RFC 5892 Appendix A.1: it follows a
    /// Virama, which is how a Devanagari conjunct is suppressed, or it sits
    /// between a left- or dual-joining character and a right- or dual-joining
    /// one, skipping Transparent characters on both sides, which is how a
    /// Persian word boundary is written inside a cursive run.
    ///
    /// A ZWNJ outside such a position carries no orthographic duty and stays
    /// reportable.
    ///
    /// @param list<int> $input
    private static function isLegitimateZwnjContext(array $input, int $i): bool
    {
        if ($i > 0 && Ucd::isVirama($input[$i - 1])) {
            return true;
        }
        $left = self::joiningTypeBefore($input, $i);
        $right = self::joiningTypeAfter($input, $i);
        $leftOk = $left === JoiningType::LeftJoining || $left === JoiningType::DualJoining;
        $rightOk = $right === JoiningType::RightJoining || $right === JoiningType::DualJoining;
        return $leftOk && $rightOk;
    }

    public static function detect(array $input): ZeroWidthVerdict
    {
        $positions = [];
        $suspicious = [];
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
            // The sanctioning model: a ZWJ inside a registered emoji sequence
            // and a ZWNJ in an RFC 5892 CONTEXTJ-valid position both carry
            // meaning a reader depends on, so they are recorded as present but
            // not treated as suspicious.
            $sanctioned = ($cp === 0x200D && self::isLegitimateZwjContext($input, $i))
                || ($cp === 0x200C && self::isLegitimateZwnjContext($input, $i));
            if (!$sanctioned) {
                $suspicious[] = $i;
            }
        }

        if ($positions === [] || $suspicious === []) {
            return new ZeroWidthVerdict(ClassificationKind::Clear, null, $positions);
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
            $sub = new ZwBareZeroWidth($input[$suspicious[0]]);
        }

        return new ZeroWidthVerdict(ClassificationKind::Hazard, $sub, $positions);
    }
}
