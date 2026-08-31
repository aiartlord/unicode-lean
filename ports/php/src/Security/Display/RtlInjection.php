<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Display;

use UnicodePhp\Security\Covert\BidiControlBalance;
use UnicodePhp\Security\Identity\Ucd;

/// The declared display direction of the field holding an input.
///
/// A caller handling Hebrew, Arabic or Persian UI text declares its field
/// right-to-left. Every other reading treats the input as a declared-LTR
/// string, under which right-to-left content is itself the hazard.
///
/// Mirrors `FieldDirection` in `Unicode/Security/Display/RtlInjection.lean`,
/// that spec's alias for the UAX #9 paragraph-direction vocabulary.
enum FieldDirection
{
    case Ltr;
    case Rtl;
}

final class RtlInjectionVerdict
{
    /** @param list<int> $positions */
    public function __construct(public readonly ?string $sub, public readonly array $positions)
    {
    }
}

final class RtlInjection
{
    /** @param list<int> $input */
    private static function countStrongRtl(array $input): int
    {
        $n = 0;
        foreach ($input as $cp) {
            if (Ucd::isStrongRtl($cp)) {
                $n++;
            }
        }
        return $n;
    }

    /** @param list<int> $input @return array{0:int,1:int} */
    private static function longestRtlRun(array $input): array
    {
        $longest = 0;
        $longestStart = 0;
        $current = 0;
        $currentStart = 0;
        foreach ($input as $i => $cp) {
            if (Ucd::isStrongRtl($cp)) {
                if ($current === 0) {
                    $currentStart = $i;
                }
                $current++;
                if ($current > $longest) {
                    $longest = $current;
                    $longestStart = $currentStart;
                }
            } else {
                $current = 0;
            }
        }
        return [$longest, $longestStart];
    }

    /** @param list<int> $input */
    private static function firstBidiControlPos(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if (BidiControlBalance::isBidiFormatControl($cp)) {
                return $i;
            }
        }
        return null;
    }

    /** @param list<int> $input @return array{0:?int,1:?bool} */
    private static function firstStrongChar(array $input): array
    {
        foreach ($input as $i => $cp) {
            if (Ucd::isStrongRtl($cp)) {
                return [$i, true];
            }
            if (Ucd::isStrongLtr($cp)) {
                return [$i, false];
            }
        }
        return [null, null];
    }

    /** @param list<int> $input */
    private static function firstStrongRtlPos(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if (Ucd::isStrongRtl($cp)) {
                return $i;
            }
        }
        return null;
    }

    /** @param list<int> $input */
    /// Detection in a field whose declared display direction is `$direction`.
    ///
    /// A bidi format control reorders what a reviewer sees whichever way the
    /// field runs, so Phase 1 holds unconditionally and trumps all.
    ///
    /// Phases 2 and 3 ask whether right-to-left text has taken over or been
    /// spliced into a left-to-right field. That question has no premise in a
    /// right-to-left field, where right-to-left text is the content. The
    /// mirror-image hazard, strong-LTR injection into a right-to-left field,
    /// belongs to the separate detector the scope note assigns it to.
    ///
    /// @param list<int> $input
    public static function detectWithContext(
        FieldDirection $direction,
        array $input
    ): RtlInjectionVerdict {
        $strongRtl = self::countStrongRtl($input);
        [$runLen, $runStart] = self::longestRtlRun($input);
        // Phase 1: bidi format-control trumps all, in either direction.
        $pos = self::firstBidiControlPos($input);
        if ($pos !== null) {
            return new RtlInjectionVerdict('BidiControlInLTRField', [$pos]);
        }
        // A right-to-left field carrying right-to-left text carries its
        // content.
        if ($direction === FieldDirection::Rtl) {
            return new RtlInjectionVerdict(null, []);
        }
        [$firstPos, $isRtl] = self::firstStrongChar($input);
        if ($firstPos !== null && $isRtl) {
            return new RtlInjectionVerdict('FieldTakeover', [$firstPos]);
        }
        if ($strongRtl === 0) {
            return new RtlInjectionVerdict(null, []);
        }
        if ($runLen >= 4) {
            return new RtlInjectionVerdict('MixedOverflow', [$runStart]);
        }
        $rtlPos = self::firstStrongRtlPos($input);
        return $rtlPos === null ? new RtlInjectionVerdict(null, []) : new RtlInjectionVerdict('StrongRTLInLTR', [$rtlPos]);
    }

    /// Detection in a field declared left-to-right, the reading the module
    /// scope note fixes for an undeclared field.
    ///
    /// @param list<int> $input
    public static function detect(array $input): RtlInjectionVerdict
    {
        return self::detectWithContext(FieldDirection::Ltr, $input);
    }
}
