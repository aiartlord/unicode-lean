<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Display;

use UnicodePhp\Security\Covert\BidiControlBalance;
use UnicodePhp\Security\Identity\Ucd;

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
    public static function detect(array $input): RtlInjectionVerdict
    {
        $strongRtl = self::countStrongRtl($input);
        [$runLen, $runStart] = self::longestRtlRun($input);
        $pos = self::firstBidiControlPos($input);
        if ($pos !== null) {
            return new RtlInjectionVerdict('RloInLTRField', [$pos]);
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
}
