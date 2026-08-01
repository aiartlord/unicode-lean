<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Boundary;

use UnicodePhp\Security\Covert\BidiControlBalance;
use UnicodePhp\Security\Covert\VariationSelectorPayload;

final class CovertDisplayCompound
{
    /** @param list<int> $input */
    private static function firstBidiPos(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if (BidiControlBalance::isBidiFormatControl($cp)) {
                return $i;
            }
        }
        return null;
    }

    /** @param list<int> $input */
    private static function firstSuspiciousVsPos(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if (VariationSelectorPayload::isVariationSelector($cp) && !($i > 0 && VariationSelectorPayload::isRegisteredVariationPair($input[$i - 1], $cp))) {
                return $i;
            }
        }
        return null;
    }

    /** @param list<int> $input */
    private static function firstTagBlockPos(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if ($cp >= 0xE0000 && $cp <= 0xE007F) {
                return $i;
            }
        }
        return null;
    }

    /** @param list<int> $input */
    public static function detect(array $input): BoundaryVerdict
    {
        $bidiPos = self::firstBidiPos($input);
        if ($bidiPos === null) {
            return new BoundaryVerdict(null, []);
        }
        $vsPos = self::firstSuspiciousVsPos($input);
        if ($vsPos !== null) {
            return new BoundaryVerdict('BidiPlusUnregisteredVs', [$bidiPos, $vsPos]);
        }
        $tagPos = self::firstTagBlockPos($input);
        if ($tagPos !== null) {
            return new BoundaryVerdict('BidiPlusTagBlock', [$bidiPos, $tagPos]);
        }
        return new BoundaryVerdict(null, []);
    }
}
