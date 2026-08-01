<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Form;

use UnicodePhp\Security\Identity\Ucd;

final class NormalizationBomb
{
    private const MAX_NFKD_PER_CP = 8;
    private const NFD_RATIO_PCT = 300;
    private const NFKD_RATIO_PCT = 400;

    /** @param list<int> $input */
    private static function firstBlowupCp(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if (count(Ucd::toNfkd([$cp])) > self::MAX_NFKD_PER_CP) {
                return $i;
            }
        }
        return null;
    }

    /** @param list<int> $input */
    private static function ratioPct(array $input, callable $normalizer): int
    {
        return $input === [] ? 0 : intdiv(count($normalizer($input)) * 100, count($input));
    }

    /** @param list<int> $input */
    public static function detect(array $input): FormVerdict
    {
        $pos = self::firstBlowupCp($input);
        if ($pos !== null) {
            return new FormVerdict('SingleCpBlowup', [$pos]);
        }
        if (self::ratioPct($input, [Ucd::class, 'toNfkd']) > self::NFKD_RATIO_PCT) {
            return new FormVerdict('NfkdHighExpansion', []);
        }
        if (self::ratioPct($input, [Ucd::class, 'toNfd']) > self::NFD_RATIO_PCT) {
            return new FormVerdict('NfdHighExpansion', []);
        }
        return new FormVerdict(null, []);
    }
}
