<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Form;

use UnicodePhp\Security\Identity\Ucd;

final class NfcIdempotenceWitness
{
    /** @param list<int> $a @param list<int> $b */
    private static function firstDivergence(array $a, array $b): ?int
    {
        $n = min(count($a), count($b));
        for ($i = 0; $i < $n; $i++) {
            if ($a[$i] !== $b[$i]) {
                return $i;
            }
        }
        return count($a) === count($b) ? null : $n;
    }

    /** @param list<int> $input */
    public static function detect(array $input): FormVerdict
    {
        $pos = self::firstDivergence($input, Ucd::toNfc($input));
        if ($pos !== null) {
            return new FormVerdict('NonNfcForm', [$pos]);
        }
        $pos = self::firstDivergence($input, Ucd::toNfkc($input));
        if ($pos !== null) {
            return new FormVerdict('NonNfkcCompatForm', [$pos]);
        }
        return new FormVerdict(null, []);
    }
}
