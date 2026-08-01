<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Form;

use UnicodePhp\Security\Identity\Locale;
use UnicodePhp\Security\Identity\Ucd;

final class FormVerdict
{
    /** @param list<int> $positions */
    public function __construct(public readonly ?string $sub, public readonly array $positions)
    {
    }
}

final class LocaleCaseInversion
{
    /** @param list<int> $input */
    private static function firstLocaleDivergence(Locale $locale, array $input): ?int
    {
        $revPrefix = [];
        $count = count($input);
        for ($i = 0; $i < $count; $i++) {
            $suffix = array_slice($input, $i + 1);
            $default = Ucd::lowerCodepoint(Locale::Default, $revPrefix, $suffix, $input[$i]);
            $localeLower = Ucd::lowerCodepoint($locale, $revPrefix, $suffix, $input[$i]);
            if ($default !== $localeLower) {
                return $i;
            }
            array_unshift($revPrefix, $input[$i]);
        }
        return null;
    }

    /** @param list<int> $input */
    public static function detect(array $input): FormVerdict
    {
        $turkish = self::firstLocaleDivergence(Locale::Turkish, $input);
        if ($turkish !== null) {
            return new FormVerdict('TurkishCaseDivergence', [$turkish]);
        }
        $lithuanian = self::firstLocaleDivergence(Locale::Lithuanian, $input);
        if ($lithuanian !== null) {
            return new FormVerdict('LithuanianCaseDivergence', [$lithuanian]);
        }
        return new FormVerdict(null, []);
    }
}
