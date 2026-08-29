<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Form;

use UnicodePhp\Security\Identity\EastAsianWidth;
use UnicodePhp\Security\Identity\Ucd;

/// Width-class-confusion detection — UAX #11 East Asian Width class confusion.
///
/// A Fullwidth (EAW = F) or Halfwidth (EAW = H) codepoint whose NFKD form
/// carries a different EAW class is a compatibility-fold homograph:
///
///   U+FF21 'Ａ' (F)  ->  U+0041 'A' (Na)
///   U+FF11 '１' (F)  ->  U+0031 '1' (Na)
///   U+FF71 'ｱ' (H)  ->  U+30A2 'ア' (W)
///
/// The two-system bypass: a validator that whitelists ASCII rejects Ａ, while a
/// downstream NFKC step at storage or comparison time folds it to plain A, so
/// ＡＤＭＩＮ claims the username ADMIN.
///
/// Distinct from RendererDivergence's FullwidthVariance, which fires on F-class
/// codepoints for renderer-cohort reasons; this is the NFKC-fold verdict and
/// both can fire on one input independently. Hangul syllables decompose to
/// jamos that are still W class, so pure Hangul stays clear.
///
/// Direct port of Unicode/Security/Form/WidthClassConfusion.lean.
final class WidthClassConfusion
{
    /// True iff the NFKD head of `$cp` carries a different EAW class.
    private static function hasWidthFold(int $cp): bool
    {
        $folded = Ucd::toNfkd([$cp]);
        if ($folded === []) {
            return false;
        }
        return Ucd::eastAsianWidth($folded[0]) !== Ucd::eastAsianWidth($cp);
    }

    /** @param list<int> $input */
    private static function firstFold(array $input, EastAsianWidth $want): ?int
    {
        $count = count($input);
        for ($i = 0; $i < $count; $i++) {
            if (Ucd::eastAsianWidth($input[$i]) === $want && self::hasWidthFold($input[$i])) {
                return $i;
            }
        }
        return null;
    }

    /// A Fullwidth fold takes priority over a Halfwidth one, matching the
    /// reference's sub-threat order.
    /** @param list<int> $input */
    public static function detect(array $input): FormVerdict
    {
        $pos = self::firstFold($input, EastAsianWidth::F);
        if ($pos !== null) {
            return new FormVerdict('FullwidthFold', [$pos]);
        }
        $pos = self::firstFold($input, EastAsianWidth::H);
        if ($pos !== null) {
            return new FormVerdict('HalfwidthFold', [$pos]);
        }
        return new FormVerdict(null, []);
    }
}
