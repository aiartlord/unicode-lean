<?php

declare(strict_types=1);

namespace UnicodePhp;

/// Detection and enumeration of the 66 designated Unicode noncharacters per
/// UAX #44 §5.6 / Unicode Standard 17.0 §23.7.
///
/// Two categories:
///
///   - BMP block:  U+FDD0 .. U+FDEF                (32 codepoints)
///   - Plane ends: U+nnFFFE / U+nnFFFF for n=0..16 (34 codepoints)
///
/// Total: 66.
final class Noncharacters
{
    /// Whether `cp` is one of the 66 designated Unicode noncharacters.
    public static function isNoncharacter(int $cp): bool
    {
        if ($cp >= 0xFDD0 && $cp <= 0xFDEF) {
            return true;
        }
        if ($cp > 0x10FFFF) {
            return false;
        }
        $low16 = $cp & 0xFFFF;
        return $low16 === 0xFFFE || $low16 === 0xFFFF;
    }

    /// Enumerate the 66 noncharacters in ascending order.
    ///
    /// @return list<int>
    public static function all(): array
    {
        $out = [];
        for ($cp = 0xFDD0; $cp <= 0xFDEF; $cp++) {
            $out[] = $cp;
        }
        for ($n = 0; $n <= 16; $n++) {
            $out[] = $n * 0x10000 + 0xFFFE;
            $out[] = $n * 0x10000 + 0xFFFF;
        }
        return $out;
    }
}
