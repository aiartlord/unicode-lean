<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Identity;

use UnicodePhp\Data;

/// The locales `SpecialCasing.txt` distinguishes. `Default` covers everything
/// not tagged Turkish / Azeri / Lithuanian.
enum Locale
{
    /// Everything not tagged tr / az / lt.
    case Default;
    /// Turkish (`tr`).
    case Turkish;
    /// Azeri (`az`).
    case Azeri;
    /// Lithuanian (`lt`).
    case Lithuanian;
}

/// The strong Bidi_Class distinction the display layer needs.
enum BidiStrong
{
    case R;
    case Al;
    case L;
    case Other;
}

/// UTS #39 § 5.1 restriction-level classification.
enum RestrictionLevel
{
    case AsciiOnly;
    case SingleScript;
    case HighlyRestrictive;
    case ModeratelyRestrictive;
    case MinimallyRestrictive;
    case Unrestricted;
}

/// UCD-table-backed support for the identity-spoofing detector family — NFC/NFD/
/// NFKC/NFKD normalization, case folding, UAX #21 case mapping, script lookup,
/// and UTS #39 identifier-status / restriction-level classification.
///
/// All data is read at runtime from the bundled UCD files in the port's `data/`
/// directory. Parsing happens lazily on first access and is cached in static
/// properties (the runtime analog of the reference ports' `OnceLock`).
final class Ucd
{
    private const HANGUL_S_BASE = 0xAC00;
    private const HANGUL_L_BASE = 0x1100;
    private const HANGUL_V_BASE = 0x1161;
    private const HANGUL_T_BASE = 0x11A7;
    private const HANGUL_L_COUNT = 19;
    private const HANGUL_V_COUNT = 21;
    private const HANGUL_T_COUNT = 28;
    private const HANGUL_N_COUNT = self::HANGUL_V_COUNT * self::HANGUL_T_COUNT;
    private const HANGUL_S_COUNT = self::HANGUL_L_COUNT * self::HANGUL_N_COUNT;

    // ── Lazy-parsed caches ──────────────────────────────────────────────
    /** @var array<int,array{ccc:int,canonical:?list<int>,compat:?list<int>}>|null */
    private static ?array $ucdTable = null;
    /** @var array{explicit:list<array{0:int,1:int,2:BidiStrong}>,defaults:list<array{0:int,1:int,2:BidiStrong}>}|null */
    private static ?array $bidiTable = null;
    /** @var array<int,bool>|null */
    private static ?array $compositionExclusions = null;
    /** @var array<int,array<int,int>>|null */
    private static ?array $compositionTable = null;
    /** @var array<int,list<int>>|null */
    private static ?array $caseFolding = null;
    /** @var list<array{0:int,1:int,2:string}>|null */
    private static ?array $scripts = null;
    /** @var list<array{0:int,1:int,2:list<string>}>|null */
    private static ?array $scriptExtensions = null;
    /** @var array<string,string>|null */
    private static ?array $scriptNameToAbbrev = null;
    /** @var list<array{0:int,1:int}>|null */
    private static ?array $identifierAllowed = null;
    /** @var list<array{0:int,1:int}>|null */
    private static ?array $defaultIgnorable = null;
    /** @var array<int,list<array{lower:list<int>,upper:list<int>,conditions:list<string>}>>|null */
    private static ?array $specialCasing = null;
    /** @var array<int,int>|null */
    private static ?array $simpleLowercase = null;
    /** @var array<int,int>|null */
    private static ?array $simpleUppercase = null;
    /** @var list<array{0:int,1:int}>|null */
    private static ?array $casedRanges = null;
    /** @var list<array{0:int,1:int}>|null */
    private static ?array $softDottedRanges = null;
    /** @var list<array{0:int,1:int}>|null */
    private static ?array $xidStartRanges = null;
    /** @var list<array{0:int,1:int}>|null */
    private static ?array $xidContinueRanges = null;

    // ── Shared parse helpers ────────────────────────────────────────────

    private static function parseHex(string $s): ?int
    {
        $s = trim($s);
        if ($s === '' || preg_match('/^[0-9A-Fa-f]+$/', $s) !== 1) {
            return null;
        }
        return (int) hexdec($s);
    }

    private static function stripCommentAndTrim(string $line): string
    {
        $idx = strpos($line, '#');
        $body = $idx === false ? $line : substr($line, 0, $idx);
        return trim($body);
    }

    /// Parse `LO..HI` or a single `CP` into an inclusive range.
    ///
    /// @return array{0:int,1:int}|null
    private static function parseRangeField(string $s): ?array
    {
        $s = trim($s);
        $idx = strpos($s, '..');
        if ($idx !== false) {
            $a = self::parseHex(substr($s, 0, $idx));
            $b = self::parseHex(substr($s, $idx + 2));
            if ($a === null || $b === null) {
                return null;
            }
            return [$a, $b];
        }
        $a = self::parseHex($s);
        return $a === null ? null : [$a, $a];
    }

    /// @param list<int> $field split into whitespace-separated hex codepoints
    /// @return list<int>
    private static function parseCodepoints(string $field): array
    {
        $out = [];
        foreach (preg_split('/\s+/', trim($field), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $token) {
            $cp = self::parseHex($token);
            if ($cp !== null) {
                $out[] = $cp;
            }
        }
        return $out;
    }

    /// Index of the last range whose start `[0]` is `<= cp`, or -1.
    ///
    /// @param list<array{0:int,1:int}|array{0:int,1:int,2:mixed}> $ranges
    private static function lastStartLe(array $ranges, int $cp): int
    {
        $lo = 0;
        $hi = count($ranges);
        while ($lo < $hi) {
            $mid = $lo + intdiv($hi - $lo, 2);
            if ($ranges[$mid][0] <= $cp) {
                $lo = $mid + 1;
            } else {
                $hi = $mid;
            }
        }
        return $lo - 1;
    }

    // ── UnicodeData.txt — CCC + canonical / compatibility decomposition ──

    /** @return array<int,array{ccc:int,canonical:?list<int>,compat:?list<int>}> */
    private static function ucdTable(): array
    {
        if (self::$ucdTable !== null) {
            return self::$ucdTable;
        }
        $out = [];
        foreach (Data::lines('UnicodeData.txt') as $line) {
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $fields = explode(';', $line);
            if (count($fields) < 6) {
                continue;
            }
            $cp = self::parseHex($fields[0]);
            if ($cp === null) {
                continue;
            }
            $cccStr = trim($fields[3]);
            if ($cccStr === '' || preg_match('/^\d+$/', $cccStr) !== 1) {
                throw new \RuntimeException(
                    sprintf('UnicodeData.txt: CCC field for U+%04X is not an integer (%s)', $cp, $fields[3])
                );
            }
            $ccc = (int) $cccStr;
            $decompField = trim($fields[5]);
            $canonical = null;
            $compat = null;
            if ($decompField !== '') {
                if ($decompField[0] === '<') {
                    // Compatibility decomposition: strip the `<tag>` prefix.
                    $gt = strpos($decompField, '>');
                    $afterTag = $gt === false ? $decompField : substr($decompField, $gt + 1);
                    $parts = self::parseCodepoints($afterTag);
                    if ($parts !== []) {
                        $compat = $parts;
                    }
                } else {
                    $parts = self::parseCodepoints($decompField);
                    if ($parts !== []) {
                        $canonical = $parts;
                    }
                }
            }
            $out[$cp] = ['ccc' => $ccc, 'canonical' => $canonical, 'compat' => $compat];
        }
        self::$ucdTable = $out;
        return $out;
    }

    /// UAX #44 § 5.7.4: codepoints absent from the listed CCC ranges have
    /// Canonical_Combining_Class = 0 by definition (Not_Reordered).
    public static function ccc(int $cp): int
    {
        $table = self::ucdTable();
        return isset($table[$cp]) ? $table[$cp]['ccc'] : 0;
    }

    // ── DerivedBidiClass.txt — strong Bidi_Class lookup ─────────────────

    private static function strongOfShort(string $token): BidiStrong
    {
        return match ($token) {
            'R' => BidiStrong::R,
            'AL' => BidiStrong::Al,
            'L' => BidiStrong::L,
            default => BidiStrong::Other,
        };
    }

    private static function strongOfLong(string $token): BidiStrong
    {
        return match ($token) {
            'Right_To_Left' => BidiStrong::R,
            'Arabic_Letter' => BidiStrong::Al,
            'Left_To_Right' => BidiStrong::L,
            default => BidiStrong::Other,
        };
    }

    /** @return array{explicit:list<array{0:int,1:int,2:BidiStrong}>,defaults:list<array{0:int,1:int,2:BidiStrong}>} */
    private static function bidiTable(): array
    {
        if (self::$bidiTable !== null) {
            return self::$bidiTable;
        }
        $explicit = [];
        $defaults = [];
        foreach (Data::lines('DerivedBidiClass.txt') as $line) {
            if (str_starts_with($line, '# @missing:')) {
                $rest = substr($line, strlen('# @missing:'));
                $semi = strpos($rest, ';');
                if ($semi !== false) {
                    $range = self::parseRangeField(substr($rest, 0, $semi));
                    if ($range !== null) {
                        $defaults[] = [$range[0], $range[1], self::strongOfLong(trim(substr($rest, $semi + 1)))];
                    }
                }
                continue;
            }
            $hash = strpos($line, '#');
            $body = trim($hash === false ? $line : substr($line, 0, $hash));
            if ($body === '') {
                continue;
            }
            $semi = strpos($body, ';');
            if ($semi === false) {
                continue;
            }
            $range = self::parseRangeField(substr($body, 0, $semi));
            if ($range !== null) {
                $explicit[] = [$range[0], $range[1], self::strongOfShort(trim(substr($body, $semi + 1)))];
            }
        }
        usort($explicit, static fn (array $a, array $b): int => $a[0] <=> $b[0]);
        self::$bidiTable = ['explicit' => $explicit, 'defaults' => $defaults];
        return self::$bidiTable;
    }

    /// Full `Bidi_Class` lookup (strong distinction only): explicit range first,
    /// then the last matching `@missing` default, then `L`.
    public static function bidiStrong(int $cp): BidiStrong
    {
        $table = self::bidiTable();
        $explicit = $table['explicit'];
        // Binary search the sorted explicit ranges.
        $lo = 0;
        $hi = count($explicit);
        while ($lo < $hi) {
            $mid = $lo + intdiv($hi - $lo, 2);
            [$rlo, $rhi, $cls] = $explicit[$mid];
            if ($cp < $rlo) {
                $hi = $mid;
            } elseif ($cp > $rhi) {
                $lo = $mid + 1;
            } else {
                return $cls;
            }
        }
        $result = BidiStrong::L;
        foreach ($table['defaults'] as [$rlo, $rhi, $cls]) {
            if ($rlo <= $cp && $cp <= $rhi) {
                $result = $cls;
            }
        }
        return $result;
    }

    public static function isStrongRtl(int $cp): bool
    {
        $s = self::bidiStrong($cp);
        return $s === BidiStrong::R || $s === BidiStrong::Al;
    }

    public static function isStrongLtr(int $cp): bool
    {
        return self::bidiStrong($cp) === BidiStrong::L;
    }

    // ── CompositionExclusions.txt ───────────────────────────────────────

    /** @return array<int,bool> */
    private static function compositionExclusions(): array
    {
        if (self::$compositionExclusions !== null) {
            return self::$compositionExclusions;
        }
        $out = [];
        foreach (Data::lines('CompositionExclusions.txt') as $line) {
            $stripped = self::stripCommentAndTrim($line);
            if ($stripped === '') {
                continue;
            }
            $cp = self::parseHex($stripped);
            if ($cp !== null) {
                $out[$cp] = true;
            }
        }
        self::$compositionExclusions = $out;
        return $out;
    }

    // ── Composition table (inverse of canonical decomp minus exclusions) ─

    /** @return array<int,array<int,int>> */
    private static function compositionTable(): array
    {
        if (self::$compositionTable !== null) {
            return self::$compositionTable;
        }
        $table = self::ucdTable();
        $exclusions = self::compositionExclusions();
        $out = [];
        foreach ($table as $cp => $entry) {
            $decomp = $entry['canonical'];
            if ($decomp !== null && count($decomp) === 2 && !isset($exclusions[$cp])) {
                // Singleton-decomposition exclusions: skip cases where the first
                // character is a non-starter.
                if (self::ccc($decomp[0]) === 0) {
                    $out[$decomp[0]][$decomp[1]] = $cp;
                }
            }
        }
        self::$compositionTable = $out;
        return $out;
    }

    // ── Hangul algorithmic decomposition + composition ──────────────────

    /**
     * @param list<int> $out appended in place
     */
    private static function hangulDecompose(int $cp, array &$out): bool
    {
        if ($cp < self::HANGUL_S_BASE || $cp >= self::HANGUL_S_BASE + self::HANGUL_S_COUNT) {
            return false;
        }
        $sIndex = $cp - self::HANGUL_S_BASE;
        $l = self::HANGUL_L_BASE + intdiv($sIndex, self::HANGUL_N_COUNT);
        $v = self::HANGUL_V_BASE + intdiv($sIndex % self::HANGUL_N_COUNT, self::HANGUL_T_COUNT);
        $tIndex = $sIndex % self::HANGUL_T_COUNT;
        $out[] = $l;
        $out[] = $v;
        if ($tIndex !== 0) {
            $out[] = self::HANGUL_T_BASE + $tIndex;
        }
        return true;
    }

    private static function hangulCompose(int $a, int $b): ?int
    {
        // L + V
        if (
            $a >= self::HANGUL_L_BASE && $a < self::HANGUL_L_BASE + self::HANGUL_L_COUNT
            && $b >= self::HANGUL_V_BASE && $b < self::HANGUL_V_BASE + self::HANGUL_V_COUNT
        ) {
            $lIndex = $a - self::HANGUL_L_BASE;
            $vIndex = $b - self::HANGUL_V_BASE;
            return self::HANGUL_S_BASE + ($lIndex * self::HANGUL_V_COUNT + $vIndex) * self::HANGUL_T_COUNT;
        }
        // LV + T
        if (
            $a >= self::HANGUL_S_BASE && $a < self::HANGUL_S_BASE + self::HANGUL_S_COUNT
            && ($a - self::HANGUL_S_BASE) % self::HANGUL_T_COUNT === 0
            && $b > self::HANGUL_T_BASE && $b < self::HANGUL_T_BASE + self::HANGUL_T_COUNT
        ) {
            return $a + ($b - self::HANGUL_T_BASE);
        }
        return null;
    }

    // ── Full canonical decomposition ────────────────────────────────────

    /** @param list<int> $out */
    private static function decomposeOne(int $cp, array &$out): void
    {
        if (self::hangulDecompose($cp, $out)) {
            return;
        }
        $table = self::ucdTable();
        if (isset($table[$cp]) && $table[$cp]['canonical'] !== null) {
            foreach ($table[$cp]['canonical'] as $child) {
                self::decomposeOne($child, $out);
            }
            return;
        }
        $out[] = $cp;
    }

    /**
     * @param list<int> $input
     * @return list<int>
     */
    private static function canonicalDecompose(array $input): array
    {
        $out = [];
        foreach ($input as $cp) {
            self::decomposeOne($cp, $out);
        }
        return $out;
    }

    /// Canonical reordering (stable sort by CCC within non-starter runs).
    ///
    /// @param list<int> $seq
    /// @return list<int>
    private static function canonicalReorder(array $seq): array
    {
        $n = count($seq);
        $i = 0;
        while ($i < $n) {
            if (self::ccc($seq[$i]) === 0) {
                $i++;
                continue;
            }
            $j = $i;
            while ($j < $n && self::ccc($seq[$j]) !== 0) {
                $j++;
            }
            $run = array_slice($seq, $i, $j - $i);
            // Stable sort by CCC (PHP sort is stable on 8.0+).
            usort($run, static fn (int $a, int $b): int => self::ccc($a) <=> self::ccc($b));
            array_splice($seq, $i, $j - $i, $run);
            $i = $j;
        }
        return $seq;
    }

    /// Canonical composition (UAX #15 D115 blocking).
    ///
    /// @param list<int> $seq
    /// @return list<int>
    private static function canonicalCompose(array $seq): array
    {
        if ($seq === []) {
            return [];
        }
        $comp = self::compositionTable();
        $out = [];
        $starterIdx = null;
        $lastCcc = -1;

        foreach ($seq as $cp) {
            $cpCcc = self::ccc($cp);

            if ($starterIdx !== null) {
                $starter = $out[$starterIdx];
                $composed = self::hangulCompose($starter, $cp);
                if ($composed === null) {
                    $composed = $comp[$starter][$cp] ?? null;
                }

                $blocked = $lastCcc !== 0 && ($cpCcc === 0 || $lastCcc >= $cpCcc);

                if (!$blocked && $composed !== null) {
                    $out[$starterIdx] = $composed;
                    // last_ccc unchanged — combiner merged into the starter.
                    continue;
                }
            }

            $out[] = $cp;
            if ($cpCcc === 0) {
                $starterIdx = count($out) - 1;
                $lastCcc = 0;
            } else {
                $lastCcc = $cpCcc;
            }
        }

        return $out;
    }

    /**
     * @param list<int> $input
     * @return list<int>
     */
    public static function toNfc(array $input): array
    {
        $nfd = self::canonicalDecompose($input);
        $nfd = self::canonicalReorder($nfd);
        return self::canonicalCompose($nfd);
    }

    /// UAX #15 NFD — canonical decompose + canonical reorder.
    ///
    /// @param list<int> $input
    /// @return list<int>
    public static function toNfd(array $input): array
    {
        $seq = self::canonicalDecompose($input);
        return self::canonicalReorder($seq);
    }

    // ── Full compatibility decomposition (NFKD/NFKC) ────────────────────

    /** @param list<int> $out */
    private static function compatDecomposeOne(int $cp, array &$out): void
    {
        if (self::hangulDecompose($cp, $out)) {
            return;
        }
        $table = self::ucdTable();
        if (isset($table[$cp])) {
            if ($table[$cp]['compat'] !== null) {
                foreach ($table[$cp]['compat'] as $child) {
                    self::compatDecomposeOne($child, $out);
                }
                return;
            }
            if ($table[$cp]['canonical'] !== null) {
                foreach ($table[$cp]['canonical'] as $child) {
                    self::compatDecomposeOne($child, $out);
                }
                return;
            }
        }
        $out[] = $cp;
    }

    /**
     * @param list<int> $input
     * @return list<int>
     */
    private static function compatDecompose(array $input): array
    {
        $out = [];
        foreach ($input as $cp) {
            self::compatDecomposeOne($cp, $out);
        }
        return $out;
    }

    /// UAX #15 NFKD — full compatibility decompose + canonical reorder.
    ///
    /// @param list<int> $input
    /// @return list<int>
    public static function toNfkd(array $input): array
    {
        $seq = self::compatDecompose($input);
        return self::canonicalReorder($seq);
    }

    /// UAX #15 NFKC — NFKD followed by canonical recomposition.
    ///
    /// @param list<int> $input
    /// @return list<int>
    public static function toNfkc(array $input): array
    {
        return self::canonicalCompose(self::toNfkd($input));
    }

    // ── CaseFolding.txt — default full case folding ─────────────────────

    /** @return array<int,list<int>> */
    private static function caseFoldingTable(): array
    {
        if (self::$caseFolding !== null) {
            return self::$caseFolding;
        }
        $out = [];
        foreach (Data::lines('CaseFolding.txt') as $line) {
            $stripped = self::stripCommentAndTrim($line);
            if ($stripped === '') {
                continue;
            }
            $parts = array_map('trim', explode(';', $stripped));
            if (count($parts) < 3) {
                continue;
            }
            $status = $parts[1];
            // Keep only status C (Common) and F (Full) — the RFC 8265 § 5.2.4
            // "default full case folding" union.
            if ($status !== 'C' && $status !== 'F') {
                continue;
            }
            $src = self::parseHex($parts[0]);
            if ($src === null) {
                continue;
            }
            $tgt = self::parseCodepoints($parts[2]);
            if ($tgt !== []) {
                $out[$src] = $tgt;
            }
        }
        self::$caseFolding = $out;
        return $out;
    }

    /// Default full case folding of a codepoint sequence.
    ///
    /// @param list<int> $input
    /// @return list<int>
    public static function caseFold(array $input): array
    {
        $table = self::caseFoldingTable();
        $out = [];
        foreach ($input as $cp) {
            if (isset($table[$cp])) {
                foreach ($table[$cp] as $c) {
                    $out[] = $c;
                }
            } else {
                $out[] = $cp;
            }
        }
        return $out;
    }

    // ── Scripts.txt — codepoint → primary script ────────────────────────

    /** @return list<array{0:int,1:int,2:string}> */
    private static function scriptsTable(): array
    {
        if (self::$scripts !== null) {
            return self::$scripts;
        }
        $out = [];
        foreach (Data::lines('Scripts.txt') as $line) {
            $stripped = self::stripCommentAndTrim($line);
            if ($stripped === '') {
                continue;
            }
            $parts = explode(';', $stripped, 2);
            if (count($parts) < 2) {
                continue;
            }
            $range = self::parseRangeField($parts[0]);
            if ($range === null) {
                continue;
            }
            $out[] = [$range[0], $range[1], trim($parts[1])];
        }
        usort($out, static fn (array $a, array $b): int => $a[0] <=> $b[0]);
        self::$scripts = $out;
        return $out;
    }

    public static function scriptOf(int $cp): string
    {
        $table = self::scriptsTable();
        $idx = self::lastStartLe($table, $cp);
        if ($idx >= 0 && $cp <= $table[$idx][1]) {
            return $table[$idx][2];
        }
        return 'Unknown';
    }

    // ── ScriptExtensions.txt — codepoint → list of scripts (abbrev) ─────

    /** @return list<array{0:int,1:int,2:list<string>}> */
    private static function scriptExtensionsTable(): array
    {
        if (self::$scriptExtensions !== null) {
            return self::$scriptExtensions;
        }
        $out = [];
        foreach (Data::lines('ScriptExtensions.txt') as $line) {
            $stripped = self::stripCommentAndTrim($line);
            if ($stripped === '') {
                continue;
            }
            $parts = explode(';', $stripped, 2);
            if (count($parts) < 2) {
                continue;
            }
            $range = self::parseRangeField($parts[0]);
            if ($range === null) {
                continue;
            }
            $value = preg_split('/\s+/', trim($parts[1]), -1, PREG_SPLIT_NO_EMPTY) ?: [];
            if ($value !== []) {
                $out[] = [$range[0], $range[1], array_values($value)];
            }
        }
        usort($out, static fn (array $a, array $b): int => $a[0] <=> $b[0]);
        self::$scriptExtensions = $out;
        return $out;
    }

    /// Resolve scripts for `cp`: the ScriptExtensions list when present,
    /// otherwise the single primary script from Scripts.txt (as abbreviation).
    ///
    /// @return list<string>
    public static function resolveScripts(int $cp): array
    {
        $table = self::scriptExtensionsTable();
        $idx = self::lastStartLe($table, $cp);
        if ($idx >= 0 && $cp <= $table[$idx][1]) {
            return $table[$idx][2];
        }
        $primary = self::scriptOf($cp);
        return [self::scriptLongToAbbrev($primary)];
    }

    /** @return array<string,string> */
    private static function scriptNameToAbbrev(): array
    {
        if (self::$scriptNameToAbbrev !== null) {
            return self::$scriptNameToAbbrev;
        }
        $out = [];
        foreach (Data::lines('PropertyValueAliases.txt') as $line) {
            $stripped = self::stripCommentAndTrim($line);
            if ($stripped === '') {
                continue;
            }
            $parts = array_map('trim', explode(';', $stripped));
            if (count($parts) < 3) {
                continue;
            }
            if ($parts[0] !== 'sc') {
                continue;
            }
            $out[$parts[2]] = $parts[1];
        }
        self::$scriptNameToAbbrev = $out;
        return $out;
    }

    private static function scriptLongToAbbrev(string $name): string
    {
        $table = self::scriptNameToAbbrev();
        if (isset($table[$name])) {
            return $table[$name];
        }
        throw new \RuntimeException("scriptLongToAbbrev: '{$name}' not in PropertyValueAliases.txt");
    }

    public static function isCommonScript(int $cp): bool
    {
        return self::scriptOf($cp) === 'Common';
    }

    public static function isInheritedScript(int $cp): bool
    {
        return self::scriptOf($cp) === 'Inherited';
    }

    public static function isIgnoredForIntersection(int $cp): bool
    {
        return self::isCommonScript($cp) || self::isInheritedScript($cp);
    }

    /// The union of all resolved scripts across non-Common, non-Inherited
    /// codepoints of `input`.
    ///
    /// @param list<int> $input
    /// @return list<string>
    public static function stringScriptUnion(array $input): array
    {
        $acc = [];
        foreach ($input as $cp) {
            if (self::isIgnoredForIntersection($cp)) {
                continue;
            }
            foreach (self::resolveScripts($cp) as $s) {
                if (!in_array($s, $acc, true)) {
                    $acc[] = $s;
                }
            }
        }
        return $acc;
    }

    // ── IdentifierStatus.txt — UTS #39 Allowed set ──────────────────────

    /** @return list<array{0:int,1:int}> */
    private static function identifierAllowedRanges(): array
    {
        if (self::$identifierAllowed !== null) {
            return self::$identifierAllowed;
        }
        $out = [];
        foreach (Data::lines('IdentifierStatus.txt') as $line) {
            $stripped = self::stripCommentAndTrim($line);
            if ($stripped === '') {
                continue;
            }
            $parts = explode(';', $stripped, 2);
            if (count($parts) < 2) {
                continue;
            }
            if (trim($parts[1]) !== 'Allowed') {
                continue;
            }
            $range = self::parseRangeField($parts[0]);
            if ($range !== null) {
                $out[] = [$range[0], $range[1]];
            }
        }
        usort($out, static fn (array $a, array $b): int => $a[0] <=> $b[0]);
        self::$identifierAllowed = $out;
        return $out;
    }

    public static function isIdAllowed(int $cp): bool
    {
        $table = self::identifierAllowedRanges();
        $idx = self::lastStartLe($table, $cp);
        return $idx >= 0 && $cp <= $table[$idx][1];
    }

    // ── DerivedCoreProperties.txt — XID_Start / XID_Continue (UAX #31) ──

    /** @return list<array{0:int,1:int}> */
    private static function xidStartRanges(): array
    {
        if (self::$xidStartRanges === null) {
            self::$xidStartRanges = self::parseCasingProperty('XID_Start', true);
        }
        return self::$xidStartRanges;
    }

    /** @return list<array{0:int,1:int}> */
    private static function xidContinueRanges(): array
    {
        if (self::$xidContinueRanges === null) {
            self::$xidContinueRanges = self::parseCasingProperty('XID_Continue', true);
        }
        return self::$xidContinueRanges;
    }

    /// True iff `cp` carries the `XID_Start` derived property.
    public static function isXidStart(int $cp): bool
    {
        $table = self::xidStartRanges();
        $idx = self::lastStartLe($table, $cp);
        return $idx >= 0 && $cp <= $table[$idx][1];
    }

    /// True iff `cp` carries the `XID_Continue` derived property.
    public static function isXidContinue(int $cp): bool
    {
        $table = self::xidContinueRanges();
        $idx = self::lastStartLe($table, $cp);
        return $idx >= 0 && $cp <= $table[$idx][1];
    }

    /// UAX #31 default identifier start: `XID_Start` or LOW LINE (U+005F).
    public static function isDefaultIdStart(int $cp): bool
    {
        return self::isXidStart($cp) || $cp === 0x005F;
    }

    /// UAX #31 default identifier continue: `XID_Continue`.
    public static function isDefaultIdContinue(int $cp): bool
    {
        return self::isXidContinue($cp);
    }

    /**
     * UAX #31 default-identifier syntax over a whole codepoint sequence: a
     * non-empty run whose head is a default id-start and whose tail is all
     * default id-continue. The empty sequence is not a valid identifier.
     * @param list<int> $cps
     */
    public static function isDefaultIdentifier(array $cps): bool
    {
        $cps = array_values($cps);
        if ($cps === []) {
            return false;
        }
        if (!self::isDefaultIdStart($cps[0])) {
            return false;
        }
        $count = count($cps);
        for ($i = 1; $i < $count; $i++) {
            if (!self::isDefaultIdContinue($cps[$i])) {
                return false;
            }
        }
        return true;
    }

    /**
     * UTS #39 whole-string admissibility: a UAX #31 default identifier every
     * codepoint of which additionally has `Identifier_Status = Allowed`.
     * @param list<int> $cps
     */
    public static function isAllowedIdentifier(array $cps): bool
    {
        if (!self::isDefaultIdentifier($cps)) {
            return false;
        }
        foreach ($cps as $cp) {
            if (!self::isIdAllowed($cp)) {
                return false;
            }
        }
        return true;
    }

    // ── DerivedCoreProperties.txt — Default_Ignorable_Code_Point ────────

    /** @return list<array{0:int,1:int}> */
    private static function defaultIgnorableRanges(): array
    {
        if (self::$defaultIgnorable !== null) {
            return self::$defaultIgnorable;
        }
        self::$defaultIgnorable = self::parseCasingProperty('Default_Ignorable_Code_Point', true);
        return self::$defaultIgnorable;
    }

    /// True iff `cp` has the `Default_Ignorable_Code_Point` derived property.
    public static function isDefaultIgnorable(int $cp): bool
    {
        $table = self::defaultIgnorableRanges();
        $idx = self::lastStartLe($table, $cp);
        return $idx >= 0 && $cp <= $table[$idx][1];
    }

    /// True iff `cp` is a whitespace codepoint per UCD `White_Space`.
    public static function isWhiteSpace(int $cp): bool
    {
        return ($cp >= 0x0009 && $cp <= 0x000D)
            || $cp === 0x0020
            || $cp === 0x0085
            || $cp === 0x00A0
            || $cp === 0x1680
            || ($cp >= 0x2000 && $cp <= 0x200A)
            || ($cp >= 0x2028 && $cp <= 0x2029)
            || $cp === 0x202F
            || $cp === 0x205F
            || $cp === 0x3000;
    }

    // ── UTS #39 § 5.1 restriction-level classification ──────────────────

    /** @param list<int> $cps */
    public static function isAsciiOnly(array $cps): bool
    {
        foreach ($cps as $cp) {
            if ($cp >= 0x80) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param list<list<string>> $sets
     * @return list<string>
     */
    private static function intersectMany(array $sets): array
    {
        if ($sets === []) {
            return [];
        }
        $acc = $sets[0];
        $rest = array_slice($sets, 1);
        foreach ($rest as $s) {
            $acc = array_values(array_filter($acc, static fn (string $x): bool => in_array($x, $s, true)));
        }
        return $acc;
    }

    /**
     * @param list<int> $cps
     * @return list<string>
     */
    public static function stringResolvedScripts(array $cps): array
    {
        $nonIgnored = [];
        foreach ($cps as $cp) {
            if (!self::isIgnoredForIntersection($cp)) {
                $nonIgnored[] = $cp;
            }
        }
        if ($nonIgnored === []) {
            return [];
        }
        $sets = array_map(static fn (int $cp): array => self::resolveScripts($cp), $nonIgnored);
        return self::intersectMany($sets);
    }

    /** @param list<int> $cps */
    public static function isSingleScript(array $cps): bool
    {
        return !self::isAsciiOnly($cps) && self::stringResolvedScripts($cps) !== [];
    }

    /**
     * @param list<int> $cps
     * @param list<string> $covered
     */
    private static function allWithinCovered(array $cps, array $covered): bool
    {
        foreach ($cps as $cp) {
            if (self::isIgnoredForIntersection($cp)) {
                continue;
            }
            $r = self::resolveScripts($cp);
            if ($r === [] || !self::intersects($r, $covered)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param list<string> $a
     * @param list<string> $b
     */
    private static function intersects(array $a, array $b): bool
    {
        foreach ($a as $x) {
            if (in_array($x, $b, true)) {
                return true;
            }
        }
        return false;
    }

    /** @param list<int> $cps */
    public static function isCoveredCjk(array $cps): bool
    {
        return self::allWithinCovered($cps, ['Latn', 'Hani', 'Hira', 'Kana'])
            || self::allWithinCovered($cps, ['Latn', 'Hani', 'Bopo'])
            || self::allWithinCovered($cps, ['Latn', 'Hani', 'Hang']);
    }

    /** @param list<int> $cps */
    public static function isHighlyRestrictive(array $cps): bool
    {
        return self::isSingleScript($cps) || self::isCoveredCjk($cps);
    }

    /** @param list<int> $cps */
    public static function isModeratelyRestrictiveShape(array $cps): bool
    {
        $other = null;
        foreach ($cps as $cp) {
            if (self::isIgnoredForIntersection($cp)) {
                continue;
            }
            $r = self::resolveScripts($cp);
            if ($r === []) {
                return false;
            }
            if (in_array('Latn', $r, true)) {
                continue;
            }
            $s = $r[0];
            if ($s === 'Cyrl' || $s === 'Grek') {
                return false;
            }
            if ($other === null) {
                $other = $s;
            } elseif ($s !== $other) {
                return false;
            }
        }
        return $other !== null;
    }

    /** @param list<int> $cps */
    public static function isMinimallyRestrictive(array $cps): bool
    {
        foreach ($cps as $cp) {
            if (!self::isIdAllowed($cp)) {
                return false;
            }
        }
        return true;
    }

    /** @param list<int> $cps */
    public static function restrictionLevel(array $cps): RestrictionLevel
    {
        if (self::isAsciiOnly($cps)) {
            return RestrictionLevel::AsciiOnly;
        }
        if (self::isSingleScript($cps)) {
            return RestrictionLevel::SingleScript;
        }
        if (self::isHighlyRestrictive($cps)) {
            return RestrictionLevel::HighlyRestrictive;
        }
        if (self::isModeratelyRestrictiveShape($cps)) {
            return RestrictionLevel::ModeratelyRestrictive;
        }
        if (self::isMinimallyRestrictive($cps)) {
            return RestrictionLevel::MinimallyRestrictive;
        }
        return RestrictionLevel::Unrestricted;
    }

    // ── UAX #21 case mapping (toLower) ──────────────────────────────────

    /** @return array<int,list<array{lower:list<int>,upper:list<int>,conditions:list<string>}>> */
    private static function specialCasingRows(): array
    {
        if (self::$specialCasing !== null) {
            return self::$specialCasing;
        }
        $rows = [];
        foreach (Data::lines('SpecialCasing.txt') as $line) {
            $stripped = self::stripCommentAndTrim($line);
            if ($stripped === '') {
                continue;
            }
            $fields = array_map('trim', explode(';', $stripped));
            if (count($fields) < 4) {
                continue;
            }
            $code = self::parseHex($fields[0]);
            if ($code === null) {
                continue;
            }
            $conditions = [];
            if (count($fields) > 4 && $fields[4] !== '') {
                $conditions = preg_split('/\s+/', $fields[4], -1, PREG_SPLIT_NO_EMPTY) ?: [];
                $conditions = array_values($conditions);
            }
            // SpecialCasing.txt: `code; lower; title; upper; conditions`.
            // Field 1 is the full lowercase mapping, field 3 the full uppercase.
            $rows[$code][] = [
                'lower' => self::parseCodepoints($fields[1]),
                'upper' => self::parseCodepoints($fields[3]),
                'conditions' => $conditions,
            ];
        }
        self::$specialCasing = $rows;
        return $rows;
    }

    /** @return array<int,int> */
    private static function simpleLowercaseTable(): array
    {
        if (self::$simpleLowercase !== null) {
            return self::$simpleLowercase;
        }
        $lower = [];
        foreach (Data::lines('UnicodeData.txt') as $line) {
            $fields = explode(';', $line);
            if (count($fields) < 15) {
                continue;
            }
            $cp = self::parseHex($fields[0]);
            if ($cp === null || $fields[13] === '') {
                continue;
            }
            $l = self::parseHex($fields[13]);
            if ($l !== null) {
                $lower[$cp] = $l;
            }
        }
        self::$simpleLowercase = $lower;
        return $lower;
    }

    private static function simpleLowercase(int $cp): int
    {
        return self::simpleLowercaseTable()[$cp] ?? $cp;
    }

    /** @return array<int,int> */
    private static function simpleUppercaseTable(): array
    {
        if (self::$simpleUppercase !== null) {
            return self::$simpleUppercase;
        }
        $upper = [];
        foreach (Data::lines('UnicodeData.txt') as $line) {
            $fields = explode(';', $line);
            if (count($fields) < 15) {
                continue;
            }
            // Field 12 (0-based) is the simple uppercase mapping.
            $cp = self::parseHex($fields[0]);
            if ($cp === null || $fields[12] === '') {
                continue;
            }
            $u = self::parseHex($fields[12]);
            if ($u !== null) {
                $upper[$cp] = $u;
            }
        }
        self::$simpleUppercase = $upper;
        return $upper;
    }

    private static function simpleUppercase(int $cp): int
    {
        return self::simpleUppercaseTable()[$cp] ?? $cp;
    }

    /**
     * @return list<array{0:int,1:int}>
     */
    private static function parseCasingProperty(string $name, bool $sort): array
    {
        $out = [];
        foreach (Data::lines('DerivedCoreProperties.txt') as $line) {
            $stripped = self::stripCommentAndTrim($line);
            if ($stripped === '') {
                continue;
            }
            $parts = explode(';', $stripped, 2);
            if (count($parts) < 2 || trim($parts[1]) !== $name) {
                continue;
            }
            $range = self::parseRangeField($parts[0]);
            if ($range !== null) {
                $out[] = [$range[0], $range[1]];
            }
        }
        if ($sort) {
            usort($out, static fn (array $a, array $b): int => $a[0] <=> $b[0]);
        }
        return $out;
    }

    /** @return list<array{0:int,1:int}> */
    private static function casedRanges(): array
    {
        if (self::$casedRanges === null) {
            self::$casedRanges = self::parseCasingProperty('Cased', false);
        }
        return self::$casedRanges;
    }

    /** @return list<array{0:int,1:int}> */
    private static function softDottedRanges(): array
    {
        if (self::$softDottedRanges === null) {
            self::$softDottedRanges = self::parseCasingProperty('Soft_Dotted', false);
        }
        return self::$softDottedRanges;
    }

    /** @param list<array{0:int,1:int}> $ranges */
    private static function inRanges(array $ranges, int $cp): bool
    {
        foreach ($ranges as [$lo, $hi]) {
            if ($lo <= $cp && $cp <= $hi) {
                return true;
            }
        }
        return false;
    }

    private static function isCased(int $cp): bool
    {
        return self::inRanges(self::casedRanges(), $cp);
    }

    private static function isSoftDotted(int $cp): bool
    {
        return self::inRanges(self::softDottedRanges(), $cp);
    }

    // Context predicates (UAX #21). `revPrefix` is the preceding codepoints
    // nearest-first; `suffix` the strictly-following ones.

    /** @param list<int> $suffix */
    private static function moreAboveAfter(array $suffix): bool
    {
        foreach ($suffix as $cp) {
            $c = self::ccc($cp);
            if ($c === 230) {
                return true;
            }
            if ($c === 0) {
                return false;
            }
        }
        return false;
    }

    /** @param list<int> $revPrefix */
    private static function afterSoftDotted(array $revPrefix): bool
    {
        foreach ($revPrefix as $cp) {
            if (self::isSoftDotted($cp)) {
                return true;
            }
            $c = self::ccc($cp);
            if ($c === 0 || $c === 230) {
                return false;
            }
        }
        return false;
    }

    /** @param list<int> $revPrefix */
    private static function afterI(array $revPrefix): bool
    {
        foreach ($revPrefix as $cp) {
            if ($cp === 0x0049) {
                return true;
            }
            $c = self::ccc($cp);
            if ($c === 0 || $c === 230) {
                return false;
            }
        }
        return false;
    }

    /** @param list<int> $suffix */
    private static function beforeDot(array $suffix): bool
    {
        foreach ($suffix as $cp) {
            if ($cp === 0x0307) {
                return true;
            }
            if (self::ccc($cp) === 0) {
                return false;
            }
        }
        return false;
    }

    /** @param list<int> $revPrefix */
    private static function hasCasedBefore(array $revPrefix): bool
    {
        foreach ($revPrefix as $cp) {
            if (self::isCased($cp)) {
                return true;
            }
            if (self::ccc($cp) === 0) {
                return false;
            }
        }
        return false;
    }

    /** @param list<int> $suffix */
    private static function hasCasedAfter(array $suffix): bool
    {
        foreach ($suffix as $cp) {
            if (self::isCased($cp)) {
                return true;
            }
            if (self::ccc($cp) === 0) {
                return false;
            }
        }
        return false;
    }

    /**
     * @param list<int> $revPrefix
     * @param list<int> $suffix
     */
    private static function finalSigma(array $revPrefix, array $suffix): bool
    {
        return self::hasCasedBefore($revPrefix) && !self::hasCasedAfter($suffix);
    }

    private static function isLocaleCondition(string $condition): bool
    {
        return $condition === 'tr' || $condition === 'az' || $condition === 'lt';
    }

    /** @param list<string> $conditions */
    private static function localeMatches(Locale $locale, array $conditions): bool
    {
        $hasLocale = false;
        foreach ($conditions as $c) {
            if (self::isLocaleCondition($c)) {
                $hasLocale = true;
                break;
            }
        }
        if (!$hasLocale) {
            return true;
        }
        foreach ($conditions as $c) {
            if (
                ($c === 'tr' && $locale === Locale::Turkish)
                || ($c === 'az' && $locale === Locale::Azeri)
                || ($c === 'lt' && $locale === Locale::Lithuanian)
            ) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param list<int> $revPrefix
     * @param list<int> $suffix
     * @param list<string> $conditions
     */
    private static function conditionsHold(Locale $locale, array $revPrefix, array $suffix, array $conditions): bool
    {
        if (!self::localeMatches($locale, $conditions)) {
            return false;
        }
        foreach ($conditions as $c) {
            if (self::isLocaleCondition($c)) {
                continue;
            }
            $ok = match ($c) {
                'Final_Sigma' => self::finalSigma($revPrefix, $suffix),
                'Not_Final_Sigma' => !self::finalSigma($revPrefix, $suffix),
                'After_Soft_Dotted' => self::afterSoftDotted($revPrefix),
                'More_Above' => self::moreAboveAfter($suffix),
                'Not_Before_Dot' => !self::beforeDot($suffix),
                'After_I' => self::afterI($revPrefix),
                default => false,
            };
            if (!$ok) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param list<int> $revPrefix
     * @param list<int> $suffix
     * @return array{lower:list<int>,upper:list<int>,conditions:list<string>}|null
     */
    private static function findSpecialRow(Locale $locale, array $revPrefix, array $suffix, int $cp): ?array
    {
        $candidates = self::specialCasingRows()[$cp] ?? null;
        if ($candidates === null) {
            return null;
        }
        foreach ($candidates as $row) {
            if ($row['conditions'] !== [] && self::conditionsHold($locale, $revPrefix, $suffix, $row['conditions'])) {
                return $row;
            }
        }
        foreach ($candidates as $row) {
            if ($row['conditions'] === []) {
                return $row;
            }
        }
        return null;
    }

    /// Lowercase a single codepoint in its full input context (UAX #21).
    ///
    /// @param list<int> $revPrefix preceding codepoints, nearest-first
    /// @param list<int> $suffix strictly-following codepoints
    /// @return list<int>
    public static function lowerCodepoint(Locale $locale, array $revPrefix, array $suffix, int $cp): array
    {
        $row = self::findSpecialRow($locale, $revPrefix, $suffix, $cp);
        if ($row !== null) {
            return $row['lower'];
        }
        return [self::simpleLowercase($cp)];
    }

    /// Uppercase a single codepoint in its full input context (UAX #21): the
    /// SpecialCasing row whose conditions hold (its uppercase column), else the
    /// simple uppercase mapping. Mirrors `lowerCodepoint` exactly, reusing the
    /// same context machinery; exposed so context-sensitive detectors can
    /// measure the case-mapped length per position.
    ///
    /// @param list<int> $revPrefix preceding codepoints, nearest-first
    /// @param list<int> $suffix strictly-following codepoints
    /// @return list<int>
    public static function upperCodepoint(Locale $locale, array $revPrefix, array $suffix, int $cp): array
    {
        $row = self::findSpecialRow($locale, $revPrefix, $suffix, $cp);
        if ($row !== null) {
            return $row['upper'];
        }
        return [self::simpleUppercase($cp)];
    }

    /// Lowercase a codepoint sequence under `locale` (UAX #21 full case mapping).
    ///
    /// @param list<int> $cps
    /// @return list<int>
    public static function toLower(Locale $locale, array $cps): array
    {
        $out = [];
        $revPrefix = [];
        $n = count($cps);
        for ($index = 0; $index < $n; $index++) {
            $cp = $cps[$index];
            $suffix = array_slice($cps, $index + 1);
            foreach (self::lowerCodepoint($locale, $revPrefix, $suffix, $cp) as $c) {
                $out[] = $c;
            }
            array_unshift($revPrefix, $cp);
        }
        return $out;
    }
}
