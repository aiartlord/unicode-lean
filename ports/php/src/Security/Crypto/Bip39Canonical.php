<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Crypto;

use UnicodePhp\Data;
use UnicodePhp\Security\Identity\Locale;
use UnicodePhp\Security\Identity\Ucd;
use UnicodePhp\Utf8;

final class Bip39Verdict
{
    /** @param list<int> $positions @param list<int> $canonical */
    public function __construct(
        public readonly ?string $sub,
        public readonly array $positions,
        public readonly ?string $language,
        public readonly array $canonical,
        public readonly int $wordCount,
    ) {
    }
}

final class Bip39Canonical
{
    private const WORDLIST_FILES = [
        ['english', 'english.txt'],
        ['japanese', 'japanese.txt'],
        ['korean', 'korean.txt'],
        ['spanish', 'spanish.txt'],
        ['chinese_simplified', 'chinese_simplified.txt'],
        ['chinese_traditional', 'chinese_traditional.txt'],
        ['french', 'french.txt'],
        ['italian', 'italian.txt'],
        ['czech', 'czech.txt'],
        ['portuguese', 'portuguese.txt'],
    ];

    /** @var list<array{name:string,set:array<string,bool>}>|null */
    private static ?array $wordlists = null;

    /** @param list<int> $cps */
    private static function key(array $cps): string
    {
        return implode(',', $cps);
    }

    private static function wordlistSet(string $raw): array
    {
        $set = [];
        foreach (explode("\n", $raw) as $line) {
            $line = rtrim($line, "\r");
            if ($line !== '') {
                $set[self::key(Utf8::decodeToCodepoints(array_values(unpack('C*', $line) ?: [])))] = true;
            }
        }
        return $set;
    }

    /** @return list<array{name:string,set:array<string,bool>}> */
    private static function wordlists(): array
    {
        if (self::$wordlists !== null) {
            return self::$wordlists;
        }
        $out = [];
        foreach (self::WORDLIST_FILES as [$name, $file]) {
            $out[] = ['name' => $name, 'set' => self::wordlistSet(Data::read('bip39/' . $file))];
        }
        self::$wordlists = $out;
        return $out;
    }

    /** @param list<int> $canonical @return list<list<int>> */
    private static function splitWords(array $canonical): array
    {
        $words = [];
        $current = [];
        foreach ($canonical as $cp) {
            if ($cp === 0x20) {
                if ($current !== []) {
                    $words[] = $current;
                    $current = [];
                }
            } else {
                $current[] = $cp;
            }
        }
        if ($current !== []) {
            $words[] = $current;
        }
        return $words;
    }

    /** @param list<int> $word @return list<string> */
    private static function wordlistsContaining(array $word): array
    {
        $out = [];
        $key = self::key($word);
        foreach (self::wordlists() as $wl) {
            if (isset($wl['set'][$key])) {
                $out[] = $wl['name'];
            }
        }
        return $out;
    }

    /** @param list<list<int>> $words */
    private static function uniqueLanguage(array $words): ?string
    {
        foreach (self::wordlists() as $wl) {
            $ok = true;
            foreach ($words as $word) {
                if (!isset($wl['set'][self::key($word)])) {
                    $ok = false;
                    break;
                }
            }
            if ($ok) {
                return $wl['name'];
            }
        }
        return null;
    }

    private static function bip39Whitespace(int $cp): bool
    {
        return $cp === 0x20 || $cp === 0x3000;
    }

    /** @param list<int> $cps @return list<int> */
    private static function collapseWhitespaceToSingle(array $cps): array
    {
        $out = [];
        $inWs = false;
        foreach ($cps as $cp) {
            if (self::bip39Whitespace($cp)) {
                if (!$inWs) {
                    $out[] = 0x20;
                }
                $inWs = true;
            } else {
                $out[] = $cp;
                $inWs = false;
            }
        }
        return $out;
    }

    /** @param list<int> $cps @return list<int> */
    private static function trimLeadingTrailing(array $cps): array
    {
        $start = null;
        foreach ($cps as $i => $cp) {
            if ($cp !== 0x20) {
                $start = $i;
                break;
            }
        }
        if ($start === null) {
            return [];
        }
        $end = $start;
        for ($i = count($cps) - 1; $i >= $start; $i--) {
            if ($cps[$i] !== 0x20) {
                $end = $i;
                break;
            }
        }
        return array_slice($cps, $start, $end - $start + 1);
    }

    /** @param list<int> $cps @return list<int> */
    public static function bip39Canonical(array $cps): array
    {
        return self::trimLeadingTrailing(self::collapseWhitespaceToSingle(Ucd::toLower(Locale::Default, Ucd::toNfkd($cps))));
    }

    /** @param list<int> $cps */
    private static function countTrailingWhitespace(array $cps): int
    {
        $count = 0;
        for ($i = count($cps) - 1; $i >= 0; $i--) {
            if (!self::bip39Whitespace($cps[$i])) {
                break;
            }
            $count++;
        }
        return $count;
    }

    /** @param list<int> $cps */
    private static function firstUppercasePos(array $cps): ?int
    {
        foreach ($cps as $i => $cp) {
            if ($cp >= 0x41 && $cp <= 0x5A) {
                return $i;
            }
        }
        return null;
    }

    /** @param list<int> $cps */
    private static function firstWhitespaceRunPos(array $cps): ?int
    {
        $count = count($cps);
        for ($i = 0; $i < $count; $i++) {
            if (self::bip39Whitespace($cps[$i]) && ($i === 0 || ($i < $count - 1 && self::bip39Whitespace($cps[$i + 1])))) {
                return $i;
            }
        }
        return null;
    }

    /** @param list<int> $a @param list<int> $b */
    private static function firstArrayDivergence(array $a, array $b): ?int
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
    public static function detect(array $input): Bip39Verdict
    {
        $canonical = self::bip39Canonical($input);
        $words = self::splitWords($canonical);
        $wordCount = count($words);
        $trailingCount = self::countTrailingWhitespace($input);
        $uppercasePos = self::firstUppercasePos($input);
        $whitespacePos = self::firstWhitespaceRunPos($input);
        $nfkd = Ucd::toNfkd($input);
        $nonNfkdPos = $input === $nfkd ? null : self::firstArrayDivergence($input, $nfkd);
        $unknownIdx = null;
        foreach ($words as $i => $word) {
            if (self::wordlistsContaining($word) === []) {
                $unknownIdx = $i;
                break;
            }
        }

        if ($trailingCount > 0) {
            return new Bip39Verdict('TrailingWhitespace', [count($input) - $trailingCount], null, $canonical, $wordCount);
        }
        if ($uppercasePos !== null) {
            return new Bip39Verdict('MixedCase', [$uppercasePos], null, $canonical, $wordCount);
        }
        if ($whitespacePos !== null) {
            return new Bip39Verdict('WhitespaceAnomaly', [$whitespacePos], null, $canonical, $wordCount);
        }
        if ($nonNfkdPos !== null) {
            return new Bip39Verdict('NonNFKD', [$nonNfkdPos], null, $canonical, $wordCount);
        }
        if ($unknownIdx !== null) {
            return new Bip39Verdict('WordlistMismatch', [$unknownIdx], null, $canonical, $wordCount);
        }
        $lang = self::uniqueLanguage($words);
        if ($lang === null) {
            return new Bip39Verdict('LanguageAmbiguous', [], null, $canonical, $wordCount);
        }
        return new Bip39Verdict(null, [], $lang, $canonical, $wordCount);
    }
}
