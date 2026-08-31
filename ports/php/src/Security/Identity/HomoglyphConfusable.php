<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Identity;

use UnicodePhp\Data;
use UnicodePhp\Security\ClassificationKind;

final class HomoglyphVerdict
{
    /** @param list<int> $skeleton @param list<int> $iteratedSkeleton @param list<string> $matchedTargets */
    public function __construct(
        public ClassificationKind $kind,
        public ?object $sub,
        public array $skeleton,
        public array $iteratedSkeleton,
        public RestrictionLevel $restrictionLevel,
        public array $matchedTargets,
        public ?string $target,
    ) {
    }
}

final class HomoglyphConfusable
{
    /** @var array<int,list<int>>|null */
    private static ?array $confusables = null;
    /** @var list<array{name:string,cps:list<int>,letters:list<int>}>|null */
    private static ?array $targets = null;

    private static function parseHex(string $s): ?int
    {
        $s = trim($s);
        return $s !== '' && preg_match('/^[0-9A-Fa-f]+$/', $s) === 1 ? (int) hexdec($s) : null;
    }

    /** @return array<int,list<int>> */
    private static function confusables(): array
    {
        if (self::$confusables !== null) {
            return self::$confusables;
        }
        $out = [];
        foreach (Data::lines('confusables.txt') as $raw) {
            $body = trim(explode('#', $raw, 2)[0]);
            if ($body === '') {
                continue;
            }
            $parts = explode(';', $body);
            if (count($parts) < 2) {
                continue;
            }
            $src = self::parseHex($parts[0]);
            $target = [];
            foreach (preg_split('/\s+/', trim($parts[1]), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $tok) {
                $cp = self::parseHex($tok);
                if ($cp !== null) {
                    $target[] = $cp;
                }
            }
            if ($src !== null && $target !== []) {
                $out[$src] = $target;
            }
        }
        self::$confusables = $out;
        return $out;
    }

    public static function confusableSource(int $cp): bool
    {
        return isset(self::confusables()[$cp]);
    }

    /** @param list<int> $input @return list<int> */
    private static function substitute(array $input): array
    {
        $map = self::confusables();
        $out = [];
        foreach ($input as $cp) {
            if (isset($map[$cp])) {
                array_push($out, ...$map[$cp]);
            } else {
                $out[] = $cp;
            }
        }
        return $out;
    }

    /** @param list<int> $input @return list<int> */
    public static function skeleton(array $input): array
    {
        return Ucd::toNfd(Ucd::caseFold(self::substitute(Ucd::caseFold(Ucd::toNfd($input)))));
    }

    /** @param list<int> $input @return list<int> */
    public static function iteratedSkeleton(array $input): array
    {
        $current = array_values($input);
        while (true) {
            $next = self::skeleton($current);
            if ($next === $current) {
                return $current;
            }
            $current = $next;
        }
    }

    /** @param list<int> $iterated @return list<int> */
    private static function letterSkeletonFromIterated(array $iterated): array
    {
        $out = [];
        foreach ($iterated as $cp) {
            if (Ucd::ccc($cp) === 0 && !Ucd::isDefaultIgnorable($cp) && !Ucd::isWhiteSpace($cp)) {
                $out[] = $cp;
            }
        }
        return $out;
    }

    /** @return list<array{name:string,cps:list<int>,letters:list<int>}> */
    private static function targets(): array
    {
        if (self::$targets !== null) {
            return self::$targets;
        }
        $out = [];
        foreach (Data::lines('KnownAttackTargets.txt') as $line) {
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $cps = self::utf8ToCodepoints($line);
            $out[] = ['name' => $line, 'cps' => $cps, 'letters' => self::letterSkeletonFromIterated(self::iteratedSkeleton($cps))];
        }
        self::$targets = $out;
        return $out;
    }

    /** @return list<int> */
    private static function utf8ToCodepoints(string $s): array
    {
        $bytes = array_values(unpack('C*', $s) ?: []);
        return \UnicodePhp\Utf8::decodeToCodepoints($bytes);
    }

    /** @param list<int> $input @param list<int> $iterated */
    private static function findTargetMatch(array $input, array $iterated): ?string
    {
        $letters = self::letterSkeletonFromIterated($iterated);
        foreach (self::targets() as $target) {
            if ($target['cps'] !== $input && $target['letters'] === $letters) {
                return $target['name'];
            }
        }
        return null;
    }

    private static function mathAlphanumeric(int $cp): bool
    {
        return $cp >= 0x1D400 && $cp <= 0x1D7FF;
    }

    private static function fullwidthHalfwidth(int $cp): bool
    {
        return $cp >= 0xFF01 && $cp <= 0xFFEF;
    }

    /** @param list<int> $input */
    public static function hasMixedScriptAdmissibility(array $input): bool
    {
        return self::mixedScriptVerdict($input, true) !== null;
    }

    /** @param list<int> $input */
    public static function mixedScriptSubThreat(array $input): string
    {
        return self::mixedScriptVerdict($input, true) ?? 'ScriptMixOther';
    }

    /**
     * The mixed-script sub-threat for $input, or null when admissible.
     *
     * The rung order is MixedScriptAdmissibility.lean's: a Restricted-status
     * codepoint outranks every script question, then the two named Latin
     * pairs, then a multi-script mix split by whether it stays inside a CJK
     * covered set, and finally an Unrestricted level with no script mix.
     *
     * $identifierField carries what the caller knows about the field,
     * mirroring that module's Context. Phase 1 is sound for an identifier,
     * which cannot contain a space, and unsound for a document, where every
     * space and every punctuation mark is Restricted.
     *
     * @param list<int> $input
     */
    public static function mixedScriptVerdict(array $input, bool $identifierField): ?string
    {
        if ($identifierField) {
            foreach ($input as $cp) {
                if (!Ucd::isIdAllowed($cp)) {
                    return 'RestrictedStatusCp';
                }
            }
        }
        $union = Ucd::stringScriptUnion($input);
        $seen = array_fill_keys($union, true);
        if (isset($seen['Latn'], $seen['Cyrl'])) {
            return 'LatinCyrillic';
        }
        if (isset($seen['Latn'], $seen['Grek'])) {
            return 'LatinGreek';
        }
        if (count($union) >= 2 && !Ucd::isHighlyRestrictive($input)) {
            return Ucd::isCoveredCjk($input) ? 'CjkMix' : 'ScriptMixOther';
        }
        if ($identifierField && Ucd::restrictionLevel($input) === RestrictionLevel::Unrestricted) {
            return 'UnrestrictedLevel';
        }
        return null;
    }

    /** @param list<int> $input */
    public static function detect(array $input): HomoglyphVerdict
    {
        $skel = self::skeleton($input);
        $iskel = self::iteratedSkeleton($input);
        $rl = Ucd::restrictionLevel($input);
        $v = new HomoglyphVerdict(ClassificationKind::Clear, null, $skel, $iskel, $rl, [], null);

        $target = self::findTargetMatch($input, $iskel);
        if ($target !== null) {
            return new HomoglyphVerdict(ClassificationKind::Hazard, (object) ['tag' => 'TargetMatch', 'target' => $target], $skel, $iskel, $rl, [$target], $target);
        }
        foreach ($input as $cp) {
            if (self::mathAlphanumeric($cp)) {
                $v->kind = ClassificationKind::Hazard;
                $v->sub = (object) ['tag' => 'MathAlpha'];
                return $v;
            }
        }
        foreach ($input as $cp) {
            if (self::fullwidthHalfwidth($cp)) {
                $v->kind = ClassificationKind::Hazard;
                $v->sub = (object) ['tag' => 'WidthClass'];
                return $v;
            }
        }
        if (Ucd::toNfc($input) !== $input) {
            $v->kind = ClassificationKind::Hazard;
            $v->sub = (object) ['tag' => 'DecompositionSwap'];
            return $v;
        }
        // Priority 5: CrossScriptMix. This rung asks the script question only;
        // the Restricted-status rung belongs to the mixed-script family.
        $union = Ucd::stringScriptUnion($input);
        if (count($union) >= 2 && !Ucd::isHighlyRestrictive($input)) {
            $v->kind = ClassificationKind::Hazard;
            $v->sub = (object) ['tag' => 'CrossScriptMix'];
            return $v;
        }
        if ($rl === RestrictionLevel::MinimallyRestrictive || $rl === RestrictionLevel::Unrestricted) {
            $v->kind = ClassificationKind::Hazard;
            $v->sub = (object) ['tag' => 'RestrictionLow'];
        }
        return $v;
    }
}
