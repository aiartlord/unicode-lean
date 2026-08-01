<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Covert;

use UnicodePhp\Security\ClassificationKind;

final class BidiControlVerdict
{
    /** @param list<int> $bidiPositions */
    public function __construct(
        public ClassificationKind $kind,
        public ?object $sub,
        public array $bidiPositions,
        public int $embOpenCount,
        public int $embPopCount,
        public int $isoOpenCount,
        public int $isoPopCount,
        public int $maxDepth,
    ) {
    }
}

final class BidiControlBalance
{
    public const UAX_DEPTH_LIMIT = 125;

    public static function opensEmbedding(int $cp): bool
    {
        return $cp === 0x202A || $cp === 0x202B || $cp === 0x202D || $cp === 0x202E;
    }

    public static function isPdf(int $cp): bool
    {
        return $cp === 0x202C;
    }

    public static function opensIsolate(int $cp): bool
    {
        return $cp === 0x2066 || $cp === 0x2067 || $cp === 0x2068;
    }

    public static function isPdi(int $cp): bool
    {
        return $cp === 0x2069;
    }

    public static function isBidiFormatControl(int $cp): bool
    {
        return self::opensEmbedding($cp) || self::isPdf($cp) || self::opensIsolate($cp) || self::isPdi($cp);
    }

    /** @param list<int> $input */
    public static function detect(array $input): BidiControlVerdict
    {
        $v = new BidiControlVerdict(ClassificationKind::Clear, null, [], 0, 0, 0, 0, 0);
        $embStack = 0;
        $isoStack = 0;
        $orphans = [];

        foreach ($input as $i => $cp) {
            if (!self::isBidiFormatControl($cp)) {
                continue;
            }
            $v->bidiPositions[] = $i;
            if (self::opensEmbedding($cp)) {
                $embStack++;
                $v->embOpenCount++;
                $v->maxDepth = max($v->maxDepth, $embStack + $isoStack);
            } elseif (self::isPdf($cp)) {
                $v->embPopCount++;
                if ($embStack > 0) {
                    $embStack--;
                } else {
                    $orphans[] = $i;
                }
            } elseif (self::opensIsolate($cp)) {
                $isoStack++;
                $v->isoOpenCount++;
                $v->maxDepth = max($v->maxDepth, $embStack + $isoStack);
            } elseif (self::isPdi($cp)) {
                $v->isoPopCount++;
                if ($isoStack > 0) {
                    $isoStack--;
                } else {
                    $orphans[] = $i;
                }
            }
        }

        if ($v->bidiPositions === []) {
            return $v;
        }
        if ($v->maxDepth > self::UAX_DEPTH_LIMIT) {
            $v->kind = ClassificationKind::Hazard;
            $v->sub = (object) ['tag' => 'DepthExceeded', 'maxDepth' => $v->maxDepth];
        } elseif ($orphans !== []) {
            $v->kind = ClassificationKind::Hazard;
            $v->sub = (object) ['tag' => 'OrphanPop', 'positions' => $orphans];
        } elseif ($embStack > 0) {
            $v->kind = ClassificationKind::Hazard;
            $v->sub = (object) ['tag' => 'UnbalancedEmbedding', 'openCount' => $v->embOpenCount, 'popCount' => $v->embPopCount];
        } elseif ($isoStack > 0) {
            $v->kind = ClassificationKind::Hazard;
            $v->sub = (object) ['tag' => 'UnbalancedIsolate', 'openCount' => $v->isoOpenCount, 'popCount' => $v->isoPopCount];
        }
        return $v;
    }
}
