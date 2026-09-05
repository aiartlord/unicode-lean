<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Boundary;

use UnicodePhp\Security\Covert\BidiControlBalance;
use UnicodePhp\Security\Display\BidiControlPurpose;
use UnicodePhp\Security\Identity\HomoglyphConfusable;

// Confusable-in-bidi-context compound detector (CVE-2021-42574 class). Fires
// only when a confusable source co-locates with a purposeless bidi control
// (BidiControlPurpose: unbalanced, or a balanced span enclosing nothing
// right-to-left in a left-to-right context); a balanced embedding around Arabic
// text renders that text as written.

final class BoundaryVerdict
{
    /** @param list<int> $positions */
    public function __construct(public readonly ?string $sub, public readonly array $positions)
    {
    }
}

final class ConfusableBidiCompound
{
    /** @param list<int> $input */
    private static function firstPos(array $input, callable $pred): ?int
    {
        foreach ($input as $i => $cp) {
            if ($pred($cp)) {
                return $i;
            }
        }
        return null;
    }

    /**
     * The first position of a purposeless bidi control satisfying $pred, or
     * null. Mirrors the Lean firstOverridePos / firstIsolatePos over the
     * purposeless positions.
     * @param list<int> $input
     */
    private static function firstPurposelessPos(array $input, callable $pred): ?int
    {
        foreach (BidiControlPurpose::purposelessControlPositions($input) as $pos) {
            if ($pred($input[$pos])) {
                return $pos;
            }
        }
        return null;
    }

    /** @param list<int> $input */
    public static function detect(array $input): BoundaryVerdict
    {
        $input = array_values($input);
        $confusablePos = self::firstPos($input, [HomoglyphConfusable::class, 'confusableSource']);
        if ($confusablePos === null) {
            return new BoundaryVerdict(null, []);
        }
        $overridePos = self::firstPurposelessPos($input, static fn (int $cp): bool => BidiControlBalance::opensEmbedding($cp) || BidiControlBalance::isPdf($cp));
        if ($overridePos !== null) {
            return new BoundaryVerdict('ConfusableInOverride', [$confusablePos, $overridePos]);
        }
        $isolatePos = self::firstPurposelessPos($input, static fn (int $cp): bool => BidiControlBalance::opensIsolate($cp) || BidiControlBalance::isPdi($cp));
        if ($isolatePos !== null) {
            return new BoundaryVerdict('ConfusableInIsolate', [$confusablePos, $isolatePos]);
        }
        return new BoundaryVerdict(null, []);
    }
}
