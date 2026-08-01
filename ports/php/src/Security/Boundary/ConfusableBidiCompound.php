<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Boundary;

use UnicodePhp\Security\Covert\BidiControlBalance;
use UnicodePhp\Security\Identity\HomoglyphConfusable;

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

    /** @param list<int> $input */
    public static function detect(array $input): BoundaryVerdict
    {
        $confusablePos = self::firstPos($input, [HomoglyphConfusable::class, 'confusableSource']);
        if ($confusablePos === null) {
            return new BoundaryVerdict(null, []);
        }
        $overridePos = self::firstPos($input, static fn (int $cp): bool => BidiControlBalance::opensEmbedding($cp) || BidiControlBalance::isPdf($cp));
        if ($overridePos !== null) {
            return new BoundaryVerdict('ConfusableInOverride', [$confusablePos, $overridePos]);
        }
        $isolatePos = self::firstPos($input, static fn (int $cp): bool => BidiControlBalance::opensIsolate($cp) || BidiControlBalance::isPdi($cp));
        if ($isolatePos !== null) {
            return new BoundaryVerdict('ConfusableInIsolate', [$confusablePos, $isolatePos]);
        }
        return new BoundaryVerdict(null, []);
    }
}
