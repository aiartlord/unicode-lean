<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Covert;

use UnicodePhp\Utf8;
use UnicodePhp\Utf8RejectKind;

final class SurrogateReassemblyVerdict
{
    /** @param list<int> $positions */
    public function __construct(
        public readonly ?string $sub,
        public readonly array $positions,
    ) {
    }
}

final class SurrogateReassembly
{
    /** @param list<int> $input */
    public static function looksLikeByteStream(array $input): bool
    {
        foreach ($input as $cp) {
            if ($cp >= 0x100) {
                return false;
            }
        }
        return true;
    }

    private static function subThreatOfRejectKind(Utf8RejectKind $kind): string
    {
        return match ($kind) {
            Utf8RejectKind::OverlongEncoding => 'Overlong',
            Utf8RejectKind::SurrogateCodepoint => 'Cesu8',
            Utf8RejectKind::TruncatedSequence => 'Truncated',
            Utf8RejectKind::InvalidStartByte => 'InvalidStartByte',
            Utf8RejectKind::InvalidContinuationByte => 'InvalidContinuation',
            Utf8RejectKind::CodepointBeyondMax => 'CodepointBeyondMax',
        };
    }

    /** @param list<int> $input */
    public static function detect(array $input): SurrogateReassemblyVerdict
    {
        $bytes = array_map(static fn (int $cp): int => $cp > 0xFF ? 0xFF : $cp, $input);
        $reject = Utf8::firstInvalidOffset($bytes);
        if ($reject === null) {
            return new SurrogateReassemblyVerdict(null, []);
        }
        return new SurrogateReassemblyVerdict(self::subThreatOfRejectKind($reject[1]), [$reject[0]]);
    }
}
