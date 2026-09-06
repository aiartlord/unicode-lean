<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Covert;

use UnicodePhp\Data;
use UnicodePhp\Security\ClassificationKind;
use UnicodePhp\Security\Crypto\AiWatermarkDetectability;

interface VsSubThreat
{
    public function tag(): string;
}

final class VsDirectPayload implements VsSubThreat
{
    public function __construct(public readonly string $decoded)
    {
    }

    public function tag(): string
    {
        return 'DirectPayload';
    }
}

final class VsIllegalTarget implements VsSubThreat
{
    public function __construct(
        public readonly int $targetCp,
        public readonly int $vsCp,
    ) {
    }

    public function tag(): string
    {
        return 'IllegalTarget';
    }
}

final class VsRepeatedBase implements VsSubThreat
{
    public function __construct(
        public readonly int $baseCp,
        public readonly int $vsCount,
    ) {
    }

    public function tag(): string
    {
        return 'RepeatedBase';
    }
}

/// A registered selector precedes the suspicious run: payload hiding behind a
/// legitimate glyph (Lean embeddedAfterReg).
final class VsEmbeddedAfterRegistered implements VsSubThreat
{
    public function __construct(
        public readonly int $registeredEnd,
        public readonly int $payloadStart,
    ) {
    }

    public function tag(): string
    {
        return 'EmbeddedAfterRegistered';
    }
}

final class VsVerdict
{
    /**
     * @param list<int> $vsPositions every selector position, the census
     * @param list<int> $suspiciousPositions the selectors no registered pair or
     *        presentation rule sanctions: what the classification localises
     * @param list<int> $recoveredBytes
     */
    public function __construct(
        public readonly ClassificationKind $kind,
        public readonly ?VsSubThreat $sub,
        public readonly array $vsPositions,
        public readonly array $suspiciousPositions,
        public readonly array $recoveredBytes,
    ) {
    }
}

/// Detection of GlassWorm-class invisible payloads encoded in Unicode variation
/// selectors. Exempts (base, VS) pairs registered in StandardizedVariants.txt or
/// emoji-variation-sequences.txt per UCD 17.0 / UTS #51.
final class VariationSelectorPayload
{
    /** @var array<string,bool>|null */
    private static ?array $legalPairs = null;

    private static function parseHex(string $s): ?int
    {
        $s = trim($s);
        if ($s === '' || preg_match('/^[0-9A-Fa-f]+$/', $s) !== 1) {
            return null;
        }
        return (int) hexdec($s);
    }

    /** @return array<string,bool> */
    private static function legalPairs(): array
    {
        if (self::$legalPairs !== null) {
            return self::$legalPairs;
        }
        $out = [];
        foreach (['StandardizedVariants.txt', 'emoji-variation-sequences.txt'] as $file) {
            foreach (Data::lines($file) as $rawLine) {
                $hash = strpos($rawLine, '#');
                $body = $hash === false ? $rawLine : substr($rawLine, 0, $hash);
                $stripped = trim($body);
                if ($stripped === '') {
                    continue;
                }
                $semi = strpos($stripped, ';');
                $pairPart = $semi === false ? $stripped : substr($stripped, 0, $semi);
                $tokens = preg_split('/\s+/', trim($pairPart), -1, PREG_SPLIT_NO_EMPTY) ?: [];
                if (count($tokens) < 2) {
                    continue;
                }
                $base = self::parseHex($tokens[0]);
                $vs = self::parseHex($tokens[1]);
                if ($base === null || $vs === null) {
                    continue;
                }
                $out[$base . ',' . $vs] = true;
            }
        }
        self::$legalPairs = $out;
        return $out;
    }

    /// True iff `(base, vs)` is a registered variation sequence.
    public static function isRegisteredVariationPair(int $base, int $vs): bool
    {
        return isset(self::legalPairs()[$base . ',' . $vs]);
    }

    public static function isVariationSelector(int $cp): bool
    {
        return ($cp >= 0xFE00 && $cp <= 0xFE0F)
            || ($cp >= 0xE0100 && $cp <= 0xE01EF)
            || ($cp >= 0x180B && $cp <= 0x180D);
    }

    /// Decode a single VS codepoint to its nibble value in [0, 255], or `null`
    /// for the Mongolian FVS codepoints (180B..180D).
    public static function vsToNibble(int $cp): ?int
    {
        if ($cp >= 0xFE00 && $cp <= 0xFE0F) {
            return $cp - 0xFE00;
        }
        if ($cp >= 0xE0100 && $cp <= 0xE01EF) {
            return $cp - 0xE0100 + 16;
        }
        return null;
    }

    /**
     * @param list<int> $input
     * @param list<int> $positions
     * @return list<int>
     */
    private static function decodeVsRun(array $input, array $positions): array
    {
        $out = [];
        $high = null;
        foreach ($positions as $p) {
            $n = self::vsToNibble($input[$p]);
            if ($n === null) {
                continue;
            }
            if ($high === null) {
                $high = $n;
            } else {
                $out[] = (($high << 4) | $n) & 0xFF;
                $high = null;
            }
        }
        return $out;
    }

    /**
     * @param list<int> $input
     * @param list<int> $positions
     */
    private static function allSameVs(array $input, array $positions): bool
    {
        if ($positions === []) {
            return true;
        }
        $cp0 = $input[$positions[0]];
        foreach ($positions as $p) {
            if ($input[$p] !== $cp0) {
                return false;
            }
        }
        return true;
    }

    /** @param list<int> $bytes */
    private static function lossyAscii(array $bytes): string
    {
        $s = '';
        foreach ($bytes as $b) {
            if (($b >= 0x20 && $b <= 0x7E) || $b === 0x09 || $b === 0x0A || $b === 0x0D) {
                $s .= chr($b);
            } else {
                $s .= '?';
            }
        }
        return $s;
    }

    /**
     * @param list<int> $input
     */
    public static function detect(array $input): VsVerdict
    {
        $vsPositions = [];
        foreach ($input as $i => $cp) {
            if (self::isVariationSelector($cp)) {
                $vsPositions[] = $i;
            }
        }

        // Each selector is judged against its predecessor (Lean classifyVS):
        // registered uses are sanctioned wherever they stand and however many;
        // the hazard is the suspicious run alone.
        $registered = [];
        $suspicious = [];
        foreach ($vsPositions as $p) {
            if (self::isRegisteredVariationUse($input, $p)) {
                $registered[] = $p;
            } else {
                $suspicious[] = $p;
            }
        }
        if ($suspicious === []) {
            return new VsVerdict(ClassificationKind::Clear, null, $vsPositions, [], []);
        }

        $recoveredBytes = self::decodeVsRun($input, $suspicious);
        $payloadStart = $suspicious[0];
        $registeredBefore = null;
        foreach ($registered as $p) {
            if ($p < $payloadStart) {
                $registeredBefore = $p;
            }
        }
        // Priority (Lean pickSubThreat): a registered selector before the
        // suspicious run, then a long single-selector run, then a decodable
        // payload, then the bare illegal target.
        if ($registeredBefore !== null) {
            $sub = new VsEmbeddedAfterRegistered($registeredBefore, $payloadStart);
        } elseif (count($suspicious) >= 4 && self::allSameVs($input, $suspicious)) {
            $base = $payloadStart === 0 ? 0 : $input[$payloadStart - 1];
            $sub = new VsRepeatedBase($base, count($suspicious));
        } elseif ($recoveredBytes !== []) {
            $sub = new VsDirectPayload(self::lossyAscii($recoveredBytes));
        } else {
            $target = $payloadStart === 0 ? 0 : $input[$payloadStart - 1];
            $sub = new VsIllegalTarget($target, $input[$payloadStart]);
        }

        return new VsVerdict(ClassificationKind::Hazard, $sub, $vsPositions, $suspicious, $recoveredBytes);
    }

    /**
     * The Lean classifyVS registered reading of the selector at $p: a
     * standardized or emoji variation sequence, or VS15 / VS16 on any base
     * carrying the Emoji property. A selector with no predecessor is never
     * registered.
     *
     * @param list<int> $input
     */
    public static function isRegisteredVariationUse(array $input, int $p): bool
    {
        if ($p === 0) {
            return false;
        }
        $base = $input[$p - 1];
        $vs = $input[$p];
        return self::isRegisteredVariationPair($base, $vs)
            || (($vs === 0xFE0F || $vs === 0xFE0E) && AiWatermarkDetectability::isEmoji($base));
    }
}
