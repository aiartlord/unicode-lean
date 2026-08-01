<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Covert;

use UnicodePhp\Security\ClassificationKind;

/// Sub-threat variant for the tag-block-payload detector. Each variant carries
/// its attribution payload and reports a fixture-row tag string.
interface TagBlockSubThreat
{
    public function tag(): string;
}

/// Input is pure tags and the decoder produces ≥ 1 printable byte.
final class TagBlockDirectAscii implements TagBlockSubThreat
{
    public function __construct(public readonly string $decoded)
    {
    }

    public function tag(): string
    {
        return 'DirectAscii';
    }
}

/// E0001 followed by ≥ 1 further tag char.
final class TagBlockLanguageTagRevival implements TagBlockSubThreat
{
    public function __construct(
        public readonly int $langTagPos,
        public readonly string $decodedTail,
    ) {
    }

    public function tag(): string
    {
        return 'LanguageTagRevival';
    }
}

/// Tag chars interleaved with non-tag codepoints.
final class TagBlockMixedBlock implements TagBlockSubThreat
{
    public function __construct(
        public readonly int $tagCount,
        public readonly int $totalCps,
    ) {
    }

    public function tag(): string
    {
        return 'MixedBlock';
    }
}

/// Fallback for isolated single tag-block codepoints.
final class TagBlockBareTagPresent implements TagBlockSubThreat
{
    public function __construct(public readonly int $tagCp)
    {
    }

    public function tag(): string
    {
        return 'BareTagPresent';
    }
}

/// Structured verdict over an input codepoint sequence.
final class TagBlockVerdict
{
    /**
     * @param list<int> $tagPositions
     */
    public function __construct(
        public readonly ClassificationKind $kind,
        public readonly ?TagBlockSubThreat $sub,
        public readonly array $tagPositions,
        public readonly string $recoveredAscii,
    ) {
    }
}

/// Detection of invisible payloads encoded in the Unicode tag block
/// U+E0000..U+E007F under the decoder `tag(c) = c + 0xE0000` for c in
/// [0x20, 0x7E]. Every occurrence is reportable; the detector attributes the
/// kind of use.
final class TagBlockPayload
{
    /// True iff `cp` is in the Unicode tag block U+E0000..U+E007F.
    public static function isTagCharacter(int $cp): bool
    {
        return $cp >= 0xE0000 && $cp <= 0xE007F;
    }

    public static function isLanguageTag(int $cp): bool
    {
        return $cp === 0xE0001;
    }

    public static function isCancelTag(int $cp): bool
    {
        return $cp === 0xE007F;
    }

    /// Decode a tag-block codepoint to its ASCII correspondent, or `null` for
    /// tag codepoints outside the printable-ASCII range and non-tag codepoints.
    public static function tagToAscii(int $cp): ?string
    {
        if ($cp >= 0xE0020 && $cp <= 0xE007E) {
            return chr($cp - 0xE0000);
        }
        return null;
    }

    /**
     * @param list<int> $input
     * @param list<int> $positions
     */
    private static function decodeTagRun(array $input, array $positions): string
    {
        $s = '';
        $len = count($input);
        foreach ($positions as $p) {
            if ($p < $len) {
                $c = self::tagToAscii($input[$p]);
                if ($c !== null) {
                    $s .= $c;
                }
            }
        }
        return $s;
    }

    /**
     * @param list<int> $input
     * @param list<int> $tagPositions
     */
    private static function hasLanguageTagPrefix(array $input, array $tagPositions): ?int
    {
        if ($tagPositions === []) {
            return null;
        }
        $langPos = $tagPositions[0];
        if ($langPos >= count($input)) {
            return null;
        }
        if (self::isLanguageTag($input[$langPos]) && count($tagPositions) >= 2) {
            return $langPos;
        }
        return null;
    }

    /**
     * @param list<int> $input
     * @param list<int> $tagPositions
     */
    private static function pickSubThreat(array $input, array $tagPositions, string $decoded): TagBlockSubThreat
    {
        $langPos = self::hasLanguageTagPrefix($input, $tagPositions);
        if ($langPos !== null) {
            $tail = array_values(array_filter($tagPositions, static fn (int $p): bool => $p !== $langPos));
            return new TagBlockLanguageTagRevival($langPos, self::decodeTagRun($input, $tail));
        }
        $allTags = true;
        foreach ($input as $cp) {
            if (!self::isTagCharacter($cp)) {
                $allTags = false;
                break;
            }
        }
        if ($allTags && $decoded !== '') {
            return new TagBlockDirectAscii($decoded);
        }
        if (count($input) > count($tagPositions)) {
            return new TagBlockMixedBlock(count($tagPositions), count($input));
        }
        return new TagBlockBareTagPresent($input[$tagPositions[0]]);
    }

    /**
     * @param list<int> $input
     */
    public static function detect(array $input): TagBlockVerdict
    {
        $tagPositions = [];
        foreach ($input as $i => $cp) {
            if (self::isTagCharacter($cp)) {
                $tagPositions[] = $i;
            }
        }

        if ($tagPositions === []) {
            return new TagBlockVerdict(ClassificationKind::Clear, null, [], '');
        }

        $decoded = self::decodeTagRun($input, $tagPositions);
        $sub = self::pickSubThreat($input, $tagPositions, $decoded);

        return new TagBlockVerdict(ClassificationKind::Hazard, $sub, $tagPositions, $decoded);
    }
}
