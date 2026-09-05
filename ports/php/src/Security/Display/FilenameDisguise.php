<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Display;

use UnicodePhp\Security\Covert\BidiControlBalance;
use UnicodePhp\Segmentation\Gcb;
use UnicodePhp\Segmentation\Grapheme;

// FilenameDisguise — detection of filename/extension disguise attacks where the
// visible extension differs from the byte extension (display-layer detector).
//
// Byte-faithful transliteration of the verified Rust reference implementation,
// itself a mirror of the Lean specification for this family.
//
// Threat model. An adversary delivers a file whose rendered name looks like a
// benign type (document.txt) but whose actual byte extension is executable —
// the canonical attack inserts U+202E RIGHT-TO-LEFT OVERRIDE so
// "document<RLO>txt.exe" renders as "document exe.txt".
//
// Detection is presentation- and language-agnostic: it surfaces every codepoint
// that could cause display-vs-byte divergence in the filename — any purposeless
// bidi format-control anywhere (BidiControlPurpose: unbalanced, or a balanced
// span enclosing nothing right-to-left in a left-to-right context), and any
// fullwidth/halfwidth or combining (grapheme Extend) codepoint in the extension
// region (after the last dot). Native-RTL names with no bidi controls clear, and
// so does a balanced embedding around an Arabic segment. It reuses the port's
// own predicates (the bidi purpose rule, the grapheme Extend class, the
// fullwidth range), never a host filesystem or rendering library.
//
// Sub-threats (priority order):
//   1. RloFlip            a purposeless bidi format-control in the input.
//   2. WidthClassExt      a fullwidth/halfwidth codepoint in the extension.
//   3. CombiningInExt     a combining (Extend) codepoint in the extension.
//   4. MultipleExtensions >= 3 dots (advisory; e.g. legitimate .tar.gz.sig).

/**
 * Sub-threat carrier for FilenameDisguise, in priority order. A single class
 * holds every variant's observation fields (nullable when not relevant to the
 * fired variant), mirroring the rust `SubThreat` enum's associated data.
 */
final class FilenameDisguiseSubThreat
{
    private function __construct(
        public readonly string $kind,
        public readonly ?int $position,
        public readonly ?int $controlCp,
        public readonly ?int $cp,
        public readonly ?int $dotCount,
    ) {
    }

    public static function rloFlip(int $position, int $controlCp): FilenameDisguiseSubThreat
    {
        return new FilenameDisguiseSubThreat('RloFlip', $position, $controlCp, null, null);
    }

    public static function widthClassExt(int $position, int $cp): FilenameDisguiseSubThreat
    {
        return new FilenameDisguiseSubThreat('WidthClassExt', $position, null, $cp, null);
    }

    public static function combiningInExt(int $position, int $cp): FilenameDisguiseSubThreat
    {
        return new FilenameDisguiseSubThreat('CombiningInExt', $position, null, $cp, null);
    }

    public static function multipleExtensions(int $dotCount): FilenameDisguiseSubThreat
    {
        return new FilenameDisguiseSubThreat('MultipleExtensions', null, null, null, $dotCount);
    }

    /** Fixture-row tag string for this sub-threat (matches `SubThreat.tag`). */
    public function tag(): string
    {
        return match ($this->kind) {
            'RloFlip' => 'RloFlip',
            'WidthClassExt' => 'WidthClassExt',
            'CombiningInExt' => 'CombiningInExt',
            'MultipleExtensions' => 'MultipleExtensions',
            default => throw new \RuntimeException("FilenameDisguiseSubThreat: unknown kind '{$this->kind}'"),
        };
    }
}

/**
 * Top-level classification (Clear when no disguise trigger present), or a Hazard
 * carrying the fired sub-threat, the implicated positions, and the (always-empty
 * for this detector) decoded-byte projection kept for shape parity with the Lean
 * `Classification.hazard`.
 */
final class FilenameDisguiseClassification
{
    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    private function __construct(
        public readonly ?FilenameDisguiseSubThreat $sub,
        public readonly array $positions,
        public readonly array $decoded,
    ) {
    }

    public static function clear(): FilenameDisguiseClassification
    {
        return new FilenameDisguiseClassification(null, [], []);
    }

    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    public static function hazard(FilenameDisguiseSubThreat $sub, array $positions, array $decoded): FilenameDisguiseClassification
    {
        return new FilenameDisguiseClassification($sub, $positions, $decoded);
    }

    /** True iff the classification is Clear. */
    public function isClear(): bool
    {
        return $this->sub === null;
    }

    /** Human-facing tag for a hazard, or null when clear. */
    public function tag(): ?string
    {
        return $this->sub?->tag();
    }

    /** @return list<int> Implicated positions (empty when clear). */
    public function positions(): array
    {
        return $this->positions;
    }
}

/** The structured output of `detect` (mirrors the Lean/rust `Verdict`). */
final class FilenameDisguiseVerdict
{
    /**
     * @param list<int> $input
     * @param list<int> $dotPositions
     */
    public function __construct(
        public readonly array $input,
        public readonly FilenameDisguiseClassification $classify,
        public readonly array $dotPositions,
        public readonly ?int $lastDotPos,
        public readonly int $bidiControlCount,
        public readonly int $fullwidthInExt,
        public readonly int $combiningInExt,
    ) {
    }
}

final class FilenameDisguise
{
    /** The number of dot separators at or beyond which the input is advisory. */
    public const MIN_MULTIPLE_EXTENSIONS = 3;

    /** True iff `cp` is `U+002E FULL STOP` (the extension separator). */
    public static function isAsciiDot(int $cp): bool
    {
        return $cp === 0x002E;
    }

    /** True iff `cp` is in the Halfwidth and Fullwidth Forms block. */
    public static function isFullwidthHalfwidth(int $cp): bool
    {
        return $cp >= 0xFF01 && $cp <= 0xFFEF;
    }

    /** True iff `cp` is a bidi format-control (reuses the port's own predicate). */
    public static function isBidiFormatControl(int $cp): bool
    {
        return BidiControlBalance::isBidiFormatControl($cp);
    }

    /** True iff `cp` has `Grapheme_Cluster_Break = Extend` (reuses the port's table). */
    public static function isGraphemeExtend(int $cp): bool
    {
        return Grapheme::lookupGcb($cp) === Gcb::Extend;
    }

    /**
     * Positions of every dot in `input`.
     * @param list<int> $input
     * @return list<int>
     */
    private static function dotPositions(array $input): array
    {
        $positions = [];
        foreach ($input as $i => $cp) {
            if (self::isAsciiDot($cp)) {
                $positions[] = $i;
            }
        }
        return $positions;
    }

    /**
     * Position and codepoint of the first purposeless bidi format-control:
     * unbalanced, or a balanced span enclosing nothing right-to-left in a
     * left-to-right context (BidiControlPurpose::firstPurposelessControl). A
     * balanced embedding around an Arabic filename segment manages that segment
     * and is not a flip. Mirrors the Lean detect, which reads
     * firstPurposelessControl.
     * @param list<int> $input @return array{0:int,1:int}|null
     */
    private static function firstBidiControl(array $input): ?array
    {
        return BidiControlPurpose::firstPurposelessControl($input);
    }

    /**
     * Position and codepoint of the first fullwidth/halfwidth codepoint at or after `$start`.
     * @param list<int> $input @return array{0:int,1:int}|null
     */
    private static function firstFullwidthFrom(array $input, int $start): ?array
    {
        foreach ($input as $i => $cp) {
            if ($i >= $start && self::isFullwidthHalfwidth($cp)) {
                return [$i, $cp];
            }
        }
        return null;
    }

    /**
     * Position and codepoint of the first Extend codepoint at or after `$start`.
     * @param list<int> $input @return array{0:int,1:int}|null
     */
    private static function firstExtendFrom(array $input, int $start): ?array
    {
        foreach ($input as $i => $cp) {
            if ($i >= $start && self::isGraphemeExtend($cp)) {
                return [$i, $cp];
            }
        }
        return null;
    }

    /**
     * Count of bidi format-controls anywhere in the input.
     * @param list<int> $input
     */
    private static function countBidiControl(array $input): int
    {
        $n = 0;
        foreach ($input as $cp) {
            if (self::isBidiFormatControl($cp)) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * Count of fullwidth/halfwidth codepoints at or after `$start`.
     * @param list<int> $input
     */
    private static function countFullwidthFrom(array $input, int $start): int
    {
        $n = 0;
        foreach ($input as $i => $cp) {
            if ($i >= $start && self::isFullwidthHalfwidth($cp)) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * Count of Extend codepoints at or after `$start`.
     * @param list<int> $input
     */
    private static function countExtendFrom(array $input, int $start): int
    {
        $n = 0;
        foreach ($input as $i => $cp) {
            if ($i >= $start && self::isGraphemeExtend($cp)) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * The FilenameDisguise detection function, reading its input as one
     * filename. Mirrors the Lean detect, which is detectWithContext at the
     * default context.
     * @param list<int> $input
     */
    public static function detect(array $input): FilenameDisguiseVerdict
    {
        return self::detectWithContext(false, $input);
    }

    /**
     * The FilenameDisguise detection function under an explicit field context.
     * $runningText mirrors the Lean Context.runningText: the extension rungs
     * read the text after the last dot as a file extension, which a source file
     * or a message does not have, so they do not run on running text; the
     * purposeless-bidi-control rung holds of any field.
     * @param list<int> $input
     */
    public static function detectWithContext(bool $runningText, array $input): FilenameDisguiseVerdict
    {
        $input = array_values($input);
        $dots = self::dotPositions($input);
        $lastDot = $dots === [] ? null : $dots[count($dots) - 1];
        $extStart = $lastDot === null ? count($input) : $lastDot + 1;
        $bidiCount = self::countBidiControl($input);
        $fwInExt = self::countFullwidthFrom($input, $extStart);
        $extInExt = self::countExtendFrom($input, $extStart);

        // Priority 1: a purposeless bidi format-control anywhere in the input.
        $bidi = self::firstBidiControl($input);
        if ($bidi !== null) {
            [$pos, $ctlCp] = $bidi;
            $classification = FilenameDisguiseClassification::hazard(
                FilenameDisguiseSubThreat::rloFlip($pos, $ctlCp),
                [$pos],
                [],
            );
        } elseif ($runningText) {
            // The remaining rungs read an extension; running text has none.
            $classification = FilenameDisguiseClassification::clear();
        } else {
            // Priority 2: fullwidth/halfwidth in the extension.
            $fw = self::firstFullwidthFrom($input, $extStart);
            if ($fw !== null) {
                [$pos, $cp] = $fw;
                $classification = FilenameDisguiseClassification::hazard(
                    FilenameDisguiseSubThreat::widthClassExt($pos, $cp),
                    [$pos],
                    [],
                );
            } else {
                // Priority 3: combining mark in the extension.
                $ext = self::firstExtendFrom($input, $extStart);
                if ($ext !== null) {
                    [$pos, $cp] = $ext;
                    $classification = FilenameDisguiseClassification::hazard(
                        FilenameDisguiseSubThreat::combiningInExt($pos, $cp),
                        [$pos],
                        [],
                    );
                } elseif (count($dots) >= self::MIN_MULTIPLE_EXTENSIONS) {
                    // Priority 4: three or more extensions (advisory).
                    $classification = FilenameDisguiseClassification::hazard(
                        FilenameDisguiseSubThreat::multipleExtensions(count($dots)),
                        $dots,
                        [],
                    );
                } else {
                    $classification = FilenameDisguiseClassification::clear();
                }
            }
        }

        return new FilenameDisguiseVerdict(
            $input,
            $classification,
            $dots,
            $lastDot,
            $bidiCount,
            $fwInExt,
            $extInExt,
        );
    }
}
