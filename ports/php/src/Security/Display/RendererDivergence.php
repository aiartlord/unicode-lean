<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Display;

use UnicodePhp\Security\Covert\VariationSelectorPayload;
use UnicodePhp\Security\Identity\EmojiZwjIntegrity;
use UnicodePhp\Security\Identity\Ucd;
use UnicodePhp\Segmentation\Gcb;
use UnicodePhp\Segmentation\Grapheme;

// RendererDivergence — detection of codepoint/sequence shapes known to render
// differently across font + terminal + browser stacks (display-layer detector).
//
// Byte-faithful transliteration of the verified rust reference
// `ports/rust/src/security/display/renderer_divergence.rs`, itself a mirror of
// `Unicode/Security/Display/RendererDivergence.lean`.
//
// Threat model. An adversary crafts content that renders one way in the
// auditor's renderer (a benign glyph or an empty span) and a different way in
// the consumer's renderer (a misleading glyph, a wider glyph, or a different
// sequence). This is the "fingerprint stability" family: clear inputs render
// the same across the renderer cohort the Standard documents as stable.
//
// What the detector draws. A heuristic three-value split, surfaced through the
// universal clear/hazard carrier: an input is clear when none of the documented
// variance triggers fire, and otherwise is classified by the first trigger in
// priority order — combining-mark stack overflow, variation-selector presence,
// an unregistered ZWJ shape, fullwidth/halfwidth display, or mixed direction. It
// reuses the port's own tables (the VariationSelectorPayload variation-selector
// set, the Grapheme Extend class, the EmojiZwjIntegrity RGI ZWJ registry, and
// the Ucd strong-bidi classes), never a host rendering or shaping library.
//
// Sub-threats (priority order):
//   1. CombiningStackOverflow    Zalgo-like combining-mark stack >= 4 on a base.
//   2. VariationSelectorVariance any variation selector present.
//   3. UnregisteredZwjVariance   ZWJ-containing input not in the RGI ZWJ set.
//   4. FullwidthVariance         a fullwidth/halfwidth codepoint present.
//   5. MixedDirectionVariance    both strong-LTR and strong-RTL codepoints.

/**
 * Sub-threat carrier for RendererDivergence, in priority order. A single class
 * holds every variant's observation fields (nullable when not relevant to the
 * fired variant), mirroring the rust `SubThreat` enum's associated data.
 */
final class RendererDivergenceSubThreat
{
    private function __construct(
        public readonly string $kind,
        public readonly ?int $basePos,
        public readonly ?int $stackLen,
        public readonly ?int $firstVsPos,
        public readonly ?int $firstVsCp,
        public readonly ?int $firstZwjPos,
        public readonly ?int $firstFwPos,
        public readonly ?int $firstFwCp,
        public readonly ?int $ltrCount,
        public readonly ?int $rtlCount,
    ) {
    }

    public static function combiningStackOverflow(int $basePos, int $stackLen): RendererDivergenceSubThreat
    {
        return new RendererDivergenceSubThreat('CombiningStackOverflow', $basePos, $stackLen, null, null, null, null, null, null, null);
    }

    public static function variationSelectorVariance(int $firstVsPos, int $firstVsCp): RendererDivergenceSubThreat
    {
        return new RendererDivergenceSubThreat('VariationSelectorVariance', null, null, $firstVsPos, $firstVsCp, null, null, null, null, null);
    }

    public static function unregisteredZwjVariance(int $firstZwjPos): RendererDivergenceSubThreat
    {
        return new RendererDivergenceSubThreat('UnregisteredZwjVariance', null, null, null, null, $firstZwjPos, null, null, null, null);
    }

    public static function fullwidthVariance(int $firstFwPos, int $firstFwCp): RendererDivergenceSubThreat
    {
        return new RendererDivergenceSubThreat('FullwidthVariance', null, null, null, null, null, $firstFwPos, $firstFwCp, null, null);
    }

    public static function mixedDirectionVariance(int $ltrCount, int $rtlCount): RendererDivergenceSubThreat
    {
        return new RendererDivergenceSubThreat('MixedDirectionVariance', null, null, null, null, null, null, null, $ltrCount, $rtlCount);
    }

    /** Fixture-row tag string for this sub-threat (matches `SubThreat.tag`). */
    public function tag(): string
    {
        return match ($this->kind) {
            'CombiningStackOverflow' => 'CombiningStackOverflow',
            'VariationSelectorVariance' => 'VariationSelectorVariance',
            'UnregisteredZwjVariance' => 'UnregisteredZwjVariance',
            'FullwidthVariance' => 'FullwidthVariance',
            'MixedDirectionVariance' => 'MixedDirectionVariance',
            default => throw new \RuntimeException("RendererDivergenceSubThreat: unknown kind '{$this->kind}'"),
        };
    }
}

/**
 * Top-level classification (stable = Clear), or a Hazard carrying the fired
 * sub-threat, the implicated positions, and the (always-empty for this
 * detector) decoded-byte projection kept for shape parity with the Lean
 * `Classification.hazard`.
 */
final class RendererDivergenceClassification
{
    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    private function __construct(
        public readonly ?RendererDivergenceSubThreat $sub,
        public readonly array $positions,
        public readonly array $decoded,
    ) {
    }

    public static function clear(): RendererDivergenceClassification
    {
        return new RendererDivergenceClassification(null, [], []);
    }

    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    public static function hazard(RendererDivergenceSubThreat $sub, array $positions, array $decoded): RendererDivergenceClassification
    {
        return new RendererDivergenceClassification($sub, $positions, $decoded);
    }

    /** True iff the classification is Clear (i.e. stable). */
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
final class RendererDivergenceVerdict
{
    /** @param list<int> $input */
    public function __construct(
        public readonly array $input,
        public readonly RendererDivergenceClassification $classify,
        public readonly int $vsCount,
        public readonly int $combiningCount,
        public readonly int $fullwidthCount,
        public readonly bool $hasZwj,
        public readonly int $strongLtrCount,
        public readonly int $strongRtlCount,
    ) {
    }
}

final class RendererDivergence
{
    /**
     * The combining-mark stack depth (on a single base) at or beyond which the
     * input is treated as a Zalgo-style rendering-variance hazard.
     */
    public const MIN_COMBINING_STACK = 4;

    /** The ZERO WIDTH JOINER codepoint. */
    public const ZWJ = 0x200D;

    /** True iff `cp` is a variation selector (reuses the port's own predicate). */
    public static function isVariationSelector(int $cp): bool
    {
        return VariationSelectorPayload::isVariationSelector($cp);
    }

    /** True iff `cp` is the ZWJ codepoint. */
    public static function isZwj(int $cp): bool
    {
        return $cp === self::ZWJ;
    }

    /** True iff `cp` is in the Halfwidth/Fullwidth Forms block. */
    public static function isFullwidthHalfwidth(int $cp): bool
    {
        return $cp >= 0xFF01 && $cp <= 0xFFEF;
    }

    /** True iff `cp` has `Grapheme_Cluster_Break = Extend` (reuses the port's table). */
    public static function isGraphemeExtend(int $cp): bool
    {
        return Grapheme::lookupGcb($cp) === Gcb::Extend;
    }

    /** @param list<int> $input */
    private static function countVs(array $input): int
    {
        $n = 0;
        foreach ($input as $cp) {
            if (self::isVariationSelector($cp)) {
                $n++;
            }
        }
        return $n;
    }

    /** @param list<int> $input */
    private static function countCombining(array $input): int
    {
        $n = 0;
        foreach ($input as $cp) {
            if (self::isGraphemeExtend($cp)) {
                $n++;
            }
        }
        return $n;
    }

    /** @param list<int> $input */
    private static function countFullwidth(array $input): int
    {
        $n = 0;
        foreach ($input as $cp) {
            if (self::isFullwidthHalfwidth($cp)) {
                $n++;
            }
        }
        return $n;
    }

    /** @param list<int> $input */
    private static function inputHasZwj(array $input): bool
    {
        foreach ($input as $cp) {
            if (self::isZwj($cp)) {
                return true;
            }
        }
        return false;
    }

    /** @param list<int> $input */
    private static function countStrongLtr(array $input): int
    {
        $n = 0;
        foreach ($input as $cp) {
            if (Ucd::isStrongLtr($cp)) {
                $n++;
            }
        }
        return $n;
    }

    /** @param list<int> $input */
    private static function countStrongRtl(array $input): int
    {
        $n = 0;
        foreach ($input as $cp) {
            if (Ucd::isStrongRtl($cp)) {
                $n++;
            }
        }
        return $n;
    }

    /** Position and codepoint of the first variation selector.
     * @param list<int> $input @return array{0:int,1:int}|null */
    private static function firstVsPos(array $input): ?array
    {
        foreach ($input as $i => $cp) {
            if (self::isVariationSelector($cp)) {
                return [$i, $cp];
            }
        }
        return null;
    }

    /** Position of the first ZWJ.
     * @param list<int> $input */
    private static function firstZwjPos(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if (self::isZwj($cp)) {
                return $i;
            }
        }
        return null;
    }

    /** Position and codepoint of the first fullwidth/halfwidth codepoint.
     * @param list<int> $input @return array{0:int,1:int}|null */
    private static function firstFullwidthPos(array $input): ?array
    {
        foreach ($input as $i => $cp) {
            if (self::isFullwidthHalfwidth($cp)) {
                return [$i, $cp];
            }
        }
        return null;
    }

    /**
     * The first base position (a non-Extend codepoint) immediately followed by
     * exactly `$minStack` consecutive Extend codepoints. Returns
     * `[base_pos, min_stack]` on hit, else null.
     * @param list<int> $input @return array{0:int,1:int}|null
     */
    private static function firstCombiningStack(array $input, int $minStack): ?array
    {
        foreach ($input as $idx => $cp) {
            if (!self::isGraphemeExtend($cp)) {
                $following = array_slice($input, $idx + 1, $minStack);
                if (count($following) === $minStack) {
                    $allExtend = true;
                    foreach ($following as $c) {
                        if (!self::isGraphemeExtend($c)) {
                            $allExtend = false;
                            break;
                        }
                    }
                    if ($allExtend) {
                        return [$idx, $minStack];
                    }
                }
            }
        }
        return null;
    }

    /**
     * The RendererDivergence detection function.
     * @param list<int> $input
     */
    public static function detect(array $input): RendererDivergenceVerdict
    {
        $input = array_values($input);
        $vsCount = self::countVs($input);
        $combiningCount = self::countCombining($input);
        $fullwidthCount = self::countFullwidth($input);
        $hasZwj = self::inputHasZwj($input);
        $ltrCount = self::countStrongLtr($input);
        $rtlCount = self::countStrongRtl($input);

        // Priority 1: combining-mark stack overflow (Zalgo).
        $stack = self::firstCombiningStack($input, self::MIN_COMBINING_STACK);
        if ($stack !== null) {
            [$basePos, $stackLen] = $stack;
            $classification = RendererDivergenceClassification::hazard(
                RendererDivergenceSubThreat::combiningStackOverflow($basePos, $stackLen),
                [$basePos],
                [],
            );
        } else {
            // Priority 2: any variation selector triggers presentation variance.
            $vs = self::firstVsPos($input);
            if ($vs !== null) {
                [$vsPos, $vsCp] = $vs;
                $classification = RendererDivergenceClassification::hazard(
                    RendererDivergenceSubThreat::variationSelectorVariance($vsPos, $vsCp),
                    [$vsPos],
                    [],
                );
            } elseif ($hasZwj && !EmojiZwjIntegrity::isRegisteredZwjSequence($input)) {
                // Priority 3: ZWJ-containing input not in the registered RGI set.
                $zwjPos = self::firstZwjPos($input);
                $classification = $zwjPos === null
                    ? RendererDivergenceClassification::clear()
                    : RendererDivergenceClassification::hazard(
                        RendererDivergenceSubThreat::unregisteredZwjVariance($zwjPos),
                        [$zwjPos],
                        [],
                    );
            } else {
                // Priority 4: fullwidth/halfwidth.
                $fw = self::firstFullwidthPos($input);
                if ($fw !== null) {
                    [$fwPos, $fwCp] = $fw;
                    $classification = RendererDivergenceClassification::hazard(
                        RendererDivergenceSubThreat::fullwidthVariance($fwPos, $fwCp),
                        [$fwPos],
                        [],
                    );
                } elseif ($ltrCount > 0 && $rtlCount > 0) {
                    // Priority 5: mixed direction.
                    $classification = RendererDivergenceClassification::hazard(
                        RendererDivergenceSubThreat::mixedDirectionVariance($ltrCount, $rtlCount),
                        [],
                        [],
                    );
                } else {
                    $classification = RendererDivergenceClassification::clear();
                }
            }
        }

        return new RendererDivergenceVerdict(
            $input,
            $classification,
            $vsCount,
            $combiningCount,
            $fullwidthCount,
            $hasZwj,
            $ltrCount,
            $rtlCount,
        );
    }
}
