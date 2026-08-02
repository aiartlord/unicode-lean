<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Display;

use UnicodePhp\Security\ClassificationKind;
use UnicodePhp\Security\Covert\BidiControlBalance;
use UnicodePhp\Security\Covert\TagBlockPayload;
use UnicodePhp\Security\Covert\VariationSelectorPayload;
use UnicodePhp\Security\Covert\ZeroWidthPayload;
use UnicodePhp\Security\Identity\HomoglyphConfusable;

// SourceDisplayDivergence — the aggregate "what a reviewer sees differs from
// what the machine runs" detector (display-layer AGGREGATOR, Tier D1).
//
// Byte-faithful transliteration of the verified rust reference
// `security/display/source_display_divergence.rs`, itself a mirror of
// `Unicode/Security/Display/SourceDisplayDivergence.lean`.
//
// Threat model. A single covert or identity trick may be individually
// benign-looking, but any hit means the rendered source diverges from its
// logical content; two or more is a strong compound signal. This detector runs
// the five constituent detectors on the same codepoint stream and aggregates:
// zero fire → clear, exactly one → pass-through that family's tag, two or more
// → `Compound`. Every constituent fires region-agnostically — payloads inside
// string literals or comments count.
//
// It reuses the port's OWN five constituent detectors (no new data, no host
// library): TagBlockPayload, VariationSelectorPayload, ZeroWidthPayload,
// BidiControlBalance (all covert-channel families) and HomoglyphConfusable (an
// identity family). A constituent "fires" when its verdict's classification
// kind is not Clear.
//
// Sub-threat tags in canonical aggregation order:
//   1. TagBlock            tag-block payload present.
//   2. VariationSelector   variation-selector payload present.
//   3. ZeroWidth           zero-width payload present.
//   4. BidiControl         bidi-control imbalance present.
//   5. IdentifierHomoglyph identifier homoglyph / confusable present.
// Two or more fired → the aggregate tag `Compound`.

/**
 * Top-level classification (Clear when no constituent fired), or a Hazard
 * carrying the aggregate sub-threat tag. Positions are always empty at this
 * layer by the Lean spec — the per-family verdicts carry them — so this result
 * carries only the sub-threat tag, kept in the universal clear/hazard shape.
 */
final class SourceDisplayDivergenceClassification
{
    private function __construct(
        public readonly ?string $sub,
    ) {
    }

    public static function clear(): SourceDisplayDivergenceClassification
    {
        return new SourceDisplayDivergenceClassification(null);
    }

    public static function hazard(string $sub): SourceDisplayDivergenceClassification
    {
        return new SourceDisplayDivergenceClassification($sub);
    }

    /** True iff the classification is Clear (no constituent fired). */
    public function isClear(): bool
    {
        return $this->sub === null;
    }

    /** Aggregate sub-threat tag for a hazard, or null when clear. */
    public function tag(): ?string
    {
        return $this->sub;
    }

    /** @return list<int> Implicated positions — empty at this aggregation layer. */
    public function positions(): array
    {
        return [];
    }
}

/** The structured output of `detect` (mirrors the Lean/rust `Detection`). */
final class SourceDisplayDivergenceVerdict
{
    /**
     * @param list<int> $input
     * @param list<string> $fires the constituent tags that fired, in canonical order
     */
    public function __construct(
        public readonly array $input,
        public readonly SourceDisplayDivergenceClassification $classify,
        public readonly array $fires,
    ) {
    }
}

final class SourceDisplayDivergence
{
    /** True iff a constituent classification kind counts as fired (not Clear). */
    private static function fired(ClassificationKind $kind): bool
    {
        return $kind !== ClassificationKind::Clear;
    }

    /**
     * Aggregate the five constituent detectors into a single D1 verdict.
     * @param list<int> $input
     */
    public static function detect(array $input): SourceDisplayDivergenceVerdict
    {
        $input = array_values($input);

        // Constituent family tags in canonical aggregation order.
        $fires = [];
        if (self::fired(TagBlockPayload::detect($input)->kind)) {
            $fires[] = 'TagBlock';
        }
        if (self::fired(VariationSelectorPayload::detect($input)->kind)) {
            $fires[] = 'VariationSelector';
        }
        if (self::fired(ZeroWidthPayload::detect($input)->kind)) {
            $fires[] = 'ZeroWidth';
        }
        if (self::fired(BidiControlBalance::detect($input)->kind)) {
            $fires[] = 'BidiControl';
        }
        if (self::fired(HomoglyphConfusable::detect($input)->kind)) {
            $fires[] = 'IdentifierHomoglyph';
        }

        $classification = match (count($fires)) {
            0 => SourceDisplayDivergenceClassification::clear(),
            1 => SourceDisplayDivergenceClassification::hazard($fires[0]),
            default => SourceDisplayDivergenceClassification::hazard('Compound'),
        };

        return new SourceDisplayDivergenceVerdict($input, $classification, $fires);
    }
}
