<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Boundary;

use UnicodePhp\Security\Identity\Ucd;

// AdmissibilityFormDrift — cross-layer identifier-admissibility x form drift
// (boundary-layer detector).
//
// Byte-faithful transliteration of the verified Rust reference implementation,
// itself a mirror of the Lean specification for this family.
//
// Fires on inputs whose UTS #39 whole-string admissibility verdict differs
// between the input and its NFKC form. This is the string-level complement of
// IdentifierFormDrift (which scans Identifier_Status against the per-codepoint
// NFKD head): here the whole-string admissibility predicate is evaluated twice —
// once on the input, once on its NFKC form. The two are not redundant. In
// particular, a sequence of decomposed Hangul jamos passes the per-codepoint
// scan cleanly (each jamo has identity NFKD and Restricted status on both sides)
// but fires here: the jamo sequence is rejected by isAllowedIdentifier, while
// its NFKC composition into a precomposed Hangul syllable is accepted.
//
// It reuses the port's own UTS #39 admissibility predicate
// (Ucd::isAllowedIdentifier = UAX #31 default identifier AND every codepoint
// Allowed) and NFKC pipeline (Ucd::toNfkc), never a host normalization or
// identifier library.
//
// Sub-threat (direction-agnostic):
//   AdmissibilityFormDrift — isAllowedIdentifier(input) differs from
//   isAllowedIdentifier(toNfkc(input)). The pair of booleans is carried so the
//   verdict records which direction the drift goes; no position is reported
//   because the predicate is whole-string.

/**
 * Sub-threat carrier for AdmissibilityFormDrift. There is a single variant,
 * AdmissibilityFormDrift, holding the two whole-string admissibility booleans,
 * mirroring the rust `SubThreat` enum.
 */
final class AdmissibilityFormDriftSubThreat
{
    private function __construct(
        public readonly string $kind,
        public readonly bool $inputAdmissible,
        public readonly bool $nfkcAdmissible,
    ) {
    }

    public static function admissibilityFormDrift(bool $inputAdmissible, bool $nfkcAdmissible): AdmissibilityFormDriftSubThreat
    {
        return new AdmissibilityFormDriftSubThreat('AdmissibilityFormDrift', $inputAdmissible, $nfkcAdmissible);
    }

    /** Fixture-row tag string for this sub-threat (matches `SubThreat.tag`). */
    public function tag(): string
    {
        return match ($this->kind) {
            'AdmissibilityFormDrift' => 'AdmissibilityFormDrift',
            default => throw new \RuntimeException("AdmissibilityFormDriftSubThreat: unknown kind '{$this->kind}'"),
        };
    }
}

/**
 * Top-level classification (Clear when the admissibility verdict agrees across
 * forms), or a Hazard carrying the fired sub-threat, the implicated positions
 * (always empty — the predicate is whole-string), and the (always-empty)
 * decoded-byte projection kept for shape parity with the Lean
 * `Classification.hazard`.
 */
final class AdmissibilityFormDriftClassification
{
    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    private function __construct(
        public readonly ?AdmissibilityFormDriftSubThreat $sub,
        public readonly array $positions,
        public readonly array $decoded,
    ) {
    }

    public static function clear(): AdmissibilityFormDriftClassification
    {
        return new AdmissibilityFormDriftClassification(null, [], []);
    }

    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    public static function hazard(AdmissibilityFormDriftSubThreat $sub, array $positions, array $decoded): AdmissibilityFormDriftClassification
    {
        return new AdmissibilityFormDriftClassification($sub, $positions, $decoded);
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

    /** @return list<int> Implicated positions (always empty — the predicate is whole-string). */
    public function positions(): array
    {
        return $this->positions;
    }
}

/** The structured output of `detect` (mirrors the Lean/rust `Verdict`). */
final class AdmissibilityFormDriftVerdict
{
    /** @param list<int> $input */
    public function __construct(
        public readonly array $input,
        public readonly AdmissibilityFormDriftClassification $classify,
        public readonly bool $inputAdmissible,
        public readonly bool $nfkcAdmissible,
    ) {
    }
}

final class AdmissibilityFormDrift
{
    /**
     * The AdmissibilityFormDrift detection function. Evaluates the whole-string
     * UTS #39 admissibility predicate on the input and on its NFKC form; a
     * disagreement is the hazard.
     * @param list<int> $input
     */
    public static function detect(array $input): AdmissibilityFormDriftVerdict
    {
        $input = array_values($input);
        $nfkc = Ucd::toNfkc($input);
        $inOk = Ucd::isAllowedIdentifier($input);
        $nfkcOk = Ucd::isAllowedIdentifier($nfkc);

        if ($inOk === $nfkcOk) {
            $classification = AdmissibilityFormDriftClassification::clear();
        } else {
            $classification = AdmissibilityFormDriftClassification::hazard(
                AdmissibilityFormDriftSubThreat::admissibilityFormDrift($inOk, $nfkcOk),
                [],
                [],
            );
        }

        return new AdmissibilityFormDriftVerdict($input, $classification, $inOk, $nfkcOk);
    }
}
