<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Boundary;

use UnicodePhp\Security\Identity\Ucd;

// IdentifierFormDrift — cross-layer identifier x form drift (boundary-layer detector).
//
// Byte-faithful transliteration of the verified Rust reference implementation,
// itself a mirror of the Lean specification for this family.
//
// Threat model. Tier A2 two-system bypass. An identity validator and a form
// normalizer disagree about a codepoint: stage A runs the UTS #39
// Identifier_Status check before normalisation and rejects, say, U+1D44E
// MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and then
// runs the same check, seeing U+0061 'a' (Allowed) and accepting. The attacker
// controls which stage processes the input and exploits the disagreement. The
// same shape covers fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01),
// and Roman-numeral (U+2163) compatibility forms.
//
// The detector fires on the form transition itself — it reports every input
// position whose Identifier_Status differs from the Identifier_Status of that
// codepoint's NFKD head. This is orthogonal to the single-form identity-spoofing
// detectors (which examine the input under one form) and stronger than a
// form-of-input fold (it asks whether the identifier verdict changes, not whether
// any output bit changes).
//
// Note on Hangul: precomposed syllables are Allowed while their NFKD-head jamos
// are Restricted, so pure Korean text fires; callers intending to accept Korean
// identifiers should apply NFC before evaluating admissibility.
//
// It reuses the port's own UTS #39 Identifier_Status predicate (Ucd::isIdAllowed)
// and NFKD pipeline (Ucd::toNfkd), never a host normalization or identifier
// library.
//
// Sub-threat (direction-agnostic):
//   IdentifierStatusShift — the first input position whose Identifier_Status
//   differs from its NFKD-head's. The verdict carries the total shift count.

/**
 * Sub-threat carrier for IdentifierFormDrift. There is a single variant,
 * IdentifierStatusShift, holding the position of the first status-shifting
 * codepoint and that codepoint, mirroring the rust `SubThreat` enum.
 */
final class IdentifierFormDriftSubThreat
{
    private function __construct(
        public readonly string $kind,
        public readonly int $basePos,
        public readonly int $cp,
    ) {
    }

    public static function identifierStatusShift(int $basePos, int $cp): IdentifierFormDriftSubThreat
    {
        return new IdentifierFormDriftSubThreat('IdentifierStatusShift', $basePos, $cp);
    }

    /** Fixture-row tag string for this sub-threat (matches `SubThreat.tag`). */
    public function tag(): string
    {
        return match ($this->kind) {
            'IdentifierStatusShift' => 'IdentifierStatusShift',
            default => throw new \RuntimeException("IdentifierFormDriftSubThreat: unknown kind '{$this->kind}'"),
        };
    }
}

/**
 * Top-level classification (Clear when no status shift is present), or a Hazard
 * carrying the fired sub-threat, the implicated positions, and the (always-empty
 * for this detector) decoded-byte projection kept for shape parity with the Lean
 * `Classification.hazard`.
 */
final class IdentifierFormDriftClassification
{
    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    private function __construct(
        public readonly ?IdentifierFormDriftSubThreat $sub,
        public readonly array $positions,
        public readonly array $decoded,
    ) {
    }

    public static function clear(): IdentifierFormDriftClassification
    {
        return new IdentifierFormDriftClassification(null, [], []);
    }

    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    public static function hazard(IdentifierFormDriftSubThreat $sub, array $positions, array $decoded): IdentifierFormDriftClassification
    {
        return new IdentifierFormDriftClassification($sub, $positions, $decoded);
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
final class IdentifierFormDriftVerdict
{
    /** @param list<int> $input */
    public function __construct(
        public readonly array $input,
        public readonly IdentifierFormDriftClassification $classify,
        public readonly int $shiftCount,
    ) {
    }
}

final class IdentifierFormDrift
{
    /**
     * `Identifier_Status = Allowed` of the first codepoint of `cp`'s NFKD form, or
     * `cp`'s own status when NFKD is empty (defensive — `Ucd::toNfkd` is total and
     * returns at least `[cp]`). Reuses the port's own UTS #39 predicate and NFKD.
     */
    public static function nfkdHeadAllowed(int $cp): bool
    {
        $decomposed = Ucd::toNfkd([$cp]);
        if ($decomposed === []) {
            return Ucd::isIdAllowed($cp);
        }
        return Ucd::isIdAllowed($decomposed[0]);
    }

    /** True iff `cp`'s own Identifier_Status differs from its NFKD-head's. */
    private static function statusShifts(int $cp): bool
    {
        return Ucd::isIdAllowed($cp) !== self::nfkdHeadAllowed($cp);
    }

    /**
     * Position and codepoint of the first input position whose `isIdAllowed`
     * differs from its NFKD-head's, or null when none shifts.
     * @param list<int> $input @return array{0:int,1:int}|null
     */
    private static function firstStatusShift(array $input): ?array
    {
        foreach ($input as $i => $cp) {
            if (self::statusShifts($cp)) {
                return [$i, $cp];
            }
        }
        return null;
    }

    /**
     * Total count of input positions where the per-cp status shifts under NFKD.
     * @param list<int> $input
     */
    private static function statusShiftCount(array $input): int
    {
        $n = 0;
        foreach ($input as $cp) {
            if (self::statusShifts($cp)) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * The IdentifierFormDrift detection function.
     * @param list<int> $input
     */
    public static function detect(array $input): IdentifierFormDriftVerdict
    {
        $input = array_values($input);
        $shift = self::firstStatusShift($input);
        if ($shift !== null) {
            [$pos, $cp] = $shift;
            $classification = IdentifierFormDriftClassification::hazard(
                IdentifierFormDriftSubThreat::identifierStatusShift($pos, $cp),
                [$pos],
                [],
            );
        } else {
            $classification = IdentifierFormDriftClassification::clear();
        }

        return new IdentifierFormDriftVerdict(
            $input,
            $classification,
            self::statusShiftCount($input),
        );
    }
}
