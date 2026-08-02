<?php

declare(strict_types=1);

// Stream-Safe-Text-Format-violation detection (F2) — inputs whose consecutive
// non-starter run exceeds the UAX #15 §13 `streamSafeLimit` of 30. Such an
// input (the canonical "Zalgo" shape, a single base codepoint followed by a
// long combining-mark run) forces unbounded combining-mark buffers in
// receiver-side streaming normalization (`toNfc` / `toNfd` / `toNfkc` /
// `toNfkd`) and is a known DoS vector.
//
// Direct port of `Unicode/Security/Form/StreamSafeViolation.lean`. UAX #15 §13
// defines Stream-Safe Text Format as the remediation: insert U+034F COMBINING
// GRAPHEME JOINER (a starter) after every 30 consecutive non-starters, which
// bounds the normalization buffer.
//
// A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
// (UAX #15 D49). This module reads CCC from the port's own bundled UCD table
// via `Ucd::ccc`, never a host normalizer.
//
// Sub-threat: `StreamSafeOverrun (basePos, runLen)` — the first non-starter
// run whose length exceeds `STREAM_SAFE_LIMIT`. `basePos` is the index of that
// run's first non-starter codepoint.

namespace UnicodePhp\Security\Form;

use UnicodePhp\Security\Identity\Ucd;

// ─────────────────────────────────────────────────────────────────────
// §2 Types
// ─────────────────────────────────────────────────────────────────────

/**
 * Sub-threats this detector can fire.
 *
 * `StreamSafeOverrun` carries the first non-starter run whose length exceeds
 * `STREAM_SAFE_LIMIT`: `basePos` is the index of the run's first non-starter
 * codepoint; `runLen` is the run's length.
 */
final class SubThreat
{
    private function __construct(
        public readonly string $kind,
        public readonly int $basePos,
        public readonly int $runLen,
    ) {
    }

    public static function streamSafeOverrun(int $basePos, int $runLen): SubThreat
    {
        return new SubThreat('StreamSafeOverrun', $basePos, $runLen);
    }

    /** Human-facing classification tag for this sub-threat. */
    public function tag(): string
    {
        return match ($this->kind) {
            'StreamSafeOverrun' => 'StreamSafeOverrun',
            default => throw new \LogicException('unknown StreamSafeViolation sub-threat ' . $this->kind),
        };
    }
}

/**
 * Top-level F2 classification: Clear, or a Hazard carrying the fired
 * sub-threat and the codepoint positions it implicates. `decoded` mirrors the
 * spec's `Classification.hazard` shape and is always empty for this detector.
 */
final class Classification
{
    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    private function __construct(
        public readonly ?SubThreat $sub,
        public readonly array $positions,
        public readonly array $decoded,
    ) {
    }

    public static function clear(): Classification
    {
        return new Classification(null, [], []);
    }

    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    public static function hazard(SubThreat $sub, array $positions, array $decoded): Classification
    {
        return new Classification($sub, $positions, $decoded);
    }

    /** True iff the input is clear. */
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

/**
 * F2 verdict — the structured output of `detect`. The run-inventory summaries
 * (`maxRunLen`, `overrunCount`, `totalNonStarters`) are exposed so downstream
 * callers can size the buffer pressure a streaming normalizer would see.
 */
final class StreamSafeVerdict
{
    /** @param list<int> $input */
    public function __construct(
        public readonly array $input,
        public readonly Classification $classify,
        public readonly int $maxRunLen,
        public readonly int $overrunCount,
        public readonly int $totalNonStarters,
    ) {
    }
}

final class StreamSafeViolation
{
    // ─────────────────────────────────────────────────────────────────
    // §1 Run inventory
    // ─────────────────────────────────────────────────────────────────

    /**
     * UAX #15 §13 Stream-Safe limit: the maximum number of consecutive
     * non-starters permitted before a COMBINING GRAPHEME JOINER must be
     * inserted.
     */
    public const STREAM_SAFE_LIMIT = 30;

    /**
     * True iff $cp is a non-starter — a codepoint with non-zero
     * Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0.
     */
    private static function isNonStarter(int $cp): bool
    {
        return Ucd::ccc($cp) !== 0;
    }

    /**
     * Inventory of `[startIndex, length]` for every maximal non-starter run in
     * $input. A run opens on the first non-starter, its start index is fixed to
     * that codepoint's absolute index, and it closes (emitting its
     * `[start, length]` pair) on the next starter or at end of input.
     *
     * @param list<int> $input
     * @return list<array{0:int,1:int}>
     */
    private static function nonStarterRuns(array $input): array
    {
        $runs = [];
        $curStart = null;
        $curLen = 0;
        foreach ($input as $i => $cp) {
            if (self::isNonStarter($cp)) {
                if ($curStart === null) {
                    $curStart = $i;
                }
                $curLen++;
            } else {
                if ($curStart !== null) {
                    $runs[] = [$curStart, $curLen];
                }
                $curStart = null;
                $curLen = 0;
            }
        }
        if ($curStart !== null) {
            $runs[] = [$curStart, $curLen];
        }
        return $runs;
    }

    /**
     * First non-starter run whose length exceeds `STREAM_SAFE_LIMIT`, as
     * `[startIndex, length]`, or null when none.
     *
     * @param list<int> $input
     * @return array{0:int,1:int}|null
     */
    private static function firstOverrun(array $input): ?array
    {
        foreach (self::nonStarterRuns($input) as $run) {
            if ($run[1] > self::STREAM_SAFE_LIMIT) {
                return $run;
            }
        }
        return null;
    }

    /**
     * Longest non-starter run length in $input.
     *
     * @param list<int> $input
     */
    private static function maxRunLen(array $input): int
    {
        $acc = 0;
        foreach (self::nonStarterRuns($input) as $run) {
            if ($run[1] > $acc) {
                $acc = $run[1];
            }
        }
        return $acc;
    }

    /**
     * Number of distinct non-starter runs that exceed `STREAM_SAFE_LIMIT`.
     *
     * @param list<int> $input
     */
    private static function overrunCount(array $input): int
    {
        $acc = 0;
        foreach (self::nonStarterRuns($input) as $run) {
            if ($run[1] > self::STREAM_SAFE_LIMIT) {
                $acc++;
            }
        }
        return $acc;
    }

    /**
     * Total non-starter codepoints in $input (sum of all run lengths).
     *
     * @param list<int> $input
     */
    private static function totalNonStarters(array $input): int
    {
        $acc = 0;
        foreach (self::nonStarterRuns($input) as $run) {
            $acc += $run[1];
        }
        return $acc;
    }

    // ─────────────────────────────────────────────────────────────────
    // §3 Top-level detection
    // ─────────────────────────────────────────────────────────────────

    /**
     * The F2 detection function. Fires `StreamSafeOverrun` on the first
     * non-starter run whose length exceeds `STREAM_SAFE_LIMIT`.
     *
     * @param list<int> $input
     */
    public static function detect(array $input): StreamSafeVerdict
    {
        $overrun = self::firstOverrun($input);
        if ($overrun !== null) {
            [$basePos, $runLen] = $overrun;
            $classification = Classification::hazard(
                SubThreat::streamSafeOverrun($basePos, $runLen),
                [$basePos],
                [],
            );
        } else {
            $classification = Classification::clear();
        }
        return new StreamSafeVerdict(
            array_values($input),
            $classification,
            self::maxRunLen($input),
            self::overrunCount($input),
            self::totalNonStarters($input),
        );
    }
}
