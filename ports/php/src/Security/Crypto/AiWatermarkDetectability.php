<?php

declare(strict_types=1);

// ai-watermark-detectability — character-level detector for inputs carrying
// codepoint patterns consistent with a known AI watermark scheme. Answers the
// question: does this input contain markers attributable to a watermarking
// protocol?
//
// Direct port of `Unicode/Security/Crypto/AiWatermarkDetectability.lean`,
// transliterated byte-faithfully from the verified rust reference
// `ports/rust/src/security/crypto/ai_watermark_detectability.rs`.
//
// Threat model — provenance-attribution attacker. An input either (a) carries
// an AI provider's watermark codepoints (a legitimate provenance marker) or
// (b) carries injected markers that impersonate a provider's scheme to
// discredit the content as AI-generated. Character-level detection alone cannot
// distinguish (a) from (b); the detector reports the matched scheme and leaves
// provider-specific authentication to downstream code.
//
// Probe inventory (priority order, first match wins):
//
//   1. adversarial              — NNBSP count >= 3 at arithmetic-progression positions.
//   2. gpt5ZwspModulo           — ZWSP count >= 3 at arithmetic-progression positions.
//   3. unknown                  — invisible markers from >= 2 distinct categories.
//   4. nnbspBoundary            — single-category NNBSP.
//   5. variationSelectorCarrier — VS NOT adjacent to an emoji codepoint.
//   6. zwjNonEmoji              — ZWJ NOT adjacent to an emoji codepoint.
//   7. smartQuoteAlternation    — paired curly quotes, no ASCII straight quotes.
//   8. emDashPattern            — em-dashes, no ASCII hyphen-minus.
//   9. statisticalTokenChoice   — input contains an AI-favored lexical pattern.
//  10. defaultIgnorableCarrier  — single-category residual Default_Ignorable.
//
// The Emoji property table is bundled in the port's own `data/emoji-data.txt`
// (UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
// adjacency probe parses the `Emoji` rows from it, never a host emoji library.
//
// PHP has no module system, so the support types the rust reference keeps in a
// dedicated module (SubThreat, Classification, Context, Verdict, CueClass) are
// carried here under an `AiWatermark` class-name prefix — the crypto namespace
// already binds bare `SubThreat`/`Classification`/`Context` to the sibling
// hash-input detector. The tag strings, cue-class names, variant order, and
// priority all mirror the reference exactly.

namespace UnicodePhp\Security\Crypto;

use UnicodePhp\Data;
use UnicodePhp\Security\Identity\Ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/**
 * The conceptual watermark cue class a sub-threat probes for, drawn from the
 * fixed vocabulary in `Unicode.Generated.WatermarkSchemes.CueClass`. Ported
 * here because the port exposes no generated watermark-schemes module.
 */
enum AiWatermarkCueClass
{
    /** A codepoint-frequency bias toward a pinned "green list" of tokens. */
    case GreenListBias;
    /** A fixed-period or carrier-byte channel surfacing a pseudorandom function. */
    case PseudorandomSeq;
    /** A stylistic-distribution drift away from natural human writing. */
    case SemanticDrift;
}

/**
 * Sub-threats this detector can fire. Each variant has a corresponding probe in
 * `detect`; the payload carries the position information the conformance
 * harness's attribution column reads back. The tag is the human-facing
 * classification string, mirrored verbatim from the rust reference.
 */
final class AiWatermarkSubThreat
{
    private function __construct(
        public readonly string $kind,
        public readonly ?int $markerCount,
        public readonly ?int $firstPos,
        public readonly ?string $impersonatedScheme,
        public readonly ?int $anomalyMarker,
    ) {
    }

    /** Single-category NNBSP (U+202F) markers; $markerCount is how many. */
    public static function nnbspBoundary(int $markerCount): AiWatermarkSubThreat
    {
        return new AiWatermarkSubThreat('NnbspBoundary', $markerCount, null, null, null);
    }

    /** Variation selector(s) not adjacent to an emoji; $markerCount is how many. */
    public static function variationSelectorCarrier(int $markerCount): AiWatermarkSubThreat
    {
        return new AiWatermarkSubThreat('VariationSelectorCarrier', $markerCount, null, null, null);
    }

    /** ZWJ(s) not adjacent to an emoji; $markerCount is how many. */
    public static function zwjNonEmoji(int $markerCount): AiWatermarkSubThreat
    {
        return new AiWatermarkSubThreat('ZwjNonEmoji', $markerCount, null, null, null);
    }

    /** Residual Default_Ignorable markers; $markerCount is how many. */
    public static function defaultIgnorableCarrier(int $markerCount): AiWatermarkSubThreat
    {
        return new AiWatermarkSubThreat('DefaultIgnorableCarrier', $markerCount, null, null, null);
    }

    /** ZWSP (U+200B) markers at arithmetic-progression positions; $firstPos is the first ZWSP. */
    public static function gpt5ZwspModulo(int $firstPos): AiWatermarkSubThreat
    {
        return new AiWatermarkSubThreat('Gpt5ZwspModulo', null, $firstPos, null, null);
    }

    /** Em-dash (U+2014) stylistic signature; $firstPos is the first em-dash. */
    public static function emDashPattern(int $firstPos): AiWatermarkSubThreat
    {
        return new AiWatermarkSubThreat('EmDashPattern', null, $firstPos, null, null);
    }

    /** Paired curly-quote stylistic signature; $firstPos is the first quote. */
    public static function smartQuoteAlternation(int $firstPos): AiWatermarkSubThreat
    {
        return new AiWatermarkSubThreat('SmartQuoteAlternation', null, $firstPos, null, null);
    }

    /** AI-favored lexical pattern hit; $firstPos is the match start. */
    public static function statisticalTokenChoice(int $firstPos): AiWatermarkSubThreat
    {
        return new AiWatermarkSubThreat('StatisticalTokenChoice', null, $firstPos, null, null);
    }

    /**
     * Over-regular marker placement impersonating a scheme; $impersonatedScheme
     * names the surfaced scheme, $firstPos the first marker position.
     */
    public static function adversarial(string $impersonatedScheme, int $firstPos): AiWatermarkSubThreat
    {
        return new AiWatermarkSubThreat('Adversarial', null, $firstPos, $impersonatedScheme, null);
    }

    /**
     * Multi-category invisible-marker mixing; $anomalyMarker is the total
     * invisible-marker count (attribution to a single scheme fails).
     */
    public static function unknown(int $anomalyMarker): AiWatermarkSubThreat
    {
        return new AiWatermarkSubThreat('Unknown', null, null, null, $anomalyMarker);
    }

    /** Human-facing classification tag for this sub-threat. */
    public function tag(): string
    {
        return $this->kind;
    }

    /**
     * Map this sub-threat to the conceptual watermark cue class it probes for.
     * Marker-encoded sub-threats route to PseudorandomSeq; vocabulary-bias to
     * GreenListBias; stylistic-distribution to SemanticDrift; Unknown
     * (multi-category mixing) implicates no single scheme.
     */
    public function cueClass(): ?AiWatermarkCueClass
    {
        return match ($this->kind) {
            'NnbspBoundary',
            'VariationSelectorCarrier',
            'ZwjNonEmoji',
            'DefaultIgnorableCarrier',
            'Gpt5ZwspModulo',
            'Adversarial' => AiWatermarkCueClass::PseudorandomSeq,
            'EmDashPattern',
            'SmartQuoteAlternation' => AiWatermarkCueClass::SemanticDrift,
            'StatisticalTokenChoice' => AiWatermarkCueClass::GreenListBias,
            'Unknown' => null,
            default => throw new \RuntimeException("AiWatermarkSubThreat: unknown kind '{$this->kind}'"),
        };
    }
}

/**
 * Top-level AiWatermarkDetectability classification: Clear, or a Hazard
 * carrying the fired sub-threat and the codepoint positions it implicates.
 */
final class AiWatermarkClassification
{
    /** @param list<int> $positions */
    private function __construct(
        public readonly ?AiWatermarkSubThreat $sub,
        public readonly array $positions,
    ) {
    }

    public static function clear(): AiWatermarkClassification
    {
        return new AiWatermarkClassification(null, []);
    }

    /** @param list<int> $positions */
    public static function hazard(AiWatermarkSubThreat $sub, array $positions): AiWatermarkClassification
    {
        return new AiWatermarkClassification($sub, $positions);
    }

    /** True iff no watermark marker was detected. */
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
 * Verdict — the structured output of `detect`. $markerCount is the count of
 * codepoints matching the fired scheme's probe (0 when clear).
 */
final class AiWatermarkVerdict
{
    /**
     * @param list<int> $input
     */
    public function __construct(
        public readonly array $input,
        public readonly AiWatermarkClassification $classify,
        public readonly int $markerCount,
    ) {
    }
}

/**
 * Optional context for the modulo-probe tolerances. Each field controls how
 * strictly the corresponding probe checks its arithmetic-progression condition;
 * the defaults of 0 require exact equality of consecutive gaps.
 */
final class AiWatermarkContext
{
    public function __construct(
        /**
         * ZWSP-modulo tolerance. 0 requires the ZWSP-position arithmetic
         * progression to be exact. k > 0 accepts position gaps within +/- k of
         * the first gap, catching modulo schedules with light jitter.
         */
        public readonly int $zwspModuloTolerance = 0,
        /**
         * NNBSP-arithmetic tolerance (the adversarial probe). Same semantic as
         * $zwspModuloTolerance but for the NNBSP positions.
         */
        public readonly int $adversarialTolerance = 0,
    ) {
    }
}

final class AiWatermarkDetectability
{
    /** @var list<array{0:int,1:int}>|null Cached Emoji=Yes closed intervals. */
    private static ?array $emojiRanges = null;

    // ─────────────────────────────────────────────────────────────────
    // §2 Emoji property table (bundled data/emoji-data.txt, Emoji rows)
    // ─────────────────────────────────────────────────────────────────

    /**
     * Parse the `Emoji` (`Emoji=Yes`) closed intervals from emoji-data.txt. Each
     * non-comment row is `<range> ; <property> # <comment>`; we keep only rows
     * whose property is exactly `Emoji`.
     *
     * @return list<array{0:int,1:int}>
     */
    private static function emojiRanges(): array
    {
        if (self::$emojiRanges !== null) {
            return self::$emojiRanges;
        }
        $out = [];
        foreach (Data::lines('emoji-data.txt') as $rawLine) {
            $hash = strpos($rawLine, '#');
            $body = $hash === false ? $rawLine : substr($rawLine, 0, $hash);
            $stripped = trim($body);
            if ($stripped === '') {
                continue;
            }
            $fields = explode(';', $stripped);
            if (count($fields) < 2) {
                continue;
            }
            if (trim($fields[1]) !== 'Emoji') {
                continue;
            }
            $range = trim($fields[0]);
            $dots = strpos($range, '..');
            if ($dots !== false) {
                $lo = self::parseHex(substr($range, 0, $dots));
                $hi = self::parseHex(substr($range, $dots + 2));
            } else {
                $lo = self::parseHex($range);
                $hi = $lo;
            }
            if ($lo === null || $hi === null) {
                continue;
            }
            $out[] = [$lo, $hi];
        }
        self::$emojiRanges = $out;
        return $out;
    }

    /** Parse a trimmed hexadecimal codepoint field, or null if malformed. */
    private static function parseHex(string $s): ?int
    {
        $s = trim($s);
        if ($s === '' || !ctype_xdigit($s)) {
            return null;
        }
        return intval($s, 16);
    }

    /** True iff $cp has the `Emoji = Yes` property per emoji-data.txt. */
    private static function isEmoji(int $cp): bool
    {
        foreach (self::emojiRanges() as [$lo, $hi]) {
            if ($lo <= $cp && $cp <= $hi) {
                return true;
            }
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────
    // §3 Codepoint probes
    // ─────────────────────────────────────────────────────────────────

    /** True iff $cp is U+202F NARROW NO-BREAK SPACE. */
    private static function isNnbsp(int $cp): bool
    {
        return $cp === 0x202F;
    }

    /** True iff $cp is U+200D ZERO WIDTH JOINER. */
    private static function isZwj(int $cp): bool
    {
        return $cp === 0x200D;
    }

    /**
     * True iff $cp is a Variation Selector — the basic block U+FE00..U+FE0F
     * (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
     */
    private static function isVariationSelector(int $cp): bool
    {
        return ($cp >= 0xFE00 && $cp <= 0xFE0F) || ($cp >= 0xE0100 && $cp <= 0xE01EF);
    }

    /**
     * True iff $cp is Default_Ignorable_Code_Point per DerivedCoreProperties.txt.
     * Reuses the port's own UCD table, never a host normalizer.
     */
    private static function isDefaultIgnorable(int $cp): bool
    {
        return Ucd::isDefaultIgnorable($cp);
    }

    /** True iff $cp is U+200B ZERO WIDTH SPACE. */
    private static function isZwsp(int $cp): bool
    {
        return $cp === 0x200B;
    }

    /** True iff $cp is U+2014 EM DASH. */
    private static function isEmDash(int $cp): bool
    {
        return $cp === 0x2014;
    }

    /** True iff $cp is U+002D HYPHEN-MINUS (ASCII). */
    private static function isHyphenMinus(int $cp): bool
    {
        return $cp === 0x002D;
    }

    /**
     * True iff $cp is one of the four "curly" quotation marks: U+2018 / U+2019
     * (single open/close) and U+201C / U+201D (double open/close).
     */
    private static function isCurlyQuote(int $cp): bool
    {
        return $cp === 0x2018 || $cp === 0x2019 || $cp === 0x201C || $cp === 0x201D;
    }

    /**
     * True iff $cp is an ASCII straight quote — U+0022 (double) or U+0027
     * (single / apostrophe).
     */
    private static function isStraightQuote(int $cp): bool
    {
        return $cp === 0x0022 || $cp === 0x0027;
    }

    /**
     * True iff $input[$i] is adjacent (immediate predecessor OR immediate
     * successor) to an emoji codepoint. Two-sided check, single pass. Used by
     * the VS and ZWJ probes to exclude legitimate emoji-context occurrences.
     *
     * @param list<int> $input
     */
    private static function isAdjacentToEmoji(array $input, int $i): bool
    {
        $prevIsEmoji = $i > 0 && array_key_exists($i - 1, $input) && self::isEmoji($input[$i - 1]);
        $nextIsEmoji = array_key_exists($i + 1, $input) && self::isEmoji($input[$i + 1]);
        return $prevIsEmoji || $nextIsEmoji;
    }

    /**
     * All positions in $input matching predicate $p.
     *
     * @param list<int> $input
     * @return list<int>
     */
    private static function allPositions(callable $p, array $input): array
    {
        $out = [];
        foreach ($input as $idx => $cp) {
            if ($p($cp)) {
                $out[] = $idx;
            }
        }
        return $out;
    }

    /**
     * True iff $positions forms an arithmetic progression with all consecutive
     * gaps within $tolerance of the first gap. Empty + singleton lists are
     * vacuously arithmetic. $positions is assumed ascending (produced by
     * `allPositions`), so gaps are non-negative.
     *
     * @param list<int> $positions
     */
    private static function positionsAreArithmeticWithin(array $positions, int $tolerance): bool
    {
        $count = count($positions);
        if ($count < 2) {
            return true;
        }
        $firstGap = $positions[1] - $positions[0];
        for ($i = 0; $i < $count - 1; $i++) {
            $gap = $positions[$i + 1] - $positions[$i];
            if (!($gap <= $firstGap + $tolerance && $firstGap <= $gap + $tolerance)) {
                return false;
            }
        }
        return true;
    }

    /**
     * First start-position at which $pattern appears as a contiguous sub-slice
     * of $input, or null if absent.
     *
     * @param list<int> $pattern
     * @param list<int> $input
     */
    private static function containsSublist(array $pattern, array $input): ?int
    {
        $patternLen = count($pattern);
        $inputLen = count($input);
        if ($patternLen === 0 || $patternLen > $inputLen) {
            return null;
        }
        $maxStart = $inputLen - $patternLen;
        for ($start = 0; $start <= $maxStart; $start++) {
            if (array_slice($input, $start, $patternLen) === $pattern) {
                return $start;
            }
        }
        return null;
    }

    /**
     * The "AI-favored" lexical-pattern catalog (each word as its codepoint
     * sequence), transcribed verbatim from the pinned `aiFavoredVocabulary`
     * literal in the Lean spec (parsed from
     * `Ucd/Security/AiFavoredVocabulary.txt` and drift-gated there against a
     * fresh parse).
     *
     * @return list<list<int>>
     */
    private static function aiFavoredVocabulary(): array
    {
        return [
            [100, 101, 108, 118, 101],
            [100, 101, 108, 118, 105, 110, 103],
            [116, 97, 112, 101, 115, 116, 114, 121],
            [105, 110, 116, 114, 105, 99, 97, 116, 101],
            [110, 117, 97, 110, 99, 101, 100],
            [109, 111, 114, 101, 111, 118, 101, 114],
            [102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101],
            [114, 101, 97, 108, 109],
            [101, 108, 117, 99, 105, 100, 97, 116, 101],
            [115, 104, 111, 119, 99, 97, 115, 105, 110, 103],
            [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115],
            [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100],
            [112, 105, 118, 111, 116, 97, 108],
            [98, 111, 108, 115, 116, 101, 114],
            [109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100],
            [116, 101, 115, 116, 97, 109, 101, 110, 116],
            [102, 111, 115, 116, 101, 114],
            [104, 111, 108, 105, 115, 116, 105, 99],
            [112, 97, 114, 97, 100, 105, 103, 109],
            [116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101],
            [115, 112, 101, 97, 114, 104, 101, 97, 100],
            [109, 101, 116, 105, 99, 117, 108, 111, 117, 115],
            [109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121],
            [101, 109, 112, 111, 119, 101, 114],
            [101, 109, 112, 111, 119, 101, 114, 105, 110, 103],
            [112, 114, 111, 102, 111, 117, 110, 100],
            [112, 114, 111, 102, 111, 117, 110, 100, 108, 121],
            [99, 111, 109, 112, 101, 108, 108, 105, 110, 103],
            [99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101],
            [99, 114, 117, 99, 105, 97, 108],
            [100, 97, 117, 110, 116, 105, 110, 103],
            [114, 111, 98, 117, 115, 116],
            [115, 116, 114, 101, 97, 109, 108, 105, 110, 101],
            [101, 110, 114, 105, 99, 104],
            [101, 120, 101, 109, 112, 108, 105, 102, 121],
            [99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103],
            [100, 105, 115, 99, 101, 114, 110, 105, 110, 103],
            [109, 101, 115, 109, 101, 114, 105, 122, 101],
            [105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121],
            [105, 109, 98, 117, 101],
            [
                112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108,
                101,
            ],
            [
                112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111,
                108, 101,
            ],
            [
                105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111,
                32, 110, 111, 116, 101,
            ],
            [
                105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103,
            ],
            [105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110],
            [105, 110, 32, 101, 115, 115, 101, 110, 99, 101],
            [100, 101, 108, 118, 101, 32, 105, 110, 116, 111],
            [100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111],
            [116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102],
            [114, 101, 97, 108, 109, 32, 111, 102],
        ];
    }

    // ─────────────────────────────────────────────────────────────────
    // §4 Top-level detection
    // ─────────────────────────────────────────────────────────────────

    /**
     * The detection function. Runs every probe in the fixed priority order
     * (most-specific first); the first hit wins. See the file header for the
     * probe inventory and the ordering rationale.
     *
     * @param list<int> $input
     */
    public static function detectWithContext(AiWatermarkContext $ctx, array $input): AiWatermarkVerdict
    {
        $input = array_values($input);

        $nnbspPositions = self::allPositions([self::class, 'isNnbsp'], $input);
        $nnbspCount = count($nnbspPositions);

        // Probe 1: adversarial — NNBSP too-regular.
        $adversarialFires = $nnbspCount >= 3
            && self::positionsAreArithmeticWithin($nnbspPositions, $ctx->adversarialTolerance);

        // Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
        $zwspPositions = self::allPositions([self::class, 'isZwsp'], $input);
        $zwspCount = count($zwspPositions);
        $zwspModuloFires = $zwspCount >= 3
            && self::positionsAreArithmeticWithin($zwspPositions, $ctx->zwspModuloTolerance);

        $vsAllPos = self::allPositions([self::class, 'isVariationSelector'], $input);
        $vsNonEmojiPos = [];
        foreach ($vsAllPos as $i) {
            if (!self::isAdjacentToEmoji($input, $i)) {
                $vsNonEmojiPos[] = $i;
            }
        }
        $vsNonEmojiCount = count($vsNonEmojiPos);

        $zwjAllPos = self::allPositions([self::class, 'isZwj'], $input);
        $zwjNonEmojiPos = [];
        foreach ($zwjAllPos as $i) {
            if (!self::isAdjacentToEmoji($input, $i)) {
                $zwjNonEmojiPos[] = $i;
            }
        }
        $zwjNonEmojiCount = count($zwjNonEmojiPos);

        // Probe 7: smartQuoteAlternation — curly quotes only.
        $curlyPositions = self::allPositions([self::class, 'isCurlyQuote'], $input);
        $curlyCount = count($curlyPositions);
        $hasStraightQuote = self::anyMatches([self::class, 'isStraightQuote'], $input);
        $smartQuoteFires = $curlyCount >= 2 && !$hasStraightQuote;

        // Probe 8: emDashPattern — em-dashes without hyphen-minus.
        $emDashPositions = self::allPositions([self::class, 'isEmDash'], $input);
        $emDashCount = count($emDashPositions);
        $hasHyphenMinus = self::anyMatches([self::class, 'isHyphenMinus'], $input);
        $emDashFires = $emDashCount >= 2 && !$hasHyphenMinus;

        // Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word
        // is compared as a contiguous sub-slice of the input.
        $vocabHit = null;
        foreach (self::aiFavoredVocabulary() as $pattern) {
            $pos = self::containsSublist($pattern, $input);
            if ($pos !== null) {
                $vocabHit = $pos;
                break;
            }
        }

        // Residual default-ignorables (excluding VS and ZWJ, handled above).
        $isResidualDi = static fn (int $cp): bool =>
            self::isDefaultIgnorable($cp) && !self::isVariationSelector($cp) && !self::isZwj($cp);
        $diPositions = self::allPositions($isResidualDi, $input);
        $diCount = count($diPositions);

        // Probe 3: unknown — invisible markers from >= 2 distinct categories.
        $categoryCount = ($nnbspCount > 0 ? 1 : 0)
            + ($vsNonEmojiCount > 0 ? 1 : 0)
            + ($zwjNonEmojiCount > 0 ? 1 : 0)
            + ($diCount > 0 ? 1 : 0);
        $unknownFires = $categoryCount >= 2;
        $totalInvisibleCount = $nnbspCount + $vsNonEmojiCount + $zwjNonEmojiCount + $diCount;

        if ($adversarialFires) {
            $firstPos = $nnbspPositions[0] ?? 0;
            $classification = AiWatermarkClassification::hazard(
                AiWatermarkSubThreat::adversarial('nnbspBoundary', $firstPos),
                $nnbspPositions,
            );
            $firedCount = $nnbspCount;
        } elseif ($zwspModuloFires) {
            $firstPos = $zwspPositions[0] ?? 0;
            $classification = AiWatermarkClassification::hazard(
                AiWatermarkSubThreat::gpt5ZwspModulo($firstPos),
                $zwspPositions,
            );
            $firedCount = $zwspCount;
        } elseif ($unknownFires) {
            $allInvisiblePos = [];
            foreach ($input as $idx => $cp) {
                if (self::isNnbsp($cp) || self::isVariationSelector($cp) || self::isZwj($cp) || self::isDefaultIgnorable($cp)) {
                    $allInvisiblePos[] = $idx;
                }
            }
            $classification = AiWatermarkClassification::hazard(
                AiWatermarkSubThreat::unknown($totalInvisibleCount),
                $allInvisiblePos,
            );
            $firedCount = $totalInvisibleCount;
        } elseif ($nnbspCount > 0) {
            $classification = AiWatermarkClassification::hazard(
                AiWatermarkSubThreat::nnbspBoundary($nnbspCount),
                $nnbspPositions,
            );
            $firedCount = $nnbspCount;
        } elseif ($vsNonEmojiCount > 0) {
            $classification = AiWatermarkClassification::hazard(
                AiWatermarkSubThreat::variationSelectorCarrier($vsNonEmojiCount),
                $vsNonEmojiPos,
            );
            $firedCount = $vsNonEmojiCount;
        } elseif ($zwjNonEmojiCount > 0) {
            $classification = AiWatermarkClassification::hazard(
                AiWatermarkSubThreat::zwjNonEmoji($zwjNonEmojiCount),
                $zwjNonEmojiPos,
            );
            $firedCount = $zwjNonEmojiCount;
        } elseif ($smartQuoteFires) {
            $firstPos = $curlyPositions[0] ?? 0;
            $classification = AiWatermarkClassification::hazard(
                AiWatermarkSubThreat::smartQuoteAlternation($firstPos),
                $curlyPositions,
            );
            $firedCount = $curlyCount;
        } elseif ($emDashFires) {
            $firstPos = $emDashPositions[0] ?? 0;
            $classification = AiWatermarkClassification::hazard(
                AiWatermarkSubThreat::emDashPattern($firstPos),
                $emDashPositions,
            );
            $firedCount = $emDashCount;
        } elseif ($vocabHit !== null) {
            $classification = AiWatermarkClassification::hazard(
                AiWatermarkSubThreat::statisticalTokenChoice($vocabHit),
                [$vocabHit],
            );
            $firedCount = 1;
        } elseif ($diCount > 0) {
            $classification = AiWatermarkClassification::hazard(
                AiWatermarkSubThreat::defaultIgnorableCarrier($diCount),
                $diPositions,
            );
            $firedCount = $diCount;
        } else {
            $classification = AiWatermarkClassification::clear();
            $firedCount = 0;
        }

        return new AiWatermarkVerdict($input, $classification, $firedCount);
    }

    /**
     * Convenience wrapper over `detectWithContext` with the empty context —
     * exact-arithmetic settings ($zwspModuloTolerance = 0,
     * $adversarialTolerance = 0).
     *
     * @param list<int> $input
     */
    public static function detect(array $input): AiWatermarkVerdict
    {
        return self::detectWithContext(new AiWatermarkContext(), $input);
    }

    /**
     * True iff any codepoint in $input matches predicate $p.
     *
     * @param list<int> $input
     */
    private static function anyMatches(callable $p, array $input): bool
    {
        foreach ($input as $cp) {
            if ($p($cp)) {
                return true;
            }
        }
        return false;
    }
}
