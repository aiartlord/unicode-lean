<?php

declare(strict_types=1);

// EmojiZwjIntegrity — detection of malformed / unsanctioned emoji ZWJ-sequence
// shapes per UTS #51 (the identity-layer detector I3).
//
// Byte-faithful port of the verified rust reference
// `ports/rust/src/security/identity/emoji_zwj_integrity.rs` and of
// `Unicode/Security/Identity/EmojiZwjIntegrity.lean`.
//
// Threat model. An adversary crafts an emoji-shaped codepoint sequence
// containing one or more U+200D ZERO WIDTH JOINERs but violating the sanctioned
// RGI ZWJ-sequence shape — by exceeding the RGI length cap, by joining a
// non-emoji codepoint, by emitting adjacent ZWJ pairs, or by overflowing the
// skin-tone count. Any non-RGI ZWJ-containing sequence is renderer-dependent,
// and that renderer divergence is the attack surface.
//
// Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
// `emoji-zwj-sequences.txt`, bundled byte-identically in this port's own
// `data/emoji-zwj-sequences.txt` and parsed here with the port's own text idiom
// (never a host emoji library, never String normalization). The registered set
// gives both the exact-match membership test (`isRegisteredZwjSequence`) and the
// ZWJ *alphabet* — every distinct codepoint occurring at any position of any
// registered sequence, excluding the joiner — which is the canonical "what may
// flank a ZWJ?" predicate.
//
// Algorithm (one pass over `input`).
//   Phase 1 — collect ZWJ positions and the skin-tone count.
//   Phase 2 — short-circuit Clear if there are no ZWJs and the skin-tone count
//             is at most 1.
//   Phase 3 — a registered RGI sequence is always Clear.
//   Phase 4 — check sub-threats by priority:
//               1. DoubleZWJ            ZWJ-ZWJ adjacency
//               2. NonEmojiInjection    ZWJ adjacent to a non-emoji codepoint
//               3. OverLength           sequence longer than the RGI cap
//               4. SkinToneOverflow     skin-tone count >= 5
//               5. UnregisteredSequence catch-all when ZWJs are present but the
//                                       sequence is not registered.
//
// PHP has no module system, so the support types the rust reference keeps in a
// dedicated module (SubThreat, Classification, Verdict) are carried here under an
// `EmojiZwj` class-name prefix — the identity namespace already binds bare names
// for the sibling homoglyph detector's helpers. The tag strings, variant order,
// and priority all mirror the reference exactly.

namespace UnicodePhp\Security\Identity;

use UnicodePhp\Data;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/**
 * A sub-threat this detector can fire, in priority order. Each variant carries
 * only the payload the rust reference records for it; the unused payload fields
 * are null. The tag is the human-facing classification string, mirrored verbatim
 * from the rust reference.
 */
final class EmojiZwjSubThreat
{
    /**
     * @param list<int>|null $positions First ZWJ of each ZWJ-ZWJ pair (DoubleZWJ only).
     */
    private function __construct(
        public readonly string $kind,
        public readonly ?array $positions,
        public readonly ?int $zwjPos,
        public readonly ?int $nonEmojiCp,
        public readonly ?int $length,
        public readonly ?int $maxLength,
        public readonly ?int $count,
        public readonly ?int $chainLen,
    ) {
    }

    /**
     * ZWJ-ZWJ adjacency; $positions are the first ZWJ of each adjacent pair.
     *
     * @param list<int> $positions
     */
    public static function doubleZwj(array $positions): EmojiZwjSubThreat
    {
        return new EmojiZwjSubThreat('DoubleZWJ', $positions, null, null, null, null, null, null);
    }

    /**
     * A ZWJ flanked by a non-emoji codepoint (or sitting at an input edge).
     * $zwjPos is the offending ZWJ; $nonEmojiCp is the flanking codepoint (0 for
     * an edge ZWJ).
     */
    public static function nonEmojiInjection(int $zwjPos, int $nonEmojiCp): EmojiZwjSubThreat
    {
        return new EmojiZwjSubThreat('NonEmojiInjection', null, $zwjPos, $nonEmojiCp, null, null, null, null);
    }

    /** The sequence is longer than the RGI cap; $length observed, $maxLength the cap. */
    public static function overLength(int $length, int $maxLength): EmojiZwjSubThreat
    {
        return new EmojiZwjSubThreat('OverLength', null, null, null, $length, $maxLength, null, null);
    }

    /** Five or more skin-tone modifiers (the family-emoji maximum is four); $count observed. */
    public static function skinToneOverflow(int $count): EmojiZwjSubThreat
    {
        return new EmojiZwjSubThreat('SkinToneOverflow', null, null, null, null, null, $count, null);
    }

    /**
     * ZWJs are present and no other sub-threat matched, but the sequence is not a
     * registered RGI ZWJ sequence; $chainLen is the length of the unregistered chain.
     */
    public static function unregisteredSequence(int $chainLen): EmojiZwjSubThreat
    {
        return new EmojiZwjSubThreat('UnregisteredSequence', null, null, null, null, null, null, $chainLen);
    }

    /** Fixture-row / wire tag string for this sub-threat (matches `SubThreat.tag`). */
    public function tag(): string
    {
        return match ($this->kind) {
            'DoubleZWJ' => 'DoubleZWJ',
            'NonEmojiInjection' => 'NonEmojiInjection',
            'OverLength' => 'OverLength',
            'SkinToneOverflow' => 'SkinToneOverflow',
            'UnregisteredSequence' => 'UnregisteredSequence',
            default => throw new \RuntimeException("EmojiZwjSubThreat: unknown kind '{$this->kind}'"),
        };
    }
}

/**
 * Top-level classification for EmojiZwjIntegrity: Clear, or a Hazard carrying the
 * fired sub-threat, the implicated positions, and the (always-empty for this
 * detector) decoded-byte projection kept for shape parity with the Lean
 * `Classification.hazard`.
 */
final class EmojiZwjClassification
{
    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    private function __construct(
        public readonly ?EmojiZwjSubThreat $sub,
        public readonly array $positions,
        public readonly array $decoded,
    ) {
    }

    public static function clear(): EmojiZwjClassification
    {
        return new EmojiZwjClassification(null, [], []);
    }

    /**
     * @param list<int> $positions
     * @param list<int> $decoded
     */
    public static function hazard(EmojiZwjSubThreat $sub, array $positions, array $decoded): EmojiZwjClassification
    {
        return new EmojiZwjClassification($sub, $positions, $decoded);
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

/**
 * The structured output of `detect` (mirrors the Lean `Verdict`).
 * $chainLength is 0 when there are no ZWJs, else the input length;
 * $isRegisteredRgi is true iff the input is exactly a registered RGI ZWJ
 * sequence; $skinToneCount counts U+1F3FB..U+1F3FF.
 */
final class EmojiZwjVerdict
{
    /**
     * @param list<int> $input
     * @param list<int> $zwjPositions
     */
    public function __construct(
        public readonly array $input,
        public readonly EmojiZwjClassification $classify,
        public readonly array $zwjPositions,
        public readonly int $chainLength,
        public readonly bool $isRegisteredRgi,
        public readonly int $skinToneCount,
    ) {
    }
}

final class EmojiZwjIntegrity
{
    // ─────────────────────────────────────────────────────────────────
    // §1 Constants
    // ─────────────────────────────────────────────────────────────────

    /**
     * Conservative cap on the length of a sanctioned RGI ZWJ sequence
     * (`maxRgiLength` in the Lean spec). The longest current entry (a four-person
     * family with skin tones) reaches ~13-14 codepoints; 16 is a safe upper bound.
     */
    public const MAX_RGI_LENGTH = 16;

    /** The ZERO WIDTH JOINER codepoint. */
    public const ZWJ = 0x200D;

    /** @var list<list<int>>|null Cached registered RGI ZWJ sequences. */
    private static ?array $zwjSequences = null;

    /** @var array<int,bool>|null Cached ZWJ alphabet, keyed by codepoint. */
    private static ?array $zwjAlphabet = null;

    // ─────────────────────────────────────────────────────────────────
    // §2 RGI ZWJ-sequence data (bundled data/emoji-zwj-sequences.txt)
    // ─────────────────────────────────────────────────────────────────

    /**
     * Parse the registered RGI ZWJ sequences from `emoji-zwj-sequences.txt`. Each
     * non-comment row is `<cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ; <desc> # <cmt>`;
     * the codepoint list is the whitespace-separated field before the first `;`.
     *
     * @return list<list<int>>
     */
    private static function zwjSequences(): array
    {
        if (self::$zwjSequences !== null) {
            return self::$zwjSequences;
        }
        $out = [];
        foreach (Data::lines('emoji-zwj-sequences.txt') as $rawLine) {
            $hash = strpos($rawLine, '#');
            $body = $hash === false ? $rawLine : substr($rawLine, 0, $hash);
            $stripped = trim($body);
            if ($stripped === '') {
                continue;
            }
            $semicolon = strpos($stripped, ';');
            $seqField = $semicolon === false ? $stripped : substr($stripped, 0, $semicolon);
            $seq = [];
            $parsedOk = true;
            foreach (preg_split('/\s+/', trim($seqField), -1, PREG_SPLIT_NO_EMPTY) as $token) {
                $cp = self::parseHex($token);
                if ($cp === null) {
                    $parsedOk = false;
                    break;
                }
                $seq[] = $cp;
            }
            if ($parsedOk && $seq !== []) {
                $out[] = $seq;
            }
        }
        self::$zwjSequences = $out;
        return $out;
    }

    /** Parse a trimmed hexadecimal codepoint token, or null if not all-hex. */
    private static function parseHex(string $s): ?int
    {
        $s = trim($s);
        if ($s === '' || !ctype_xdigit($s)) {
            return null;
        }
        return intval($s, 16);
    }

    /**
     * The ZWJ alphabet: every distinct codepoint occurring at any position of any
     * registered RGI ZWJ sequence, excluding the joiner U+200D itself.
     *
     * @return array<int,bool>
     */
    private static function zwjAlphabet(): array
    {
        if (self::$zwjAlphabet !== null) {
            return self::$zwjAlphabet;
        }
        $set = [];
        foreach (self::zwjSequences() as $seq) {
            foreach ($seq as $cp) {
                if ($cp !== self::ZWJ) {
                    $set[$cp] = true;
                }
            }
        }
        self::$zwjAlphabet = $set;
        return $set;
    }

    /**
     * True iff $cps is exactly a registered RGI ZWJ sequence.
     *
     * @param list<int> $cps
     */
    public static function isRegisteredZwjSequence(array $cps): bool
    {
        foreach (self::zwjSequences() as $seq) {
            if ($seq === $cps) {
                return true;
            }
        }
        return false;
    }

    /**
     * True iff $cp appears at some position of a registered RGI ZWJ sequence
     * (the canonical "what may flank a ZWJ?" predicate).
     */
    public static function isEmojiTarget(int $cp): bool
    {
        return isset(self::zwjAlphabet()[$cp]);
    }

    // ─────────────────────────────────────────────────────────────────
    // §3 Core predicates
    // ─────────────────────────────────────────────────────────────────

    /** True iff $cp is the ZWJ codepoint. */
    public static function isZwj(int $cp): bool
    {
        return $cp === self::ZWJ;
    }

    /** True iff $cp is an emoji skin-tone modifier (U+1F3FB..U+1F3FF). */
    public static function isEmojiModifier(int $cp): bool
    {
        return $cp >= 0x1F3FB && $cp <= 0x1F3FF;
    }

    /**
     * Positions of every ZWJ in $input.
     *
     * @param list<int> $input
     * @return list<int>
     */
    private static function zwjPositions(array $input): array
    {
        $out = [];
        foreach ($input as $idx => $cp) {
            if (self::isZwj($cp)) {
                $out[] = $idx;
            }
        }
        return $out;
    }

    /**
     * Count of skin-tone modifier codepoints.
     *
     * @param list<int> $input
     */
    private static function skinToneCount(array $input): int
    {
        $count = 0;
        foreach ($input as $cp) {
            if (self::isEmojiModifier($cp)) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Positions of the first ZWJ in each ZWJ-ZWJ adjacent pair.
     *
     * @param list<int> $input
     * @return list<int>
     */
    private static function doubleZwjPositions(array $input): array
    {
        $out = [];
        $len = count($input);
        for ($idx = 0; $idx < $len; $idx++) {
            if ($idx + 1 >= $len) {
                continue;
            }
            if (self::isZwj($input[$idx]) && self::isZwj($input[$idx + 1])) {
                $out[] = $idx;
            }
        }
        return $out;
    }

    /**
     * The first ZWJ position where either neighbour is a non-emoji codepoint, as
     * `[$zwjPos, $offendingCp]`, or null when none. A ZWJ at an input edge (no
     * preceding or no following codepoint) is itself an injection-class hazard,
     * reported with offending codepoint 0.
     *
     * @param list<int> $input
     * @return array{0:int,1:int}|null
     */
    private static function firstNonEmojiInjection(array $input): ?array
    {
        $len = count($input);
        for ($idx = 0; $idx < $len; $idx++) {
            if (!self::isZwj($input[$idx])) {
                continue;
            }
            $prev = $idx === 0 ? null : $input[$idx - 1];
            $next = $idx + 1 < $len ? $input[$idx + 1] : null;
            if ($prev !== null && $next !== null) {
                if (!self::isEmojiTarget($prev)) {
                    return [$idx, $prev];
                } elseif (!self::isEmojiTarget($next)) {
                    return [$idx, $next];
                }
            } elseif ($prev === null) {
                return [$idx, 0];
            } else {
                return [$idx, 0];
            }
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────
    // §4 Top-level detection
    // ─────────────────────────────────────────────────────────────────

    /**
     * The EmojiZwjIntegrity detection function. Runs the priority ladder over the
     * one-pass scan results; the first sub-threat wins. See the file header for
     * the ordering rationale.
     *
     * @param list<int> $input
     */
    public static function detect(array $input): EmojiZwjVerdict
    {
        $input = array_values($input);

        $zwjs = self::zwjPositions($input);
        $stCount = self::skinToneCount($input);
        $isRgi = self::isRegisteredZwjSequence($input);
        $chainLen = $zwjs === [] ? 0 : count($input);

        if ($zwjs === [] && $stCount <= 1) {
            return new EmojiZwjVerdict($input, EmojiZwjClassification::clear(), [], 0, $isRgi, $stCount);
        }

        if ($isRgi) {
            // Phase 3: a registered RGI sequence is always clear.
            $classification = EmojiZwjClassification::clear();
        } else {
            // Phase 4.1: ZWJ-ZWJ adjacency.
            $dzwj = self::doubleZwjPositions($input);
            if ($dzwj !== []) {
                $classification = EmojiZwjClassification::hazard(
                    EmojiZwjSubThreat::doubleZwj($dzwj),
                    $dzwj,
                    [],
                );
            } else {
                // Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
                $injection = self::firstNonEmojiInjection($input);
                if ($injection !== null) {
                    [$zwjPos, $offendCp] = $injection;
                    $classification = EmojiZwjClassification::hazard(
                        EmojiZwjSubThreat::nonEmojiInjection($zwjPos, $offendCp),
                        [$zwjPos],
                        [],
                    );
                } elseif (count($input) > self::MAX_RGI_LENGTH) {
                    // Phase 4.3: length cap.
                    $classification = EmojiZwjClassification::hazard(
                        EmojiZwjSubThreat::overLength(count($input), self::MAX_RGI_LENGTH),
                        [],
                        [],
                    );
                } elseif ($stCount >= 5) {
                    // Phase 4.4: skin-tone overflow.
                    $classification = EmojiZwjClassification::hazard(
                        EmojiZwjSubThreat::skinToneOverflow($stCount),
                        [],
                        [],
                    );
                } elseif ($zwjs !== []) {
                    // Phase 4.5: catch-all for unregistered ZWJ sequences.
                    $classification = EmojiZwjClassification::hazard(
                        EmojiZwjSubThreat::unregisteredSequence(count($input)),
                        $zwjs,
                        [],
                    );
                } else {
                    $classification = EmojiZwjClassification::clear();
                }
            }
        }

        return new EmojiZwjVerdict($input, $classification, $zwjs, $chainLen, $isRgi, $stCount);
    }
}
