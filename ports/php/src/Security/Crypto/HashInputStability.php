<?php

declare(strict_types=1);

// hash-input-stability — detection of inputs that are not in canonical
// hash-input form. Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an input
// hashed by a signer must be byte-identical to the input hashed by the
// verifier; if the two ends pick different canonical forms (NFC vs NFD, trim
// policy, line-ending convention) the resulting hashes diverge silently while
// both sides believe they signed the same content.
//
// Direct port of `Unicode/Security/Crypto/HashInputStability.lean`. The
// canonical (hash-stable) form is `trimTrailing(toNfc(input))`, where
// `trimTrailing` strips only ASCII whitespace {U+0020, U+0009, U+000A,
// U+000D}; Unicode whitespace (U+00A0, U+2000..U+200A, U+3000) is content and
// is not stripped. NFC is the port's Ucd::toNfc, never a host normalizer.
//
// Six probes run in strict priority order (first hit wins):
//
//   1. encodingMismatch         (context: declaredEncoding)
//   2. webhookSignatureDrift    (context: serverBytes)
//   3. auditLogReinterpretation (context: asWritten)
//   4. signedMessageRule        (context: rfcRule)
//   5. trailingWhitespace       (bare input)
//   6. normalizationDrift       (bare input)
//   7. clear
//
// Context-specific probes fire first because they carry more precise threat
// information than the generic probes. `detect` is the convenience wrapper
// `detectWithContext(new Context(), input)` that leaves the four
// context-bearing probes silent.

namespace UnicodePhp\Security\Crypto;

use UnicodePhp\Security\Identity\Ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/**
 * RFC canonicalisation profiles that the `signedMessageRule` probe checks
 * against. Each case names a specific canonicalisation rule from a published
 * RFC; callers pass one as Context::$rfcRule to opt the probe in.
 */
enum RfcRule
{
    /** RFC 4880 §5.2.4 — detached signatures normalise trailing whitespace. */
    case Pgp4880TrailingWhitespace;
    /** RFC 9580 (current OpenPGP) — line-endings normalise to CRLF; a bare LF or bare CR violates. */
    case Pgp9580LineEnding;
    /** RFC 8785 §3.2.5 — JSON Canonicalization Scheme requires strings in NFC before serialisation. */
    case Rfc8785NfcRequirement;
    /** RFC 8259 §7 — JSON strings must escape control characters (U+0000..U+001F). */
    case Rfc8259ControlChar;
    /** RFC 7515 §2 — JWS Base64URL; any character outside [A-Za-z0-9_-] violates. */
    case Rfc7515JwsBase64Url;
    /** RFC 6376 §3.4.4 — DKIM relaxed body canonicalization collapses internal whitespace runs to a single SP. */
    case Rfc6376DkimRelaxed;
    /** RFC 5751 §3.1.1 — S/MIME canonical text; a bare LF or bare CR (not part of a CRLF pair) violates. */
    case Rfc5751SmimeLineEnding;

    /**
     * Fixture-string identifier for an RfcRule — used by the conformance
     * harness's attribution parser to round-trip rule selections.
     */
    public function tag(): string
    {
        return match ($this) {
            RfcRule::Pgp4880TrailingWhitespace => 'pgp4880TrailingWhitespace',
            RfcRule::Pgp9580LineEnding => 'pgp9580LineEnding',
            RfcRule::Rfc8785NfcRequirement => 'rfc8785NfcRequirement',
            RfcRule::Rfc8259ControlChar => 'rfc8259ControlChar',
            RfcRule::Rfc7515JwsBase64Url => 'rfc7515JwsBase64Url',
            RfcRule::Rfc6376DkimRelaxed => 'rfc6376DkimRelaxed',
            RfcRule::Rfc5751SmimeLineEnding => 'rfc5751SmimeLineEnding',
        };
    }

    /** Inverse of tag(). Returns null for unrecognised strings. */
    public static function fromTag(string $tag): ?RfcRule
    {
        return match ($tag) {
            'pgp4880TrailingWhitespace' => RfcRule::Pgp4880TrailingWhitespace,
            'pgp9580LineEnding' => RfcRule::Pgp9580LineEnding,
            'rfc8785NfcRequirement' => RfcRule::Rfc8785NfcRequirement,
            'rfc8259ControlChar' => RfcRule::Rfc8259ControlChar,
            'rfc7515JwsBase64Url' => RfcRule::Rfc7515JwsBase64Url,
            'rfc6376DkimRelaxed' => RfcRule::Rfc6376DkimRelaxed,
            'rfc5751SmimeLineEnding' => RfcRule::Rfc5751SmimeLineEnding,
            default => null,
        };
    }
}

/**
 * Sub-threats this detector can fire. Two probes fire from the raw input alone
 * (TrailingWhitespace, NormalizationDrift); the other four require the
 * corresponding Context field to be set. The tag is the human-facing
 * classification; the payload fields carry the diverging positions and labels.
 */
final class SubThreat
{
    private function __construct(
        public readonly string $kind,
        public readonly ?int $firstDivergentPos,
        public readonly ?int $count,
        public readonly ?string $declaredEnc,
        public readonly ?string $detectedEnc,
        public readonly ?string $rfcRule,
        public readonly ?int $firstPos,
    ) {
    }

    public static function normalizationDrift(int $firstDivergentPos): SubThreat
    {
        return new SubThreat('NormalizationDrift', $firstDivergentPos, null, null, null, null, null);
    }

    public static function trailingWhitespace(int $count): SubThreat
    {
        return new SubThreat('TrailingWhitespace', null, $count, null, null, null, null);
    }

    public static function encodingMismatch(string $declaredEnc, string $detectedEnc): SubThreat
    {
        return new SubThreat('EncodingMismatch', null, null, $declaredEnc, $detectedEnc, null, null);
    }

    public static function signedMessageRule(string $rfcRule, int $firstPos): SubThreat
    {
        return new SubThreat('SignedMessageRule', null, null, null, null, $rfcRule, $firstPos);
    }

    public static function auditLogReinterpretation(int $firstDivergentPos): SubThreat
    {
        return new SubThreat('AuditLogReinterpretation', $firstDivergentPos, null, null, null, null, null);
    }

    public static function webhookSignatureDrift(int $firstPos): SubThreat
    {
        return new SubThreat('WebhookSignatureDrift', null, null, null, null, null, $firstPos);
    }

    /** Human-facing classification tag for this sub-threat. */
    public function tag(): string
    {
        return $this->kind;
    }
}

/**
 * Context passed to `detectWithContext` to enable the four context-bearing
 * probes. Each field is null by default — the empty context is the identity
 * case: `detectWithContext(new Context(), input)` equals `detect(input)`.
 */
final class Context
{
    /**
     * @param list<int>|null $asWritten
     * @param list<int>|null $serverBytes
     */
    public function __construct(
        public readonly ?string $declaredEncoding = null,
        public readonly ?RfcRule $rfcRule = null,
        public readonly ?array $asWritten = null,
        public readonly ?array $serverBytes = null,
    ) {
    }
}

/**
 * Top-level classification: Clear, or a Hazard carrying the fired sub-threat
 * and the codepoint positions it implicates.
 */
final class Classification
{
    /** @param list<int> $positions */
    private function __construct(
        public readonly ?SubThreat $sub,
        public readonly array $positions,
    ) {
    }

    public static function clear(): Classification
    {
        return new Classification(null, []);
    }

    /** @param list<int> $positions */
    public static function hazard(SubThreat $sub, array $positions): Classification
    {
        return new Classification($sub, $positions);
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
 * Verdict — the structured output of `detect`. $stableSize is the codepoint
 * count of the hash-stable canonical form; downstream callers compare it
 * against count($input) to size the byte-drift their hash sees.
 */
final class HashInputVerdict
{
    /**
     * @param list<int> $input
     * @param list<int> $stableForm
     */
    public function __construct(
        public readonly array $input,
        public readonly Classification $classify,
        public readonly array $stableForm,
        public readonly int $stableSize,
    ) {
    }
}

final class HashInputStability
{
    // ─────────────────────────────────────────────────────────────────
    // §3 Canonicalisation pipeline
    // ─────────────────────────────────────────────────────────────────

    /**
     * True iff $cp is an ASCII whitespace codepoint that line-oriented
     * hash-input protocols treat as framing rather than content: U+0020 SPACE,
     * U+0009 TAB, U+000A LF, U+000D CR.
     */
    private static function isAsciiWhitespace(int $cp): bool
    {
        return $cp === 0x0020 || $cp === 0x0009 || $cp === 0x000A || $cp === 0x000D;
    }

    /**
     * Count of trailing ASCII whitespace codepoints in $input.
     *
     * @param list<int> $input
     */
    private static function countTrailingWhitespace(array $input): int
    {
        $count = 0;
        for ($i = count($input) - 1; $i >= 0; $i--) {
            if (!self::isAsciiWhitespace($input[$i])) {
                break;
            }
            $count++;
        }
        return $count;
    }

    /**
     * Strip trailing ASCII whitespace.
     *
     * @param list<int> $input
     * @return list<int>
     */
    private static function trimTrailing(array $input): array
    {
        $keep = count($input) - self::countTrailingWhitespace($input);
        return array_slice($input, 0, $keep);
    }

    /**
     * The hash-stable form of an input: NFC then trim, in spec order.
     *
     * @param list<int> $input
     * @return list<int>
     */
    public static function hashStable(array $input): array
    {
        return self::trimTrailing(Ucd::toNfc($input));
    }

    // ─────────────────────────────────────────────────────────────────
    // §5 Priority position-finder
    // ─────────────────────────────────────────────────────────────────

    /**
     * First position at which $a and $b diverge, or the length of the shared
     * prefix when one strictly extends the other. null when identical.
     *
     * @param list<int> $a
     * @param list<int> $b
     */
    private static function firstArrayDivergence(array $a, array $b): ?int
    {
        $common = min(count($a), count($b));
        for ($i = 0; $i < $common; $i++) {
            if ($a[$i] !== $b[$i]) {
                return $i;
            }
        }
        if (count($a) !== count($b)) {
            return $common;
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────
    // §6 Context-bearing probes
    // ─────────────────────────────────────────────────────────────────

    /** Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A). */
    private static function asciiLower(int $cp): int
    {
        if ($cp >= 0x41 && $cp <= 0x5A) {
            return $cp + 0x20;
        }
        return $cp;
    }

    /**
     * True iff $label (after ASCII case-fold) names UTF-8: accepts "utf-8",
     * "UTF-8", "UTF8", "utf8". Non-ASCII bytes pass through unchanged.
     */
    private static function isUtf8Label(string $label): bool
    {
        $normalised = '';
        $length = strlen($label);
        for ($i = 0; $i < $length; $i++) {
            $normalised .= chr(self::asciiLower(ord($label[$i])));
        }
        return $normalised === 'utf-8' || $normalised === 'utf8';
    }

    /**
     * True iff $cp is a valid Unicode scalar value: in [0, 0x10FFFF] and not a
     * surrogate [0xD800, 0xDFFF].
     */
    private static function isValidScalar(int $cp): bool
    {
        return $cp >= 0 && $cp <= 0x10FFFF && !($cp >= 0xD800 && $cp <= 0xDFFF);
    }

    /**
     * First position in $input holding a codepoint that is not a valid Unicode
     * scalar, or null if every codepoint is valid.
     *
     * @param list<int> $input
     */
    private static function firstInvalidScalar(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if (!self::isValidScalar($cp)) {
                return $i;
            }
        }
        return null;
    }

    /**
     * Probe: encodingMismatch. Validity is dispatched first — an invalid scalar
     * fires with detectedEnc = "invalid" regardless of the declared label;
     * otherwise a non-UTF-8 label fires with detectedEnc = "utf-8" at
     * position 0. Returns [declared, detected, firstPos] when firing.
     *
     * @param list<int> $input
     * @return array{0:string,1:string,2:int}|null
     */
    private static function encodingMismatchProbe(string $declared, array $input): ?array
    {
        $pos = self::firstInvalidScalar($input);
        if ($pos !== null) {
            return [$declared, 'invalid', $pos];
        }
        if (self::isUtf8Label($declared)) {
            return null;
        }
        return [$declared, 'utf-8', 0];
    }

    /**
     * Probe: signedMessageRule for pgp4880TrailingWhitespace. Same condition as
     * trailingWhitespace; returns the first position of the trailing run.
     *
     * @param list<int> $input
     */
    private static function pgp4880Violation(array $input): ?int
    {
        $trailing = self::countTrailingWhitespace($input);
        if ($trailing > 0) {
            return count($input) - $trailing;
        }
        return null;
    }

    /**
     * Probe: signedMessageRule for pgp9580LineEnding. First bare LF (U+000A not
     * preceded by CR) or bare CR (U+000D not followed by LF).
     *
     * @param list<int> $input
     */
    private static function pgp9580Violation(array $input): ?int
    {
        $count = count($input);
        foreach ($input as $i => $cp) {
            if ($cp === 0x000A) {
                $precededByCr = $i > 0 && $input[$i - 1] === 0x000D;
                if (!$precededByCr) {
                    return $i;
                }
            } elseif ($cp === 0x000D) {
                $followedByLf = $i + 1 < $count && $input[$i + 1] === 0x000A;
                if (!$followedByLf) {
                    return $i;
                }
            }
        }
        return null;
    }

    /**
     * Probe: signedMessageRule for rfc8785NfcRequirement. Same condition as
     * normalizationDrift; returns the first NFC divergence position.
     *
     * @param list<int> $input
     */
    private static function rfc8785Violation(array $input): ?int
    {
        $nfc = Ucd::toNfc($input);
        if ($input === $nfc) {
            return null;
        }
        return self::firstArrayDivergence($input, $nfc);
    }

    /**
     * Probe: signedMessageRule for rfc8259ControlChar. First C0 control
     * (U+0000..U+001F) — the JSON-permitted whitespace still requires escaping,
     * so it also counts.
     *
     * @param list<int> $input
     */
    private static function rfc8259Violation(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if ($cp <= 0x1F) {
                return $i;
            }
        }
        return null;
    }

    /** True iff $cp is in the JWS Base64URL alphabet [A-Za-z0-9_-]. */
    private static function isBase64Url(int $cp): bool
    {
        return ($cp >= 0x41 && $cp <= 0x5A)      // A-Z
            || ($cp >= 0x61 && $cp <= 0x7A)      // a-z
            || ($cp >= 0x30 && $cp <= 0x39)      // 0-9
            || $cp === 0x2D                      // '-'
            || $cp === 0x5F;                     // LOW LINE
    }

    /**
     * Probe: signedMessageRule for rfc7515JwsBase64Url. First codepoint outside
     * [A-Za-z0-9_-].
     *
     * @param list<int> $input
     */
    private static function rfc7515Violation(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if (!self::isBase64Url($cp)) {
                return $i;
            }
        }
        return null;
    }

    /** True iff $cp is DKIM whitespace: U+0020 SPACE or U+0009 HTAB. */
    private static function isDkimWhitespace(int $cp): bool
    {
        return $cp === 0x20 || $cp === 0x09;
    }

    /**
     * Probe: signedMessageRule for rfc6376DkimRelaxed. Position of the second
     * whitespace codepoint in the first internal whitespace run longer than one.
     *
     * @param list<int> $input
     */
    private static function rfc6376Violation(array $input): ?int
    {
        foreach ($input as $i => $cp) {
            if (self::isDkimWhitespace($cp) && $i > 0 && self::isDkimWhitespace($input[$i - 1])) {
                return $i;
            }
        }
        return null;
    }

    /**
     * Probe: signedMessageRule for rfc5751SmimeLineEnding. Reuses the PGP 9580
     * bare-line-ending rule.
     *
     * @param list<int> $input
     */
    private static function rfc5751Violation(array $input): ?int
    {
        return self::pgp9580Violation($input);
    }

    /**
     * Dispatch the RFC-rule probe. First violation position, or null if clean.
     *
     * @param list<int> $input
     */
    private static function rfcRuleViolation(RfcRule $rule, array $input): ?int
    {
        return match ($rule) {
            RfcRule::Pgp4880TrailingWhitespace => self::pgp4880Violation($input),
            RfcRule::Pgp9580LineEnding => self::pgp9580Violation($input),
            RfcRule::Rfc8785NfcRequirement => self::rfc8785Violation($input),
            RfcRule::Rfc8259ControlChar => self::rfc8259Violation($input),
            RfcRule::Rfc7515JwsBase64Url => self::rfc7515Violation($input),
            RfcRule::Rfc6376DkimRelaxed => self::rfc6376Violation($input),
            RfcRule::Rfc5751SmimeLineEnding => self::rfc5751Violation($input),
        };
    }

    // ─────────────────────────────────────────────────────────────────
    // §7 Top-level detection
    // ─────────────────────────────────────────────────────────────────

    /**
     * The full detection function. Runs all six probes in priority order, with
     * the context-bearing probes ahead of the generic ones.
     *
     * @param list<int> $input
     */
    public static function detectWithContext(Context $ctx, array $input): HashInputVerdict
    {
        $stable = self::hashStable($input);

        // Probe 1: encodingMismatch.
        $encodingHit = $ctx->declaredEncoding !== null
            ? self::encodingMismatchProbe($ctx->declaredEncoding, $input)
            : null;

        // Probe 2: webhookSignatureDrift.
        $webhookHit = $ctx->serverBytes !== null
            ? self::firstArrayDivergence($input, $ctx->serverBytes)
            : null;

        // Probe 3: auditLogReinterpretation.
        $auditHit = $ctx->asWritten !== null
            ? self::firstArrayDivergence($ctx->asWritten, $input)
            : null;

        // Probe 4: signedMessageRule.
        $rfcHit = null;
        if ($ctx->rfcRule !== null) {
            $pos = self::rfcRuleViolation($ctx->rfcRule, $input);
            if ($pos !== null) {
                $rfcHit = [$ctx->rfcRule, $pos];
            }
        }

        // Probe 5: trailingWhitespace.
        $trailingCount = self::countTrailingWhitespace($input);

        // Probe 6: normalizationDrift.
        $nfc = Ucd::toNfc($input);
        $nonNfcPos = $input === $nfc ? null : self::firstArrayDivergence($input, $nfc);

        $classification = self::classify(
            $encodingHit,
            $webhookHit,
            $auditHit,
            $rfcHit,
            $trailingCount,
            count($input),
            $nonNfcPos,
        );

        return new HashInputVerdict(array_values($input), $classification, $stable, count($stable));
    }

    /**
     * The priority resolver: first hit wins, in the spec's fixed order.
     *
     * @param array{0:string,1:string,2:int}|null $encodingHit
     * @param array{0:RfcRule,1:int}|null $rfcHit
     */
    private static function classify(
        ?array $encodingHit,
        ?int $webhookHit,
        ?int $auditHit,
        ?array $rfcHit,
        int $trailingCount,
        int $inputLen,
        ?int $nonNfcPos,
    ): Classification {
        if ($encodingHit !== null) {
            [$declared, $detected, $pos] = $encodingHit;
            return Classification::hazard(SubThreat::encodingMismatch($declared, $detected), [$pos]);
        }
        if ($webhookHit !== null) {
            return Classification::hazard(SubThreat::webhookSignatureDrift($webhookHit), [$webhookHit]);
        }
        if ($auditHit !== null) {
            return Classification::hazard(SubThreat::auditLogReinterpretation($auditHit), [$auditHit]);
        }
        if ($rfcHit !== null) {
            [$rule, $pos] = $rfcHit;
            return Classification::hazard(SubThreat::signedMessageRule($rule->tag(), $pos), [$pos]);
        }
        if ($trailingCount > 0) {
            $p = $inputLen - $trailingCount;
            return Classification::hazard(SubThreat::trailingWhitespace($trailingCount), [$p]);
        }
        if ($nonNfcPos !== null) {
            return Classification::hazard(SubThreat::normalizationDrift($nonNfcPos), [$nonNfcPos]);
        }
        return Classification::clear();
    }

    /**
     * Convenience wrapper over `detectWithContext` with the empty context —
     * equivalent to running only the two bare-input probes (trailingWhitespace,
     * normalizationDrift).
     *
     * @param list<int> $input
     */
    public static function detect(array $input): HashInputVerdict
    {
        return self::detectWithContext(new Context(), $input);
    }
}
