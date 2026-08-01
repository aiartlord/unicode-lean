<?php

declare(strict_types=1);

namespace UnicodePhp;

/// Strict UTF-8 codec — validator and decoder.
///
/// The accepted byte set is exactly the strict RFC 3629 acceptance language:
/// it rejects overlong encodings, surrogate codepoints (U+D800..U+DFFF),
/// codepoints beyond U+10FFFF, truncated multi-byte sequences, invalid start
/// bytes, and invalid continuation bytes. The accepted byte set is closed-form
/// per the spec.
///
/// Offset convention for `firstInvalidOffset`: the returned offset is the index
/// of the byte on which the state machine transitions to reject. For
/// `OverlongEncoding` (detected on emission of a multi-byte sequence) the offset
/// is the start byte of the sequence, not the last byte consumed.
final class Utf8
{
    /// The first byte offset at which the strict UTF-8 state machine rejects,
    /// or `null` when the entire input is valid UTF-8. Returns a pair
    /// `[offset, Utf8RejectKind]`. `TruncatedSequence` reports an offset equal
    /// to the input length.
    ///
    /// @param list<int> $bytes octet values in 0..255
    /// @return array{0:int,1:Utf8RejectKind}|null
    public static function firstInvalidOffset(array $bytes): ?array
    {
        // State encoding: remaining === 0 means ExpectStart; remaining > 0 is
        // an open multi-byte sequence carrying `accum` and `minCp`.
        $remaining = 0;
        $accum = 0;
        $minCp = 0;
        $seqStart = 0;
        $count = count($bytes);

        for ($i = 0; $i < $count; $i++) {
            $b = $bytes[$i];
            if ($remaining === 0) {
                $seqStart = $i;
                $n = $b;
                if ($n < 0x80) {
                    // 1-byte ASCII, emit directly; stay in ExpectStart.
                    continue;
                }
                if ($n < 0xC2) {
                    return [$i, Utf8RejectKind::InvalidStartByte];
                }
                if ($n < 0xE0) {
                    $remaining = 1;
                    $accum = $n & 0x1F;
                    $minCp = 0x80;
                } elseif ($n < 0xF0) {
                    $remaining = 2;
                    $accum = $n & 0x0F;
                    $minCp = 0x800;
                } elseif ($n < 0xF5) {
                    $remaining = 3;
                    $accum = $n & 0x07;
                    $minCp = 0x10000;
                } else {
                    return [$i, Utf8RejectKind::InvalidStartByte];
                }
                continue;
            }

            // ExpectCont: continuation bytes must lie in 0x80..0xBF.
            $n = $b;
            if ($n < 0x80 || $n >= 0xC0) {
                return [$i, Utf8RejectKind::InvalidContinuationByte];
            }
            $next = ($accum << 6) | ($n & 0x3F);
            if ($remaining === 1) {
                if ($next < $minCp) {
                    return [$seqStart, Utf8RejectKind::OverlongEncoding];
                }
                if ($next >= 0xD800 && $next <= 0xDFFF) {
                    return [$i, Utf8RejectKind::SurrogateCodepoint];
                }
                if ($next > 0x10FFFF) {
                    return [$i, Utf8RejectKind::CodepointBeyondMax];
                }
                $remaining = 0;
            } else {
                $remaining -= 1;
                $accum = $next;
            }
        }

        if ($remaining > 0) {
            return [$count, Utf8RejectKind::TruncatedSequence];
        }
        return null;
    }

    /// Whole-input validity predicate.
    ///
    /// @param list<int> $bytes
    public static function isValid(array $bytes): bool
    {
        return self::firstInvalidOffset($bytes) === null;
    }

    /// Decode a UTF-8 byte string to a codepoint list. Semantically meaningful
    /// only when the input is valid UTF-8; on malformed input the walker yields
    /// the longest valid prefix and stops. Callers that need explicit failure
    /// propagation should validate first via `firstInvalidOffset`.
    ///
    /// @param list<int> $bytes
    /// @return list<int>
    public static function decodeToCodepoints(array $bytes): array
    {
        $out = [];
        $remaining = 0;
        $accum = 0;
        $minCp = 0;

        foreach ($bytes as $b) {
            if ($remaining === 0) {
                $n = $b;
                if ($n < 0x80) {
                    $out[] = $n;
                } elseif ($n < 0xC2) {
                    return $out;
                } elseif ($n < 0xE0) {
                    $remaining = 1;
                    $accum = $n & 0x1F;
                    $minCp = 0x80;
                } elseif ($n < 0xF0) {
                    $remaining = 2;
                    $accum = $n & 0x0F;
                    $minCp = 0x800;
                } elseif ($n < 0xF5) {
                    $remaining = 3;
                    $accum = $n & 0x07;
                    $minCp = 0x10000;
                } else {
                    return $out;
                }
                continue;
            }
            $n = $b;
            if ($n < 0x80 || $n >= 0xC0) {
                return $out;
            }
            $next = ($accum << 6) | ($n & 0x3F);
            if ($remaining === 1) {
                if ($next < $minCp || ($next >= 0xD800 && $next <= 0xDFFF) || $next > 0x10FFFF) {
                    return $out;
                }
                $out[] = $next;
                $remaining = 0;
            } else {
                $remaining -= 1;
                $accum = $next;
            }
        }
        return $out;
    }
}
