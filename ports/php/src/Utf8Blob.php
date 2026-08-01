<?php

declare(strict_types=1);

namespace UnicodePhp;

/**
 * Opaque text predicate — structurally valid UTF-8, size-bounded.
 *
 * No character-class or codepoint filtering beyond UTF-8 validity. Intended
 * for callers who apply their own text hardening downstream; hardened
 * identifier and printable profiles layer on top of this predicate. Byte
 * sequences are lists of integers in this port.
 */
final class Utf8Blob
{
    /** @param list<int> $value */
    private function __construct(
        public readonly array $value,
        public readonly int $maxBytes,
    ) {
    }

    /**
     * Opaque-blob predicate: structurally valid UTF-8. Named so the "blob"
     * framing — no character-class hardening — is explicit at the call site.
     *
     * @param list<int> $data
     */
    public static function isUtf8Blob(array $data): bool
    {
        return Utf8::isValid($data);
    }

    /**
     * Build a Utf8Blob under the size bound $maxBytes. Returns null when
     * either the bound or UTF-8 validity is violated.
     *
     * @param list<int> $data
     */
    public static function of(array $data, int $maxBytes): ?self
    {
        if (count($data) > $maxBytes) {
            return null;
        }
        if (!self::isUtf8Blob($data)) {
            return null;
        }

        return new self($data, $maxBytes);
    }
}
