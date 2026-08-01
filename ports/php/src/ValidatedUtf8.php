<?php

declare(strict_types=1);

namespace UnicodePhp;

/**
 * Refinement type for bytes validated as strict RFC 3629 UTF-8.
 *
 * The validity claim is pinned at the module boundary: the only way to build a
 * ValidatedUtf8 is via the smart constructor {@see ValidatedUtf8::validate()},
 * which routes through the strict decoder state machine. A downstream consumer
 * that wants the raw bytes has to explicitly {@see ValidatedUtf8::unwrap()},
 * which reads as "I am consuming the RFC 3629 claim here". Byte sequences are
 * lists of integers in this port.
 */
final class ValidatedUtf8
{
    /** @param list<int> $bytes */
    private function __construct(
        private readonly array $bytes,
    ) {
    }

    /**
     * Validate $data and, on success, return a ValidatedUtf8 carrying the
     * RFC 3629 validity claim. Returns null when the bytes fail the strict
     * state machine.
     *
     * @param list<int> $data
     */
    public static function validate(array $data): ?self
    {
        if (!Utf8::isValid($data)) {
            return null;
        }

        return new self($data);
    }

    /**
     * Borrow the validated bytes.
     *
     * @return list<int>
     */
    public function asBytes(): array
    {
        return $this->bytes;
    }

    /**
     * Consume the validity claim, returning the underlying bytes. After this
     * call the validity claim is no longer carried at the module boundary.
     *
     * @return list<int>
     */
    public static function unwrap(self $validated): array
    {
        return $validated->bytes;
    }
}
