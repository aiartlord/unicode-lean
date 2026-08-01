<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Utf8Blob;
use UnicodePhp\ValidatedUtf8;

// Utf8Blob / ValidatedUtf8 refinement-type tests. Byte sequences are lists of
// integers in this port.

assert_same_value(true, Utf8Blob::isUtf8Blob([0x48, 0x69]), 'blob-ascii');
assert_same_value(true, Utf8Blob::isUtf8Blob([0xC3, 0xA9]), 'blob-2byte');
assert_same_value(true, Utf8Blob::isUtf8Blob([0xF0, 0x9F, 0x98, 0x80]), 'blob-4byte');
assert_same_value(false, Utf8Blob::isUtf8Blob([0xC0, 0x80]), 'blob-overlong');
assert_same_value(false, Utf8Blob::isUtf8Blob([0xED, 0xA0, 0x80]), 'blob-surrogate');

$blob = Utf8Blob::of([0x48, 0x69], 16);
if ($blob === null) {
    throw new RuntimeException('blob-of-within-bound returned null');
}
assert_same_value([0x48, 0x69], $blob->value, 'blob-value');
assert_same_value(16, $blob->maxBytes, 'blob-max');
assert_same_value(null, Utf8Blob::of([0x48, 0x69, 0x21], 2), 'blob-over-bound');
assert_same_value(null, Utf8Blob::of([0xC0, 0x80], 16), 'blob-malformed');
if (Utf8Blob::of([], 32) === null) {
    throw new RuntimeException('blob-empty-any-bound returned null');
}

$validated = ValidatedUtf8::validate([0xC3, 0xA9]);
if ($validated === null) {
    throw new RuntimeException('validated-utf8 rejected valid input');
}
assert_same_value([0xC3, 0xA9], $validated->asBytes(), 'validated-as-bytes');
assert_same_value([0xC3, 0xA9], ValidatedUtf8::unwrap($validated), 'validated-unwrap');
assert_same_value(null, ValidatedUtf8::validate([0xED, 0xA0, 0x80]), 'validated-rejects-malformed');
