import assert from "node:assert/strict";
import test from "node:test";

import { isUtf8Blob, Utf8Blob, ValidatedUtf8 } from "../src/security.js";

// Byte sequences exercising the strict RFC 3629 validator the refinements
// layer over. The refinements reuse the port's own firstInvalidUtf8 state
// machine, so overlong and surrogate encodings that the host TextDecoder might
// tolerate under different flags are rejected here structurally.
const ASCII = [0x41, 0x42, 0x43]; // "ABC"
const TWO_BYTE = [0xc3, 0xa9]; // U+00E9 é
const FOUR_BYTE = [0xf0, 0x9f, 0x98, 0x80]; // U+1F600 😀
const OVERLONG_NUL = [0xc0, 0x80]; // overlong encoding of U+0000
const SURROGATE = [0xed, 0xa0, 0x80]; // U+D800, an unpaired surrogate
const TRUNCATED = [0xf0, 0x9f, 0x98]; // 4-byte lead, one continuation missing

test("isUtf8Blob accepts ascii, 2-byte, 4-byte, empty", () => {
  assert.equal(isUtf8Blob(ASCII), true);
  assert.equal(isUtf8Blob(TWO_BYTE), true);
  assert.equal(isUtf8Blob(FOUR_BYTE), true);
  assert.equal(isUtf8Blob([]), true);
  assert.equal(isUtf8Blob(Uint8Array.from(FOUR_BYTE)), true);
});

test("isUtf8Blob rejects overlong and surrogate encodings", () => {
  assert.equal(isUtf8Blob(OVERLONG_NUL), false);
  assert.equal(isUtf8Blob(SURROGATE), false);
  assert.equal(isUtf8Blob(TRUNCATED), false);
});

test("Utf8Blob.of accepts valid bytes within the bound", () => {
  const blob = Utf8Blob.of(FOUR_BYTE, 4);
  assert.notEqual(blob, null);
  assert.deepEqual(blob.value, FOUR_BYTE);
  assert.deepEqual(blob.bytes(), FOUR_BYTE);
  assert.equal(blob.maxBytes, 4);
});

test("Utf8Blob.of accepts empty under any bound", () => {
  assert.notEqual(Utf8Blob.of([], 0), null);
  assert.notEqual(Utf8Blob.of([], 16), null);
  assert.deepEqual(Utf8Blob.of([], 0).value, []);
});

test("Utf8Blob.of rejects over-bound input", () => {
  assert.equal(Utf8Blob.of(FOUR_BYTE, 3), null);
  assert.equal(Utf8Blob.of(ASCII, 2), null);
});

test("Utf8Blob.of rejects invalid utf-8 even within the bound", () => {
  assert.equal(Utf8Blob.of(OVERLONG_NUL, 8), null);
  assert.equal(Utf8Blob.of(SURROGATE, 8), null);
});

test("Utf8Blob accepts Uint8Array input", () => {
  const blob = Utf8Blob.of(Uint8Array.from(TWO_BYTE), 4);
  assert.notEqual(blob, null);
  assert.deepEqual(blob.value, TWO_BYTE);
});

test("Utf8Blob direct construction is guarded and instances are frozen", () => {
  assert.throws(() => new Utf8Blob(null, [], 0), TypeError);
  const blob = Utf8Blob.of(ASCII, 8);
  assert.equal(Object.isFrozen(blob), true);
  assert.equal(Object.isFrozen(blob.value), true);
});

test("ValidatedUtf8.validate roundtrips valid bytes via asBytes and unwrap", () => {
  const validated = ValidatedUtf8.validate(TWO_BYTE);
  assert.notEqual(validated, null);
  assert.deepEqual(validated.asBytes(), TWO_BYTE);
  assert.deepEqual(validated.unwrap(), TWO_BYTE);
  assert.deepEqual(ValidatedUtf8.validate(ASCII).unwrap(), ASCII);
  assert.deepEqual(ValidatedUtf8.validate(FOUR_BYTE).unwrap(), FOUR_BYTE);
  assert.deepEqual(ValidatedUtf8.validate([]).unwrap(), []);
});

test("ValidatedUtf8.validate rejects malformed bytes", () => {
  assert.equal(ValidatedUtf8.validate(OVERLONG_NUL), null);
  assert.equal(ValidatedUtf8.validate(SURROGATE), null);
  assert.equal(ValidatedUtf8.validate(TRUNCATED), null);
});

test("ValidatedUtf8 accepts Uint8Array and is guarded and frozen", () => {
  const validated = ValidatedUtf8.validate(Uint8Array.from(FOUR_BYTE));
  assert.notEqual(validated, null);
  assert.deepEqual(validated.asBytes(), FOUR_BYTE);
  assert.throws(() => new ValidatedUtf8(null, []), TypeError);
  assert.equal(Object.isFrozen(validated), true);
});
