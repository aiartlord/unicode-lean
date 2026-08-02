import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  MAX_RGI_LENGTH,
  EMOJI_ZWJ,
  emojiZwjIntegrityDetect,
  emojiZwjIntegrityReasonCode,
  emojiZwjSubThreatTag,
  isRegisteredZwjSequence,
  isEmojiTarget,
  isEmojiModifier,
} from "../src/security-core.js";

const detect = (input) => emojiZwjIntegrityDetect(input);
const tag = (input) => detect(input).classify.tag;

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("emoji-zwj-integrity shared detector fixture", () => {
  const fixture = loadFixture("detectors/emoji_zwj_integrity.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "emoji-zwj-integrity");

  for (const entry of fixture.cases) {
    const verdict = detect(entry.input);
    const codes =
      verdict.classify.tag === null
        ? []
        : [emojiZwjIntegrityReasonCode(verdict.classify.tag)];
    for (const required of entry.required_findings) {
      assert.ok(codes.includes(required), `${entry.name}: missing ${required}`);
    }
    if (entry.required_findings.length === 0) {
      assert.equal(verdict.classify.isClear, true, `${entry.name}: expected clear`);
    }
  }
});

// ── data-layer sanity ───────────────────────────────────────────────────────

test("is_emoji_modifier checks", () => {
  assert.equal(isEmojiModifier(0x1f3fb), true);
  assert.equal(isEmojiModifier(0x1f3ff), true);
  assert.equal(isEmojiModifier(0x1f3fa), false);
  assert.equal(isEmojiModifier(0x1f600), false);
});

test("zwj alphabet admits heart and man, rejects grinning and the joiner", () => {
  // U+2764 HEAVY BLACK HEART appears in couple-with-heart RGI sequences.
  assert.equal(isEmojiTarget(0x2764), true);
  // U+1F468 MAN appears in family/couple RGI sequences.
  assert.equal(isEmojiTarget(0x1f468), true);
  // U+1F600 GRINNING FACE appears in no registered RGI ZWJ sequence.
  assert.equal(isEmojiTarget(0x1f600), false);
  // The joiner itself is excluded from the alphabet.
  assert.equal(isEmojiTarget(EMOJI_ZWJ), false);
});

test("registered membership is exact", () => {
  // MAN + ZWJ + LAPTOP (man technologist) is a registered RGI sequence.
  assert.equal(isRegisteredZwjSequence([0x1f468, 0x200d, 0x1f4bb]), true);
  // MAN + ZWJ + WOMAN is not a registered RGI sequence.
  assert.equal(isRegisteredZwjSequence([0x1f468, 0x200d, 0x1f469]), false);
});

// ── §5 detect spot checks (one per Rust #[test]) ─────────────────────────────

test("detect_empty_clear", () => {
  const v = detect([]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.classify.tag, null);
  assert.deepEqual(v.zwjPositions, []);
  assert.equal(v.chainLength, 0);
  assert.equal(v.skinToneCount, 0);
});

test("detect_ascii_clear", () => {
  assert.equal(detect([0x48, 0x65, 0x6c, 0x6c, 0x6f]).classify.isClear, true);
});

test("detect_plain_emoji_clear", () => {
  assert.equal(detect([0x1f600]).classify.isClear, true);
});

test("detect_one_skintone_clear", () => {
  const v = detect([0x1f44b, 0x1f3fb]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.skinToneCount, 1);
});

test("detect_family_rgi_clear", () => {
  const v = detect([0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467, 0x200d, 0x1f466]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.isRegisteredRgi, true);
});

test("detect_double_zwj", () => {
  const v = detect([0x1f600, 0x200d, 0x200d, 0x1f600]);
  assert.equal(v.classify.tag, "DoubleZWJ");
  assert.deepEqual(v.classify.positions, [1]);
});

test("detect_non_emoji_injection", () => {
  const v = detect([0x1f600, 0x200d, 0x0061]);
  assert.equal(v.classify.tag, "NonEmojiInjection");
});

test("detect_skin_tone_overflow", () => {
  const v = detect([0x1f44b, 0x1f3fb, 0x1f3fc, 0x1f3fd, 0x1f3fe, 0x1f3ff]);
  assert.equal(v.classify.tag, "SkinToneOverflow");
  assert.equal(v.skinToneCount, 5);
});

test("detect_man_laptop_registered_clear", () => {
  assert.equal(detect([0x1f468, 0x200d, 0x1f4bb]).classify.isClear, true);
});

test("detect_unregistered", () => {
  // man + ZWJ + woman: both flanks are in the RGI alphabet but the joined
  // sequence is not registered.
  const v = detect([0x1f468, 0x200d, 0x1f469]);
  assert.equal(v.classify.tag, "UnregisteredSequence");
});

test("detect_grinning_laptop_non_emoji_injection", () => {
  // grinning face is not a valid ZWJ-join target, so this surfaces as
  // NonEmojiInjection.
  assert.equal(tag([0x1f600, 0x200d, 0x1f4bb]), "NonEmojiInjection");
});

// ── structural checks (follow from the priority ladder) ──────────────────────

test("over_length_fires_past_cap", () => {
  // 9 men joined by 8 ZWJs = 17 codepoints (> MAX_RGI_LENGTH).
  const input = [];
  for (let i = 0; i < 9; i += 1) {
    if (i > 0) {
      input.push(0x200d);
    }
    input.push(0x1f468);
  }
  assert.equal(input.length, 17);
  const v = detect(input);
  assert.equal(v.classify.tag, "OverLength");
  assert.equal(v.classify.sub.kind, "OverLength");
  assert.equal(v.classify.sub.length, 17);
  assert.equal(v.classify.sub.maxLength, MAX_RGI_LENGTH);
  assert.deepEqual(v.classify.positions, []);
});

test("trailing_zwj_is_injection", () => {
  const v = detect([0x1f468, 0x200d]);
  assert.equal(v.classify.tag, "NonEmojiInjection");
  assert.deepEqual(v.classify.positions, [1]);
});

test("double_zwj_beats_unregistered", () => {
  // man ZWJ ZWJ boy — adjacent ZWJs present.
  const v = detect([0x1f468, 0x200d, 0x200d, 0x1f466]);
  assert.equal(v.classify.tag, "DoubleZWJ");
});

// ── reason-code shape ────────────────────────────────────────────────────────

test("sub-threat tag and reason code", () => {
  assert.equal(emojiZwjSubThreatTag({ kind: "DoubleZwj", positions: [1] }), "DoubleZWJ");
  assert.equal(
    emojiZwjIntegrityReasonCode("DoubleZWJ"),
    "unicode.security.I.emoji-zwj-integrity.DoubleZWJ",
  );
});
