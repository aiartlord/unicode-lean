import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  skinToneVariationForgeryDetect,
  skinToneVariationForgeryReasonCode,
  skinToneVariationForgerySubThreatTag,
} from "../src/security-core.js";

const detect = (input) => skinToneVariationForgeryDetect(input);
const tag = (input) => detect(input).classify.tag;

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("skin-tone-variation-forgery shared detector fixture", () => {
  const fixture = loadFixture("detectors/skin_tone_variation_forgery.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "skin-tone-variation-forgery");

  for (const entry of fixture.cases) {
    const verdict = detect(entry.input);
    const codes =
      verdict.classify.tag === null
        ? []
        : [skinToneVariationForgeryReasonCode(verdict.classify.tag)];
    for (const required of entry.required_findings) {
      assert.ok(codes.includes(required), `${entry.name}: missing ${required}`);
    }
    if (entry.required_findings.length === 0) {
      assert.equal(verdict.classify.isClear, true, `${entry.name}: expected clear`);
    }
  }
});

// ── (b) detect spot checks (one per Rust #[test]) ────────────────────────────

test("detect_empty_clear", () => {
  assert.equal(detect([]).classify.isClear, true);
});

test("detect_ascii_clear", () => {
  // "He" — plain ASCII, no skin tones or variation selectors.
  assert.equal(detect([0x48, 0x65]).classify.isClear, true);
});

test("detect_plain_emoji_clear", () => {
  // U+1F600 grinning face, alone.
  assert.equal(detect([0x1f600]).classify.isClear, true);
});

test("detect_wave_skin_tone_clear", () => {
  // U+1F44B waving hand (a modifier base) + one skin tone.
  const v = detect([0x1f44b, 0x1f3fb]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.skinToneCount, 1);
});

test("detect_stacked_skin_tones", () => {
  // Waving hand + two skin tones.
  const v = detect([0x1f44b, 0x1f3fb, 0x1f3fc]);
  assert.equal(v.classify.tag, "StackedSkinTones");
  assert.deepEqual(v.classify.positions, [1, 2]);
});

test("detect_invalid_target_ascii", () => {
  // Skin tone on ASCII 'A'.
  const v = detect([0x0041, 0x1f3fb]);
  assert.equal(v.classify.tag, "InvalidSkinToneTarget");
  assert.deepEqual(v.classify.positions, [1]);
});

test("detect_invalid_target_smiley", () => {
  // Skin tone on grinning face (not a modifier base).
  assert.equal(tag([0x1f600, 0x1f3fb]), "InvalidSkinToneTarget");
});

test("detect_forced_text_style", () => {
  // VS15 on grinning face (Emoji_Presentation).
  const v = detect([0x1f600, 0xfe0e]);
  assert.equal(v.classify.tag, "ForcedTextStyle");
  assert.equal(v.variationSelector15Count, 1);
});

// ── (c) reason-code / sub-threat-tag shape ──────────────────────────────────

test("reason_code_is_stable", () => {
  assert.equal(
    skinToneVariationForgeryReasonCode("StackedSkinTones"),
    "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones",
  );
  assert.equal(
    skinToneVariationForgeryReasonCode("ForcedTextStyle"),
    "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle",
  );
});

test("sub-threat tag", () => {
  assert.equal(
    skinToneVariationForgerySubThreatTag({
      kind: "InvalidSkinToneTarget",
      basePos: 0,
      baseCp: 0x0041,
      modifierCp: 0x1f3fb,
    }),
    "InvalidSkinToneTarget",
  );
});
