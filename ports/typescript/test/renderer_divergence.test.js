import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  MIN_COMBINING_STACK,
  rendererDivergenceDetect,
  rendererDivergenceReasonCode,
  rendererDivergenceSubThreatTag,
} from "../src/security-core.js";

const detect = (input) => rendererDivergenceDetect(input);
const tag = (input) => detect(input).classify.tag;

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("renderer-divergence shared detector fixture", () => {
  const fixture = loadFixture("detectors/renderer_divergence.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "renderer-divergence");

  for (const entry of fixture.cases) {
    const verdict = detect(entry.input);
    const codes =
      verdict.classify.tag === null
        ? []
        : [rendererDivergenceReasonCode(verdict.classify.tag)];
    for (const required of entry.required_findings) {
      assert.ok(codes.includes(required), `${entry.name}: missing ${required}`);
    }
    if (entry.required_findings.length === 0) {
      assert.equal(verdict.classify.isClear, true, `${entry.name}: expected clear`);
    }
  }
});

// ── §5 detect spot checks (one per Rust #[test]) ─────────────────────────────

test("detect_empty_clear", () => {
  assert.equal(detect([]).classify.isClear, true);
});

test("detect_ascii_clear", () => {
  assert.equal(detect([0x48, 0x65, 0x6c, 0x6c, 0x6f]).classify.isClear, true);
});

test("detect_han_clear", () => {
  assert.equal(detect([0x4e2d, 0x6587]).classify.isClear, true);
});

test("detect_vs_variance", () => {
  // A single VS (FE0F) after an emoji.
  assert.equal(tag([0x1f600, 0xfe0f]), "VariationSelectorVariance");
});

test("detect_rgi_family_clear", () => {
  // A registered RGI family ZWJ sequence.
  const v = detect([0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467, 0x200d, 0x1f466]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.hasZwj, true);
});

test("detect_unregistered_zwj_variance", () => {
  // man + ZWJ + woman, not in RGI.
  assert.equal(tag([0x1f468, 0x200d, 0x1f469]), "UnregisteredZwjVariance");
});

test("detect_zalgo_variance", () => {
  // A 4-deep combining stack.
  const v = detect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304]);
  assert.equal(v.classify.tag, "CombiningStackOverflow");
  assert.deepEqual(v.classify.positions, [0]);
  assert.equal(v.combiningCount, 4);
});

test("detect_fullwidth_variance", () => {
  // Fullwidth 'A'.
  assert.equal(tag([0xff21]), "FullwidthVariance");
});

test("detect_mixed_direction", () => {
  // Latin + Hebrew in one input.
  const v = detect([0x41, 0x42, 0x05d0, 0x05d1]);
  assert.equal(v.classify.tag, "MixedDirectionVariance");
  assert.ok(v.strongLtrCount > 0 && v.strongRtlCount > 0);
});

// ── priority-ladder structural checks ────────────────────────────────────────

test("combining_stack_beats_vs", () => {
  // A combining stack outranks a variation selector present later.
  const v = detect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xfe0f]);
  assert.equal(v.classify.tag, "CombiningStackOverflow");
});

test("three_marks_below_threshold", () => {
  // Exactly three combining marks is below the stack threshold — no overflow.
  const v = detect([0x0061, 0x0301, 0x0302, 0x0303]);
  assert.notEqual(v.classify.tag, "CombiningStackOverflow");
});

// ── reason-code shape ────────────────────────────────────────────────────────

test("sub-threat tag and reason code", () => {
  assert.equal(
    rendererDivergenceSubThreatTag({ kind: "MixedDirectionVariance", ltrCount: 1, rtlCount: 1 }),
    "MixedDirectionVariance",
  );
  assert.equal(
    rendererDivergenceReasonCode("CombiningStackOverflow"),
    "unicode.security.D.renderer-divergence.CombiningStackOverflow",
  );
  assert.equal(MIN_COMBINING_STACK, 4);
});
