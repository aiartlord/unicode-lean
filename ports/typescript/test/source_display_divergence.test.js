import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  sourceDisplayDivergenceDetect,
  sourceDisplayDivergenceReasonCode,
  sourceDisplayDivergenceSubThreatTag,
} from "../src/security-core.js";

const detect = (input) => sourceDisplayDivergenceDetect(input);
const tag = (input) => detect(input).classify.tag;

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("source-display-divergence shared detector fixture", () => {
  const fixture = loadFixture("detectors/source_display_divergence.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "source-display-divergence");

  for (const entry of fixture.cases) {
    const verdict = detect(entry.input);
    const codes =
      verdict.classify.tag === null
        ? []
        : [sourceDisplayDivergenceReasonCode(verdict.classify.tag)];
    for (const required of entry.required_findings) {
      assert.ok(codes.includes(required), `${entry.name}: missing ${required}`);
    }
    if (entry.required_findings.length === 0) {
      assert.equal(verdict.classify.isClear, true, `${entry.name}: expected clear`);
    }
  }
});

// ── (b) detect spot checks (mirror the Rust #[test] cases) ───────────────────

test("clear_cases", () => {
  assert.equal(detect([]).classify.isClear, true);
  // "Hello world"
  assert.equal(
    detect([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64]).classify.isClear,
    true,
  );
  // "let x = 1;"
  assert.equal(
    detect([0x6c, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3d, 0x20, 0x31, 0x3b]).classify.isClear,
    true,
  );
});

test("single_fire_passthrough", () => {
  // tag-encoded "AB"
  assert.equal(tag([0xe0041, 0xe0042]), "TagBlock");
  // A + VS16
  assert.equal(tag([0x0041, 0xfe0f]), "VariationSelector");
  // H + ZWSP + i
  assert.equal(tag([0x0048, 0x200b, 0x69]), "ZeroWidth");
  // RLO + A
  assert.equal(tag([0x202e, 0x41]), "BidiControl");
  // "Neth<Cyrillic е>um"
  assert.equal(
    tag([0x4e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6d]),
    "IdentifierHomoglyph",
  );
});

test("two_or_more_is_compound", () => {
  // A + VS16 + ZWSP
  assert.equal(tag([0x0041, 0xfe0f, 0x200b]), "Compound");
  // tag "AB" + ZWSP
  assert.equal(tag([0xe0041, 0xe0042, 0x200b]), "Compound");
});

// ── (c) fired-list ordering + reason-code shape ──────────────────────────────

test("fired list preserves canonical aggregation order", () => {
  // tag "AB" + ZWSP fires TagBlock then ZeroWidth, in that order.
  assert.deepEqual(detect([0xe0041, 0xe0042, 0x200b]).fired, ["TagBlock", "ZeroWidth"]);
});

test("sub-threat tag and reason code", () => {
  assert.equal(sourceDisplayDivergenceSubThreatTag({ kind: "Compound" }), "Compound");
  assert.equal(sourceDisplayDivergenceSubThreatTag({ kind: "TagBlock" }), "TagBlock");
  assert.equal(
    sourceDisplayDivergenceReasonCode("Compound"),
    "unicode.security.D.source-display-divergence.Compound",
  );
});

test("unrecognised sub-threat kind throws", () => {
  assert.throws(() => sourceDisplayDivergenceSubThreatTag({ kind: "Nonexistent" }));
});
