import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  CueClass,
  aiWatermarkDetectabilityDetect,
  aiWatermarkDetectabilityDetectWithContext,
  aiWatermarkDetectabilityReasonCode,
  aiWatermarkSubThreatTag,
  aiWatermarkCueClass,
} from "../src/security-core.js";

const detect = (input) => aiWatermarkDetectabilityDetect(input);
const tag = (input) => detect(input).classify.tag;

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("ai-watermark-detectability shared detector fixture", () => {
  const fixture = loadFixture("detectors/ai_watermark_detectability.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "ai-watermark-detectability");

  for (const entry of fixture.cases) {
    const verdict = detect(entry.input);
    const codes =
      verdict.classify.tag === null
        ? []
        : [aiWatermarkDetectabilityReasonCode(verdict.classify.tag)];
    for (const required of entry.required_findings) {
      assert.ok(codes.includes(required), `${entry.name}: missing ${required}`);
    }
    if (entry.required_findings.length === 0) {
      assert.equal(verdict.classify.isClear, true, `${entry.name}: expected clear`);
    }
  }
});

// ── §6 detect spot checks (from the Rust #[test] module) ─────────────────────

test("detect clear vectors", () => {
  assert.equal(detect([]).classify.isClear, true);
  assert.equal(detect([0x61, 0x62, 0x63]).classify.isClear, true);
  assert.equal(detect([0x4e2d, 0x6587]).classify.isClear, true);
});

test("detect nnbsp fires", () => {
  const v = detect([0x61, 0x202f, 0x62]);
  assert.equal(v.classify.tag, "NnbspBoundary");
  assert.deepEqual(v.classify.positions, [1]);
  assert.equal(v.markerCount, 1);
});

test("detect multiple nnbsp aggregates", () => {
  const v = detect([0x61, 0x202f, 0x62, 0x202f, 0x63]);
  assert.equal(v.classify.tag, "NnbspBoundary");
  assert.equal(v.markerCount, 2);
  assert.deepEqual(v.classify.positions, [1, 3]);
});

test("detect vs in plain text fires", () => {
  const v = detect([0x61, 0xfe0f, 0x62]);
  assert.equal(v.classify.tag, "VariationSelectorCarrier");
  assert.equal(v.markerCount, 1);
});

test("detect vs after emoji clear", () => {
  assert.equal(detect([0x1f600, 0xfe0f]).classify.isClear, true);
});

test("detect zwj in plain text fires", () => {
  const v = detect([0x61, 0x200d, 0x62]);
  assert.equal(v.classify.tag, "ZwjNonEmoji");
  assert.equal(v.markerCount, 1);
});

test("detect zwj emoji sequence clear", () => {
  assert.equal(detect([0x1f469, 0x200d, 0x1f52c]).classify.isClear, true);
});

test("detect soft hyphen fires", () => {
  const v = detect([0x61, 0x00ad, 0x62]);
  assert.equal(v.classify.tag, "DefaultIgnorableCarrier");
  assert.equal(v.markerCount, 1);
});

test("detect zwsp fires as default-ignorable", () => {
  const v = detect([0x61, 0x200b, 0x62]);
  assert.equal(v.classify.tag, "DefaultIgnorableCarrier");
  assert.equal(v.markerCount, 1);
});

// ── §7 priority + refinement-probe spot checks ──────────────────────────────

test("detect priority unknown over nnbsp with di", () => {
  assert.equal(tag([0x61, 0x202f, 0x00ad, 0x62]), "Unknown");
});

test("detect priority unknown over vs with zwj", () => {
  assert.equal(tag([0x61, 0xfe0f, 0x200d, 0x62]), "Unknown");
});

test("detect adversarial arithmetic nnbsp", () => {
  const v = detect([0x61, 0x202f, 0x62, 0x202f, 0x63, 0x202f, 0x64]);
  assert.equal(v.classify.tag, "Adversarial");
  assert.equal(v.markerCount, 3);
  assert.equal(v.classify.sub.impersonatedScheme, "nnbspBoundary");
});

test("detect nnbsp two below adversarial threshold", () => {
  assert.equal(tag([0x61, 0x202f, 0x62, 0x202f, 0x63]), "NnbspBoundary");
});

test("detect gpt5 zwsp modulo", () => {
  const v = detect([0x61, 0x200b, 0x62, 0x200b, 0x63, 0x200b, 0x64]);
  assert.equal(v.classify.tag, "Gpt5ZwspModulo");
  assert.equal(v.markerCount, 3);
});

test("detect zwsp two below modulo threshold", () => {
  assert.equal(tag([0x61, 0x200b, 0x62, 0x200b, 0x63]), "DefaultIgnorableCarrier");
});

test("detect smart quote alternation", () => {
  const v = detect([0x201c, 0x61, 0x62, 0x63, 0x201d]);
  assert.equal(v.classify.tag, "SmartQuoteAlternation");
  assert.equal(v.markerCount, 2);
});

test("detect smart quote with straight clear", () => {
  assert.equal(detect([0x201c, 0x61, 0x22, 0x201d]).classify.isClear, true);
});

test("detect em dash pattern", () => {
  const v = detect([0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66]);
  assert.equal(v.classify.tag, "EmDashPattern");
  assert.equal(v.markerCount, 2);
});

test("detect em dash with hyphen clear", () => {
  assert.equal(
    detect([0x61, 0x62, 0x2d, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66]).classify.isClear,
    true,
  );
});

test("detect statistical token delve", () => {
  const v = detect([0x64, 0x65, 0x6c, 0x76, 0x65]);
  assert.equal(v.classify.tag, "StatisticalTokenChoice");
  assert.equal(v.markerCount, 1);
});

test("detect statistical token moreover embedded", () => {
  const v = detect([0x3b, 0x20, 0x6d, 0x6f, 0x72, 0x65, 0x6f, 0x76, 0x65, 0x72, 0x2c, 0x20]);
  assert.equal(v.classify.tag, "StatisticalTokenChoice");
  assert.deepEqual(v.classify.positions, [2]);
});

test("detect unknown nnbsp plus di", () => {
  const v = detect([0x61, 0x202f, 0x00ad, 0x62]);
  assert.equal(v.classify.tag, "Unknown");
  assert.equal(v.markerCount, 2);
});

test("detect unknown vs plus zwj", () => {
  const v = detect([0x61, 0xfe0f, 0x200d, 0x62]);
  assert.equal(v.classify.tag, "Unknown");
  assert.equal(v.markerCount, 2);
});

test("detect unknown nnbsp plus zwj", () => {
  const v = detect([0x61, 0x202f, 0x200d, 0x62]);
  assert.equal(v.classify.tag, "Unknown");
  assert.equal(v.markerCount, 2);
});

test("detect single category skips unknown", () => {
  assert.equal(tag([0x61, 0x202f, 0x62]), "NnbspBoundary");
});

test("detect priority adversarial over nnbsp", () => {
  assert.equal(tag([0x61, 0x202f, 0x62, 0x202f, 0x63, 0x202f, 0x64]), "Adversarial");
});

test("detect priority zwsp modulo over di", () => {
  assert.equal(tag([0x61, 0x200b, 0x62, 0x200b, 0x63, 0x200b, 0x64]), "Gpt5ZwspModulo");
});

// ── §8 tolerance-parameterised probes (the two Rust Context vectors) ─────────

test("detect zwsp jittered strict clear (tolerance 0)", () => {
  // ZWSPs at 1, 3, 6 (gaps 2, 3). Bare detect (tolerance 0) does not fire
  // gpt5ZwspModulo; falls through to defaultIgnorableCarrier.
  const input = [0x61, 0x200b, 0x62, 0x200b, 0x63, 0x64, 0x200b, 0x65];
  assert.equal(tag(input), "DefaultIgnorableCarrier");
});

test("detect zwsp jittered tolerant fires (tolerance 1)", () => {
  const input = [0x61, 0x200b, 0x62, 0x200b, 0x63, 0x64, 0x200b, 0x65];
  const v = aiWatermarkDetectabilityDetectWithContext({ zwspModuloTolerance: 1 }, input);
  assert.equal(v.classify.tag, "Gpt5ZwspModulo");
});

test("detect_with_context default matches detect", () => {
  const d = detect([0x61, 0x202f, 0x62]);
  const c = aiWatermarkDetectabilityDetectWithContext({}, [0x61, 0x202f, 0x62]);
  assert.deepEqual(c.classify, d.classify);
});

// ── §7 cue-class coverage ───────────────────────────────────────────────────

test("every cue class is probed by some sub-threat", () => {
  const classes = [CueClass.GreenListBias, CueClass.PseudorandomSeq, CueClass.SemanticDrift];
  const subThreats = [
    { kind: "NnbspBoundary", markerCount: 0 },
    { kind: "VariationSelectorCarrier", markerCount: 0 },
    { kind: "ZwjNonEmoji", markerCount: 0 },
    { kind: "DefaultIgnorableCarrier", markerCount: 0 },
    { kind: "Gpt5ZwspModulo", firstPos: 0 },
    { kind: "EmDashPattern", firstPos: 0 },
    { kind: "SmartQuoteAlternation", firstPos: 0 },
    { kind: "StatisticalTokenChoice", firstPos: 0 },
    { kind: "Adversarial", impersonatedScheme: "", firstPos: 0 },
  ];
  for (const cls of classes) {
    assert.ok(
      subThreats.some((st) => aiWatermarkCueClass(st) === cls),
      `cue class ${cls} is not probed by any sub-threat`,
    );
  }
});

test("unknown has no cue class", () => {
  assert.equal(aiWatermarkCueClass({ kind: "Unknown", anomalyMarker: 0 }), null);
});

test("sub-threat tag mirrors kind", () => {
  assert.equal(aiWatermarkSubThreatTag({ kind: "NnbspBoundary", markerCount: 3 }), "NnbspBoundary");
  assert.equal(
    aiWatermarkDetectabilityReasonCode("NnbspBoundary"),
    "unicode.security.K.ai-watermark-detectability.NnbspBoundary",
  );
});
