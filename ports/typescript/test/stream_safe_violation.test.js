import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  STREAM_SAFE_LIMIT,
  streamSafeViolationDetect,
  streamSafeViolationReasonCode,
} from "../src/security-core.js";

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// U+0301 COMBINING ACUTE ACCENT has CCC = 230 (a non-starter); the ASCII
// letters below have CCC = 0 (starters).
const ACUTE = 0x0301;

// "a" followed by n combining acute accents.
function aPlusMarks(n) {
  const out = [0x61];
  for (let i = 0; i < n; i += 1) {
    out.push(ACUTE);
  }
  return out;
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("stream-safe-violation shared detector fixture", () => {
  const fixture = loadFixture("detectors/stream_safe_violation.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "stream-safe-violation");

  for (const entry of fixture.cases) {
    const verdict = streamSafeViolationDetect(entry.input);
    const codes =
      verdict.classify.tag === null ? [] : [streamSafeViolationReasonCode(verdict.classify.tag)];
    for (const required of entry.required_findings) {
      assert.ok(codes.includes(required), `${entry.name}: missing ${required}`);
    }
    if (entry.required_findings.length === 0) {
      assert.equal(verdict.classify.isClear, true, `${entry.name}: expected clear`);
    }
  }
});

// ── (b) the 30/31 boundary (from the Rust #[test] module) ────────────────────

test("STREAM_SAFE_LIMIT is 30", () => {
  assert.equal(STREAM_SAFE_LIMIT, 30);
});

test("empty input is clear", () => {
  const v = streamSafeViolationDetect([]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.classify.tag, null);
  assert.equal(v.maxRunLen, 0);
  assert.equal(v.overrunCount, 0);
  assert.equal(v.totalNonStarters, 0);
});

test("pure-ASCII input is clear", () => {
  const v = streamSafeViolationDetect([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.maxRunLen, 0);
  assert.equal(v.totalNonStarters, 0);
});

test("a single combining mark is clear", () => {
  const v = streamSafeViolationDetect([0x61, ACUTE]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.maxRunLen, 1);
  assert.equal(v.overrunCount, 0);
  assert.equal(v.totalNonStarters, 1);
});

test("exactly 30 marks is the boundary — stays clear under strict >", () => {
  const v = streamSafeViolationDetect(aPlusMarks(30));
  assert.equal(v.classify.isClear, true);
  assert.equal(v.classify.tag, null);
  assert.equal(v.maxRunLen, 30);
  assert.equal(v.overrunCount, 0);
  assert.equal(v.totalNonStarters, 30);
});

test("31 marks fires StreamSafeOverrun at base position 1", () => {
  const v = streamSafeViolationDetect(aPlusMarks(31));
  assert.equal(v.classify.isClear, false);
  assert.equal(v.classify.tag, "StreamSafeOverrun");
  assert.deepEqual(v.classify.positions, [1]);
  assert.deepEqual(v.classify.sub, { kind: "StreamSafeOverrun", basePos: 1, runLen: 31 });
  assert.equal(
    streamSafeViolationReasonCode(v.classify.tag),
    "unicode.security.F.stream-safe-violation.StreamSafeOverrun",
  );
  assert.equal(v.maxRunLen, 31);
  assert.equal(v.overrunCount, 1);
  assert.equal(v.totalNonStarters, 31);
});

// ── (c) run-inventory structure checks (from the Rust #[test] module) ─────────

test("a bare non-starter run records its start as 0", () => {
  const input = [];
  for (let i = 0; i < 31; i += 1) {
    input.push(ACUTE);
  }
  const v = streamSafeViolationDetect(input);
  assert.equal(v.classify.tag, "StreamSafeOverrun");
  assert.deepEqual(v.classify.positions, [0]);
  assert.equal(v.maxRunLen, 31);
  assert.equal(v.totalNonStarters, 31);
});

test("two short runs stay clear but both count toward the totals", () => {
  const input = aPlusMarks(30);
  input.push(0x62);
  for (let i = 0; i < 30; i += 1) {
    input.push(ACUTE);
  }
  const v = streamSafeViolationDetect(input);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.maxRunLen, 30);
  assert.equal(v.overrunCount, 0);
  assert.equal(v.totalNonStarters, 60);
});

test("the first overrun wins and reports the long run's start", () => {
  const input = aPlusMarks(5);
  input.push(0x62);
  for (let i = 0; i < 31; i += 1) {
    input.push(ACUTE);
  }
  const v = streamSafeViolationDetect(input);
  assert.equal(v.classify.tag, "StreamSafeOverrun");
  assert.deepEqual(v.classify.positions, [7]);
  assert.equal(v.maxRunLen, 31);
  assert.equal(v.overrunCount, 1);
  assert.equal(v.totalNonStarters, 36);
});
