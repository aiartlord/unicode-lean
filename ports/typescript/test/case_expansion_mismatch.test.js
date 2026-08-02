import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  caseExpansionMismatchDetect,
  caseExpansionMismatchReasonCode,
  caseExpansionMismatchSubThreatTag,
} from "../src/security-core.js";

const detect = (input) => caseExpansionMismatchDetect(input);
const tag = (input) => detect(input).classify.tag;

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("case-expansion-mismatch shared detector fixture", () => {
  const fixture = loadFixture("detectors/case_expansion_mismatch.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "case-expansion-mismatch");

  for (const entry of fixture.cases) {
    const verdict = detect(entry.input);
    const codes =
      verdict.classify.tag === null
        ? []
        : [caseExpansionMismatchReasonCode(verdict.classify.tag)];
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
  // "Hello" — every ASCII cp case-maps to a single cp.
  const v = detect([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.maxExpansionLen, 1);
});

test("detect_sharp_s_upper", () => {
  // ß (U+00DF) toUpper → "SS".
  const v = detect([0x00df]);
  assert.equal(v.classify.tag, "UpperExpansion");
  assert.deepEqual(v.classify.positions, [0]);
  assert.equal(v.upperExpansionCount, 1);
  assert.equal(v.maxExpansionLen, 2);
});

test("detect_fi_ligature_upper", () => {
  // ﬁ (U+FB01) toUpper → "FI".
  assert.equal(tag([0xfb01]), "UpperExpansion");
});

test("detect_dotted_I_lower", () => {
  // İ (U+0130) toLower under default → "i + 0307"; no upper expansion, so the
  // detector falls through to the lower scan.
  const v = detect([0x0130]);
  assert.equal(v.classify.tag, "LowerExpansion");
  assert.equal(v.lowerExpansionCount, 1);
});

test("detect_ffi_ligature_len3", () => {
  // ﬃ (U+FB03) toUpper → "FFI" (length 3) — the expansion length is reported.
  const v = detect([0xfb03]);
  assert.equal(v.classify.tag, "UpperExpansion");
  assert.equal(v.maxExpansionLen, 3);
});

test("detect_reports_first_expansion_position", () => {
  // A leading ASCII then ß: the upper expansion is reported at position 1.
  const v = detect([0x61, 0x00df]);
  assert.deepEqual(v.classify.positions, [1]);
});

// ── (c) reason-code / sub-threat-tag shape ──────────────────────────────────

test("reason_code_is_stable", () => {
  assert.equal(
    caseExpansionMismatchReasonCode("UpperExpansion"),
    "unicode.security.F.case-expansion-mismatch.UpperExpansion",
  );
  assert.equal(
    caseExpansionMismatchReasonCode("LowerExpansion"),
    "unicode.security.F.case-expansion-mismatch.LowerExpansion",
  );
});

test("sub-threat tag", () => {
  assert.equal(
    caseExpansionMismatchSubThreatTag({
      kind: "UpperExpansion",
      basePos: 0,
      cp: 0x00df,
      expansionLen: 2,
    }),
    "UpperExpansion",
  );
  assert.equal(
    caseExpansionMismatchSubThreatTag({
      kind: "LowerExpansion",
      basePos: 0,
      cp: 0x0130,
      expansionLen: 2,
    }),
    "LowerExpansion",
  );
});
