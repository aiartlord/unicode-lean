import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  identifierFormDriftDetect,
  identifierFormDriftReasonCode,
  identifierFormDriftSubThreatTag,
} from "../src/security-core.js";

const detect = (input) => identifierFormDriftDetect(input);
const tag = (input) => detect(input).classify.tag;

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("identifier-form-drift shared detector fixture", () => {
  const fixture = loadFixture("detectors/identifier_form_drift.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "identifier-form-drift");

  for (const entry of fixture.cases) {
    const verdict = detect(entry.input);
    const codes =
      verdict.classify.tag === null
        ? []
        : [identifierFormDriftReasonCode(verdict.classify.tag)];
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
  // "Hello" — every ASCII letter is Allowed, identity NFKD.
  const v = detect([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.shiftCount, 0);
});

test("detect_greek_alpha_clear", () => {
  // α is Allowed with identity NFKD.
  assert.equal(detect([0x03b1]).classify.isClear, true);
});

test("detect_math_italic_a_shift", () => {
  // U+1D44E Restricted, NFKD head U+0061 Allowed.
  const v = detect([0x1d44e]);
  assert.equal(v.classify.tag, "IdentifierStatusShift");
  assert.deepEqual(v.classify.positions, [0]);
  assert.equal(v.shiftCount, 1);
});

test("detect_fullwidth_A_shift", () => {
  // U+FF21 Restricted, NFKD head U+0041 Allowed.
  assert.equal(tag([0xff21]), "IdentifierStatusShift");
});

test("detect_circled_A_shift", () => {
  // U+24B6 CIRCLED LATIN CAPITAL LETTER A → Restricted → Allowed (A).
  assert.equal(tag([0x24b6]), "IdentifierStatusShift");
});

test("detect_fi_ligature_shift", () => {
  // U+FB01 'ﬁ' ligature → Restricted → Allowed (f).
  assert.equal(tag([0xfb01]), "IdentifierStatusShift");
});

test("detect_roman_iv_shift", () => {
  // U+2163 ROMAN NUMERAL FOUR → Restricted → Allowed (I).
  assert.equal(tag([0x2163]), "IdentifierStatusShift");
});

test("detect_reports_first_shift_position", () => {
  // "ab" + U+1D44E: positions 0,1 are Allowed/identity, position 2 shifts.
  const v = detect([0x61, 0x62, 0x1d44e]);
  assert.deepEqual(v.classify.positions, [2]);
  assert.equal(v.shiftCount, 1);
});

// ── (c) reason-code / sub-threat-tag shape ──────────────────────────────────

test("reason_code_is_stable", () => {
  assert.equal(
    identifierFormDriftReasonCode("IdentifierStatusShift"),
    "unicode.security.X.identifier-form-drift.IdentifierStatusShift",
  );
});

test("sub-threat tag", () => {
  assert.equal(
    identifierFormDriftSubThreatTag({ kind: "IdentifierStatusShift", basePos: 0, cp: 0x1d44e }),
    "IdentifierStatusShift",
  );
});
