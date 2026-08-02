import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  admissibilityFormDriftDetect,
  admissibilityFormDriftReasonCode,
  admissibilityFormDriftSubThreatTag,
} from "../src/security-core.js";

const detect = (input) => admissibilityFormDriftDetect(input);
const tag = (input) => detect(input).classify.tag;

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("admissibility-form-drift shared detector fixture", () => {
  const fixture = loadFixture("detectors/admissibility_form_drift.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "admissibility-form-drift");

  for (const entry of fixture.cases) {
    const verdict = detect(entry.input);
    const codes =
      verdict.classify.tag === null
        ? []
        : [admissibilityFormDriftReasonCode(verdict.classify.tag)];
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
  // Both admissibility calls return false, so they agree.
  assert.equal(detect([]).classify.isClear, true);
});

test("detect_ascii_clear", () => {
  // "admin" — admissible on both sides (NFKC is identity).
  const v = detect([0x61, 0x64, 0x6d, 0x69, 0x6e]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.inputAdmissible, true);
  assert.equal(v.nfkcAdmissible, true);
});

test("detect_fi_ligature_drift", () => {
  // ﬁ (U+FB01) is Restricted (inadmissible), but NFKC decomposes it to "fi"
  // (admissible). Drift fires.
  const v = detect([0xfb01]);
  assert.equal(v.classify.tag, "AdmissibilityFormDrift");
  assert.equal(v.inputAdmissible, false);
  assert.equal(v.nfkcAdmissible, true);
  assert.deepEqual(v.classify.positions, []);
});

test("detect_jamo_sequence_drift", () => {
  // Decomposed Hangul jamos [U+1112, U+1161, U+11AB] are inadmissible, but NFKC
  // composes them to U+D55C 한 (admissible).
  assert.equal(tag([0x1112, 0x1161, 0x11ab]), "AdmissibilityFormDrift");
});

// ── (c) reason-code / sub-threat-tag shape ──────────────────────────────────

test("reason_code_is_stable", () => {
  assert.equal(
    admissibilityFormDriftReasonCode("AdmissibilityFormDrift"),
    "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift",
  );
});

test("sub-threat tag", () => {
  assert.equal(
    admissibilityFormDriftSubThreatTag({
      kind: "AdmissibilityFormDrift",
      inputAdmissible: false,
      nfkcAdmissible: true,
    }),
    "AdmissibilityFormDrift",
  );
});
