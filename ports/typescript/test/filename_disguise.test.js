import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  filenameDisguiseDetect,
  filenameDisguiseReasonCode,
  filenameDisguiseSubThreatTag,
} from "../src/security-core.js";

const detect = (input) => filenameDisguiseDetect(input);
const tag = (input) => detect(input).classify.tag;

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("filename-disguise shared detector fixture", () => {
  const fixture = loadFixture("detectors/filename_disguise.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "filename-disguise");

  for (const entry of fixture.cases) {
    const verdict = detect(entry.input);
    const codes =
      verdict.classify.tag === null
        ? []
        : [filenameDisguiseReasonCode(verdict.classify.tag)];
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

test("detect_plain_txt_clear", () => {
  // "document.txt"
  const v = detect([0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x2e, 0x74, 0x78, 0x74]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.lastDotPos, 8);
});

test("detect_no_extension_clear", () => {
  // "foo"
  const v = detect([0x66, 0x6f, 0x6f]);
  assert.equal(v.classify.isClear, true);
  assert.equal(v.lastDotPos, null);
});

test("detect_tar_gz_clear", () => {
  // "archive.tar.gz" — 2 dots, below the multi-ext bound.
  assert.equal(
    detect([0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2e, 0x74, 0x61, 0x72, 0x2e, 0x67, 0x7a])
      .classify.isClear,
    true,
  );
});

test("detect_hebrew_clear", () => {
  // Native Hebrew name, no bidi controls.
  assert.equal(detect([0x05d0, 0x05d1, 0x05d2, 0x2e, 0x74, 0x78, 0x74]).classify.isClear, true);
});

test("detect_rlo_flip", () => {
  // "document<RLO>txt.exe"
  const v = detect([
    0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x202e, 0x74, 0x78, 0x74, 0x2e, 0x65, 0x78,
    0x65,
  ]);
  assert.equal(v.classify.tag, "RloFlip");
  assert.deepEqual(v.classify.positions, [8]);
});

test("detect_isolate_flip", () => {
  // RLI/PDI isolate variant, also RloFlip.
  assert.equal(
    tag([0x64, 0x6f, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2e, 0x65, 0x78, 0x65, 0x2069]),
    "RloFlip",
  );
});

test("detect_fullwidth_exe", () => {
  // "file.ＥＸＥ" (fullwidth EXE in the extension).
  assert.equal(tag([0x66, 0x69, 0x6c, 0x65, 0x2e, 0xff25, 0xff38, 0xff25]), "WidthClassExt");
});

test("detect_combining_in_ext", () => {
  // "file.e<combining acute>xe" — combining acute in the extension.
  assert.equal(tag([0x66, 0x69, 0x6c, 0x65, 0x2e, 0x65, 0x0301, 0x78, 0x65]), "CombiningInExt");
});

test("detect_triple_extension", () => {
  // "setup.tar.gz.sig"
  const v = detect([
    0x73, 0x65, 0x74, 0x75, 0x70, 0x2e, 0x74, 0x61, 0x72, 0x2e, 0x67, 0x7a, 0x2e, 0x73, 0x69,
    0x67,
  ]);
  assert.equal(v.classify.tag, "MultipleExtensions");
});

// ── (c) priority-ladder structural check ─────────────────────────────────────

test("bidi_beats_fullwidth", () => {
  // A bidi control outranks a fullwidth extension.
  assert.equal(tag([0x202e, 0x66, 0x2e, 0xff25]), "RloFlip");
});

// ── reason-code shape ────────────────────────────────────────────────────────

test("sub-threat tag and reason code", () => {
  assert.equal(
    filenameDisguiseSubThreatTag({ kind: "MultipleExtensions", dotCount: 3 }),
    "MultipleExtensions",
  );
  assert.equal(
    filenameDisguiseReasonCode("RloFlip"),
    "unicode.security.D.filename-disguise.RloFlip",
  );
});
