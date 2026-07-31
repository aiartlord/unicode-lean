import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  scan,
  scanUtf8,
  scanUtf16BE,
  scanUtf16LE,
  scanUtf32BE,
  scanUtf32LE,
  verdictJson,
  verdictToWire,
  toNfkdCodepoints,
  toNfkcCodepoints,
} from "../src/security.js";
import { instantiateSecurity as instantiateEdgeSecurity } from "../src/edge.js";

test("policy contract fixture", () => {
  const contract = loadFixture("policy_contract.json");
  assert.equal(contract.schema, 1);
  assert.equal(contract.contract, "unicode-security-policy-v0");

  for (const entry of contract.cases) {
    const verdict = scan(entry.profile, entry.mode, entry.input);
    assert.equal(verdict.action, entry.action, entry.name);
    for (const required of entry.required_findings) {
      assert.ok(hasFinding(verdict.findings, required), `${entry.name}: missing ${required}`);
    }
  }
});

test("verdict JSON contract fixture", () => {
  const contract = loadFixture("verdict_contract.json");
  assert.equal(contract.schema, 1);
  assert.equal(contract.contract, "unicode-security-verdict-v0");

  for (const entry of contract.cases) {
    const verdict = scan(entry.profile, entry.mode, entry.input);
    assert.deepEqual(verdictToWire(verdict), entry.verdict, entry.name);
    assert.equal(verdictJson(verdict), JSON.stringify(entry.verdict), entry.name);
  }
});

test("UTF-8 decode contract fixture", () => {
  const contract = loadFixture("decode_contract.json");
  assert.equal(contract.schema, 1);
  assert.equal(contract.contract, "unicode-security-decode-v0");

  for (const entry of contract.cases) {
    const verdict = scanUtf8(entry.profile, entry.mode, entry.input_bytes);
    assert.equal(verdict.action, entry.action, entry.name);
    assert.deepEqual(verdict.input, entry.input, entry.name);
    assertRequiredFindings(entry, verdict);
  }
});

test("multi-encoding decode contract fixture", () => {
  const contract = loadFixture("decode_multiencoding_contract.json");
  assert.equal(contract.schema, 1);
  assert.equal(contract.contract, "unicode-security-multiencoding-decode-v0");

  for (const entry of contract.cases) {
    const verdict = scanEncodedCase(entry);
    assert.equal(verdict.action, entry.action, entry.name);
    assert.deepEqual(verdict.input, entry.input, entry.name);
    assertRequiredFindings(entry, verdict);
  }
});

test("detector fixtures", () => {
  for (const fixture of [
    "detectors/tag_block_payload.json",
    "detectors/variation_selector_payload.json",
    "detectors/zero_width_payload.json",
    "detectors/bidi_control_balance.json",
    "detectors/noncharacter_control.json",
    "detectors/homoglyph_confusable.json",
    "detectors/mixed_script_admissibility.json",
  ]) {
    const detector = loadFixture(fixture);
    assert.equal(detector.schema, 1);
    for (const entry of detector.cases) {
      const verdict = scan("gateway-header", "observe", entry.input);
      for (const required of entry.required_findings) {
        assert.ok(hasFinding(verdict.findings, required), `${fixture}:${entry.name}: missing ${required}`);
      }
      if (entry.required_findings.length === 0) {
        assert.equal(hasFamilyFinding(verdict.findings, detector.family), false, `${fixture}:${entry.name}`);
      }
    }
  }
});

test("edge entry works with injected data", async () => {
  const security = await instantiateEdgeSecurity({
    data: {
      confusables: readFileSync(new URL("../src/data/confusables.txt", import.meta.url), "utf8"),
      caseFolding: readFileSync(new URL("../src/data/CaseFolding.txt", import.meta.url), "utf8"),
      knownAttackTargets: readFileSync(new URL("../src/data/KnownAttackTargets.txt", import.meta.url), "utf8"),
      derivedBidiClass: readFileSync(new URL("../src/data/DerivedBidiClass.txt", import.meta.url), "utf8"),
      unicodeData: readFileSync(new URL("../src/data/UnicodeData.txt", import.meta.url), "utf8"),
      compositionExclusions: readFileSync(new URL("../src/data/CompositionExclusions.txt", import.meta.url), "utf8"),
      derivedCoreProperties: readFileSync(new URL("../src/data/DerivedCoreProperties.txt", import.meta.url), "utf8"),
      specialCasing: readFileSync(new URL("../src/data/SpecialCasing.txt", import.meta.url), "utf8"),
    },
  });
  const verdict = security.scan("gateway-header", "enforce", [78, 101, 116, 104, 101, 114, 1077, 117, 109]);
  assert.equal(verdict.action, "reject");
  assert.ok(hasFinding(verdict.findings, "unicode.security.I.homoglyph-confusable.TargetMatch"));
});

test("surrogate-reassembly detector matches Lean spot-checks", () => {
  const cases = [
    // Clear: empty, ASCII, and well-formed multi-byte UTF-8.
    ["clear-empty", [], null],
    ["clear-ascii", [0x48, 0x65, 0x6c, 0x6c, 0x6f], null],
    ["clear-e-acute", [0xc3, 0xa9], null],
    ["clear-han", [0xe4, 0xb8, 0xad], null],
    ["clear-emoji", [0xf0, 0x9f, 0x98, 0x80], null],
    // Invalid start byte (0xC0/0xC1 forbidden, lone continuation, 0xFE/0xFF).
    ["modified-utf8-null", [0xc0, 0x80], "InvalidStartByte"],
    ["modified-utf8-slash", [0xc0, 0xaf], "InvalidStartByte"],
    ["byte-fe", [0xfe], "InvalidStartByte"],
    ["lone-continuation", [0x80], "InvalidStartByte"],
    ["byte-ff", [0xff], "InvalidStartByte"],
    // Overlong encodings.
    ["overlong-slash-3byte", [0xe0, 0x80, 0xaf], "Overlong"],
    ["overlong-slash-4byte", [0xf0, 0x80, 0x80, 0xaf], "Overlong"],
    // CESU-8 / surrogate codepoints.
    ["cesu8-surrogate", [0xed, 0xa0, 0x80], "Cesu8"],
    ["cesu8-surrogate-high", [0xed, 0xaf, 0xbf], "Cesu8"],
    // Truncated sequences.
    ["truncated-2byte", [0xc3], "Truncated"],
    ["truncated-4byte", [0xf0, 0x9f, 0x98], "Truncated"],
    // Non-byte-stream input (any codepoint >= 0x100): family does not apply.
    ["non-byte-stream-emoji", [0x1f600], null],
    ["non-byte-stream-mixed", [0x41, 0x100], null],
  ];
  for (const [name, input, want] of cases) {
    const verdict = scan("gateway-header", "observe", input);
    const finding = verdict.findings.find((f) => f.family === "surrogate-reassembly");
    const got = finding ? finding.sub_threat : null;
    assert.equal(got, want, name);
    if (want !== null) {
      assert.equal(finding.code, `unicode.security.C.surrogate-reassembly.${want}`, name);
    }
  }
});

test("confusable-bidi-compound detector matches Lean spot-checks", () => {
  const cases = [
    ["clear-empty", [], null],
    ["clear-ascii", [0x48, 0x65, 0x6c, 0x6c, 0x6f], null],
    ["clear-override-no-confusable", [0x202e, 0x0041, 0x0042, 0x0043], null],
    ["clear-confusable-no-bidi", [0x0430], null],
    ["confusable-in-override", [0x202e, 0x0430], "ConfusableInOverride"],
    ["confusable-in-isolate", [0x2066, 0x03bf], "ConfusableInIsolate"],
  ];
  for (const [name, input, want] of cases) {
    const verdict = scan("gateway-header", "observe", input);
    const finding = verdict.findings.find((f) => f.family === "confusable-bidi-compound");
    const got = finding ? finding.sub_threat : null;
    assert.equal(got, want, name);
    if (want !== null) {
      assert.equal(finding.code, `unicode.security.X.confusable-bidi-compound.${want}`, name);
    }
  }
});

test("covert-display-compound detector matches Lean spot-checks", () => {
  const cases = [
    ["clear-empty", [], null],
    ["clear-ascii", [0x48, 0x65, 0x6c, 0x6c, 0x6f], null],
    ["clear-rlo-alone", [0x202e], null],
    ["clear-vs-no-bidi", [0x0041, 0xfe00], null],
    ["bidi-plus-unregistered-vs", [0x202e, 0x0041, 0xfe00], "BidiPlusUnregisteredVs"],
    ["bidi-plus-tag-block", [0x202e, 0x0041, 0xe0001], "BidiPlusTagBlock"],
  ];
  for (const [name, input, want] of cases) {
    const verdict = scan("gateway-header", "observe", input);
    const finding = verdict.findings.find((f) => f.family === "covert-display-compound");
    const got = finding ? finding.sub_threat : null;
    assert.equal(got, want, name);
    if (want !== null) {
      assert.equal(finding.code, `unicode.security.X.covert-display-compound.${want}`, name);
    }
  }
});

function scanEncodedCase(entry) {
  switch (entry.encoding) {
    case "utf-8":
      return scanUtf8(entry.profile, entry.mode, entry.input_bytes);
    case "utf-16be":
      return scanUtf16BE(entry.profile, entry.mode, entry.input_bytes);
    case "utf-16le":
      return scanUtf16LE(entry.profile, entry.mode, entry.input_bytes);
    case "utf-32be":
      return scanUtf32BE(entry.profile, entry.mode, entry.input_bytes);
    case "utf-32le":
      return scanUtf32LE(entry.profile, entry.mode, entry.input_bytes);
    default:
      throw new Error(`unknown encoding: ${entry.encoding}`);
  }
}

function assertRequiredFindings(entry, verdict) {
  for (const required of entry.required_findings) {
    assert.ok(hasFinding(verdict.findings, required), `${entry.name}: missing ${required}`);
  }
  for (const expected of entry.required_positions) {
    const finding = verdict.findings.find((candidate) => candidate.code === expected.code);
    assert.ok(finding, `${entry.name}: missing positions for ${expected.code}`);
    assert.deepEqual(finding.positions, expected.positions, `${entry.name}: ${expected.code}`);
  }
}

function loadFixture(path) {
  return JSON.parse(readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"));
}

function hasFinding(findings, code) {
  return findings.some((finding) => finding.code === code);
}

function hasFamilyFinding(findings, family) {
  return findings.some((finding) => finding.family === family);
}

test("rtl-injection detector matches Lean spot-checks", () => {
  const cases = [
    ["clear-digits", [0x30, 0x31, 0x32, 0x33], null],
    ["clear-cyrillic", [0x043f], null],
    ["rlo-in-ltr", [0x41, 0x202e, 0x42], "RloInLTRField"],
    ["field-takeover-hebrew", [0x05d0, 0x42, 0x43], "FieldTakeover"],
    ["field-takeover-arabic", [0x0627, 0x42, 0x43], "FieldTakeover"],
    ["mid-stream-hebrew", [0x41, 0x42, 0x05d0, 0x44], "StrongRTLInLTR"],
    ["overflow-hebrew", [0x41, 0x42, 0x05d0, 0x05d1, 0x05d2, 0x05d3, 0x44], "MixedOverflow"],
  ];
  for (const [name, input, want] of cases) {
    const verdict = scan("gateway-header", "observe", input);
    const finding = verdict.findings.find((f) => f.family === "rtl-injection");
    const got = finding ? finding.sub_threat : null;
    assert.equal(got, want, name);
  }
});

test("NFKC normalization matches Lean/Rust reference vectors", () => {
  assert.deepEqual(toNfkcCodepoints([0xfb01]), [0x66, 0x69], "fi ligature");
  assert.deepEqual(toNfkcCodepoints([0x2460]), [0x31], "circled digit one");
  assert.deepEqual(toNfkcCodepoints([0xff21]), [0x41], "fullwidth A");
  assert.deepEqual(toNfkcCodepoints([0x00e9]), [0x00e9], "precomposed e-acute");
  assert.deepEqual(toNfkcCodepoints([0x0065, 0x0301]), [0x00e9], "e + combining acute");
  assert.deepEqual(
    toNfkcCodepoints([0x1112, 0x1161, 0x11ab]),
    [0xd55c],
    "hangul jamo composition",
  );
});

test("NFKD normalization matches Lean/Rust reference vectors", () => {
  assert.deepEqual(toNfkdCodepoints([0xff21]), [0x41], "fullwidth A");
  assert.deepEqual(toNfkdCodepoints([0x00e9]), [0x0065, 0x0301], "e-acute decomposition");
});
