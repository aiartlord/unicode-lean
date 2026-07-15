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
    },
  });
  const verdict = security.scan("gateway-header", "enforce", [78, 101, 116, 104, 101, 114, 1077, 117, 109]);
  assert.equal(verdict.action, "reject");
  assert.ok(hasFinding(verdict.findings, "unicode.security.I.homoglyph-confusable.TargetMatch"));
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
