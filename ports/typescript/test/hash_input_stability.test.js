import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import {
  RfcRule,
  rfcRuleTag,
  rfcRuleFromTag,
  hashStable,
  hashInputStabilityDetect,
  hashInputStabilityDetectWithContext,
  hashInputStabilityReasonCode,
} from "../src/security-core.js";

const tag = (input) => hashInputStabilityDetect(input).classify.tag;
const ctxTag = (ctx, input) => hashInputStabilityDetectWithContext(ctx, input).classify.tag;

function loadFixture(path) {
  return JSON.parse(
    readFileSync(new URL(`../testdata/fixtures/security/${path}`, import.meta.url), "utf8"),
  );
}

// ── (a) shared context-free detector fixture ────────────────────────────────

test("hash-input-stability shared detector fixture", () => {
  const fixture = loadFixture("detectors/hash_input_stability.json");
  assert.equal(fixture.schema, 1);
  assert.equal(fixture.family, "hash-input-stability");

  for (const entry of fixture.cases) {
    const verdict = hashInputStabilityDetect(entry.input);
    const codes = verdict.classify.tag === null ? [] : [hashInputStabilityReasonCode(verdict.classify.tag)];
    for (const required of entry.required_findings) {
      assert.ok(codes.includes(required), `${entry.name}: missing ${required}`);
    }
    if (entry.required_findings.length === 0) {
      assert.equal(verdict.classify.isClear, true, `${entry.name}: expected clear`);
    }
  }
});

// ── §4 hashStable spot checks (from the Rust #[test] module) ─────────────────

test("hashStable spot checks match the Lean/Rust vectors", () => {
  assert.deepEqual(hashStable([]), []);
  assert.deepEqual(hashStable([0x61, 0x62, 0x63]), [0x61, 0x62, 0x63]);
  assert.deepEqual(hashStable(hashStable([0x61, 0x62, 0x63])), hashStable([0x61, 0x62, 0x63]));
  assert.deepEqual(hashStable([0x61, 0x20]), [0x61]);
  assert.deepEqual(hashStable([0x61, 0x09]), [0x61]);
  assert.deepEqual(hashStable([0x61, 0x0a]), [0x61]);
  assert.deepEqual(hashStable([0x61, 0x0d, 0x0a]), [0x61]);
  assert.deepEqual(hashStable([0x61, 0x20, 0x62]), [0x61, 0x20, 0x62]);
  assert.deepEqual(hashStable([0x0065, 0x0301]), [0x00e9]);
  assert.deepEqual(hashStable([0x61, 0x00a0]), [0x61, 0x00a0]); // trailing NBSP is content
});

// ── §8 detect spot checks (bare input) ──────────────────────────────────────

test("detect bare-input spot checks match the Lean/Rust vectors", () => {
  assert.equal(hashInputStabilityDetect([]).classify.isClear, true);
  assert.equal(hashInputStabilityDetect([0x61, 0x62, 0x63]).classify.isClear, true);

  const trailingSpace = hashInputStabilityDetect([0x61, 0x20]);
  assert.equal(trailingSpace.classify.tag, "TrailingWhitespace");
  assert.equal(trailingSpace.stableSize, 1);
  assert.deepEqual(trailingSpace.classify.positions, [1]);

  const trailingCrlf = hashInputStabilityDetect([0x61, 0x0d, 0x0a]);
  assert.equal(trailingCrlf.classify.tag, "TrailingWhitespace");
  assert.equal(trailingCrlf.stableSize, 1);

  const decomposed = hashInputStabilityDetect([0x0065, 0x0301]);
  assert.equal(decomposed.classify.tag, "NormalizationDrift");
  assert.deepEqual(decomposed.classify.positions, [0]);

  assert.equal(hashInputStabilityDetect([0x00e9]).classify.isClear, true);
  // Decomposed "é " — TrailingWhitespace wins over NormalizationDrift.
  assert.equal(tag([0x0065, 0x0301, 0x20]), "TrailingWhitespace");
  assert.equal(hashInputStabilityDetect([0x61, 0x20, 0x62]).classify.isClear, true);
});

// ── §9 Context-bearing probe vectors (verbatim from the Rust comment block) ──
//
//   declared_encoding = Some("utf-16"),  [0x61,0x62,0x63]      → EncodingMismatch, [0]
//   declared_encoding = Some("utf-8"),   [0x61,0xD800,0x62]    → EncodingMismatch, [1]  (invalid surrogate)
//   declared_encoding = Some("utf-8"),   [0x61,0x110000,0x62]  → EncodingMismatch, [1]  (out of range)
//   declared_encoding = Some("UTF-8"|"utf-8"|"UTF8"), [0x61,0x62,0x63] → clear
//   rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20]          → SignedMessageRule, [1]
//   rfc_rule = Pgp9580LineEnding, [0x61,0x0A,0x62]             → SignedMessageRule, [1]  (bare LF)
//   rfc_rule = Pgp9580LineEnding, [0x61,0x62,0x63,0x0D,0x0A,0x64,0x65,0x66] → clear (CRLF)
//   rfc_rule = Rfc8785NfcRequirement, [0x0065,0x0301]          → SignedMessageRule, [0]
//   rfc_rule = Rfc8259ControlChar, [0x61,0x01,0x62]            → SignedMessageRule, [1]
//   rfc_rule = Rfc7515JwsBase64Url, [0x41,0x2B,0x42]           → SignedMessageRule, [1]  ('+')
//   rfc_rule = Rfc7515JwsBase64Url, [0x41,0x61,0x30,0x2D,0x5F,0x7A,0x5A,0x39] → clear
//   rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x20,0x62]       → SignedMessageRule, [2]
//   rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x62]            → clear (single space)
//   rfc_rule = Rfc5751SmimeLineEnding, [0x61,0x0A,0x62]        → SignedMessageRule, [1]  (bare LF)
//   as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x64] → AuditLogReinterpretation, [2]
//   as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
//   server_bytes = Some([0x61,0x62,0x64]), input [0x61,0x62,0x63] → WebhookSignatureDrift, [2]
//   server_bytes = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
//   declared_encoding = Some("utf-16") + rfc_rule = Pgp9580LineEnding,
//     [0x0065,0x0301,0x0A]                                     → EncodingMismatch  (priority over rfc)
//   server_bytes = Some([0x61,0x62,0x65]) + as_written = Some([0x61,0x62,0x66]),
//     input [0x61,0x62,0x63]                                   → WebhookSignatureDrift (priority over audit)
//   rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20]          → SignedMessageRule (priority over trailing)

test("detect_with_context default matches detect", () => {
  const d = hashInputStabilityDetect([0x61, 0x62, 0x63]);
  const c = hashInputStabilityDetectWithContext({}, [0x61, 0x62, 0x63]);
  assert.deepEqual(c.classify, d.classify);
  assert.equal(c.stableSize, d.stableSize);
});

test("encodingMismatch context vectors", () => {
  const utf16 = hashInputStabilityDetectWithContext(
    { declaredEncoding: "utf-16" },
    [0x61, 0x62, 0x63],
  );
  assert.equal(utf16.classify.tag, "EncodingMismatch");
  assert.deepEqual(utf16.classify.positions, [0]);

  const surrogate = hashInputStabilityDetectWithContext(
    { declaredEncoding: "utf-8" },
    [0x61, 0xd800, 0x62],
  );
  assert.equal(surrogate.classify.tag, "EncodingMismatch");
  assert.deepEqual(surrogate.classify.positions, [1]);

  const outOfRange = hashInputStabilityDetectWithContext(
    { declaredEncoding: "utf-8" },
    [0x61, 0x110000, 0x62],
  );
  assert.equal(outOfRange.classify.tag, "EncodingMismatch");
  assert.deepEqual(outOfRange.classify.positions, [1]);

  for (const label of ["UTF-8", "utf-8", "UTF8", "utf8"]) {
    assert.equal(
      hashInputStabilityDetectWithContext({ declaredEncoding: label }, [0x61, 0x62, 0x63]).classify
        .isClear,
      true,
      `label ${label} should be recognised as UTF-8`,
    );
  }
});

test("signedMessageRule context vectors", () => {
  const pgp4880 = hashInputStabilityDetectWithContext(
    { rfcRule: RfcRule.Pgp4880TrailingWhitespace },
    [0x61, 0x20],
  );
  assert.equal(pgp4880.classify.tag, "SignedMessageRule");
  assert.deepEqual(pgp4880.classify.positions, [1]);

  const pgp9580BareLf = hashInputStabilityDetectWithContext(
    { rfcRule: RfcRule.Pgp9580LineEnding },
    [0x61, 0x0a, 0x62],
  );
  assert.equal(pgp9580BareLf.classify.tag, "SignedMessageRule");
  assert.deepEqual(pgp9580BareLf.classify.positions, [1]);

  assert.equal(
    ctxTag({ rfcRule: RfcRule.Pgp9580LineEnding }, [0x61, 0x62, 0x63, 0x0d, 0x0a, 0x64, 0x65, 0x66]),
    null,
  );

  const rfc8785 = hashInputStabilityDetectWithContext(
    { rfcRule: RfcRule.Rfc8785NfcRequirement },
    [0x0065, 0x0301],
  );
  assert.equal(rfc8785.classify.tag, "SignedMessageRule");
  assert.deepEqual(rfc8785.classify.positions, [0]);

  const rfc8259 = hashInputStabilityDetectWithContext(
    { rfcRule: RfcRule.Rfc8259ControlChar },
    [0x61, 0x01, 0x62],
  );
  assert.equal(rfc8259.classify.tag, "SignedMessageRule");
  assert.deepEqual(rfc8259.classify.positions, [1]);

  const rfc7515Plus = hashInputStabilityDetectWithContext(
    { rfcRule: RfcRule.Rfc7515JwsBase64Url },
    [0x41, 0x2b, 0x42],
  );
  assert.equal(rfc7515Plus.classify.tag, "SignedMessageRule");
  assert.deepEqual(rfc7515Plus.classify.positions, [1]);

  assert.equal(
    ctxTag({ rfcRule: RfcRule.Rfc7515JwsBase64Url }, [0x41, 0x61, 0x30, 0x2d, 0x5f, 0x7a, 0x5a, 0x39]),
    null,
  );

  const rfc6376Double = hashInputStabilityDetectWithContext(
    { rfcRule: RfcRule.Rfc6376DkimRelaxed },
    [0x61, 0x20, 0x20, 0x62],
  );
  assert.equal(rfc6376Double.classify.tag, "SignedMessageRule");
  assert.deepEqual(rfc6376Double.classify.positions, [2]);

  assert.equal(ctxTag({ rfcRule: RfcRule.Rfc6376DkimRelaxed }, [0x61, 0x20, 0x62]), null);

  const rfc5751 = hashInputStabilityDetectWithContext(
    { rfcRule: RfcRule.Rfc5751SmimeLineEnding },
    [0x61, 0x0a, 0x62],
  );
  assert.equal(rfc5751.classify.tag, "SignedMessageRule");
  assert.deepEqual(rfc5751.classify.positions, [1]);
});

test("auditLogReinterpretation context vectors", () => {
  const drift = hashInputStabilityDetectWithContext(
    { asWritten: [0x61, 0x62, 0x63] },
    [0x61, 0x62, 0x64],
  );
  assert.equal(drift.classify.tag, "AuditLogReinterpretation");
  assert.deepEqual(drift.classify.positions, [2]);

  assert.equal(ctxTag({ asWritten: [0x61, 0x62, 0x63] }, [0x61, 0x62, 0x63]), null);
});

test("webhookSignatureDrift context vectors", () => {
  const drift = hashInputStabilityDetectWithContext(
    { serverBytes: [0x61, 0x62, 0x64] },
    [0x61, 0x62, 0x63],
  );
  assert.equal(drift.classify.tag, "WebhookSignatureDrift");
  assert.deepEqual(drift.classify.positions, [2]);

  assert.equal(ctxTag({ serverBytes: [0x61, 0x62, 0x63] }, [0x61, 0x62, 0x63]), null);
});

test("priority ordering context vectors", () => {
  // encoding over rfc: bare LF (pgp9580) + decomposed é (rfc8785) labeled utf-16.
  assert.equal(
    ctxTag(
      { declaredEncoding: "utf-16", rfcRule: RfcRule.Pgp9580LineEnding },
      [0x0065, 0x0301, 0x0a],
    ),
    "EncodingMismatch",
  );

  // webhook over audit.
  assert.equal(
    ctxTag(
      { serverBytes: [0x61, 0x62, 0x65], asWritten: [0x61, 0x62, 0x66] },
      [0x61, 0x62, 0x63],
    ),
    "WebhookSignatureDrift",
  );

  // rfc over trailing.
  assert.equal(
    ctxTag({ rfcRule: RfcRule.Pgp4880TrailingWhitespace }, [0x61, 0x20]),
    "SignedMessageRule",
  );
});

test("RfcRule fixture-tag round-trip", () => {
  for (const rule of [
    RfcRule.Pgp4880TrailingWhitespace,
    RfcRule.Pgp9580LineEnding,
    RfcRule.Rfc8785NfcRequirement,
    RfcRule.Rfc8259ControlChar,
    RfcRule.Rfc7515JwsBase64Url,
    RfcRule.Rfc6376DkimRelaxed,
    RfcRule.Rfc5751SmimeLineEnding,
  ]) {
    assert.equal(rfcRuleFromTag(rfcRuleTag(rule)), rule);
  }
  assert.equal(rfcRuleFromTag("nope"), null);
});
