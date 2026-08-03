# Integrate the engine into a service

This guide wires the security engine into a consuming system as the inline
sanitization layer for untrusted text. It is generic. Consumer-specific wiring
belongs in the consuming repository, not here.

## Choose a deployment shape

Pick by the consumer's language and latency budget.

- **In-process, native port** — the hot path. Available when the consumer's
  language has a port under `ports/`: Rust, C++, Python, Go, JVM, TypeScript,
  .NET, Swift, Zig, Haskell, Ruby, Lua, PHP, Elixir, Erlang, COBOL. Lowest
  latency, no network hop, scales with the consumer's own processes. Use this for
  a router or gateway data plane.
- **`serve` sidecar** — the fallback. A local endpoint over TCP, a Unix socket,
  or newline-framed stdio, called by any language. One hop on the same host. Use
  this when the consumer's language has no native port. See
  [`operate.md`](operate.md).

## Scan at the trust boundary, once

Sanitize where untrusted text enters the system and carry the verdict forward.

1. Take the raw inbound bytes at ingress.
2. Call the byte-level entry point for the wire encoding: `scan_utf8`,
   `scan_utf16be`, `scan_utf16le`, `scan_utf32be`, or `scan_utf32le`. These
   strict-decode first and reject malformed input with a specific reason code and
   byte offset. Do not lenient-decode to U+FFFD and then hand codepoints to the
   codepoint-level `scan`; that skips decode-boundary enforcement.
3. Select a `Profile` and a `Mode` for the context. The profile names the allowed
   encodings, normalization behavior, and detector set; the mode chooses
   `observe`, `warn`, `enforce`, or `strict`. Profiles and modes are listed in
   [`../reference/cli.md`](../reference/cli.md).
4. Branch on the verdict. On a hazard, apply the policy action and record the
   reason code. Attach the verdict to the message so downstream stages read it
   rather than re-scanning.

## Minimal in-process example

The shape is the same in every port: decode is folded into the byte-level entry
point, and the caller branches on the verdict. In Rust:

```rust
use unicode_security::security::policy;

let verdict = policy::scan_utf8(Profile::GatewayHeader, Mode::Enforce, &bytes);
if verdict.action != Action::Allow {
    // verdict.findings each carry a stable reason code, family, severity, positions
    return reject(verdict);
}
forward_with_verdict(message, verdict);
```

## Operate it as the middle layer

- **Bound the input.** Enforce a maximum message size at ingress so per-message
  cost and state stay bounded.
- **Fail closed on table drift.** A node whose vendored tables do not match the
  pinned digests must refuse to serve rather than classify differently from the
  fleet. Table attestation is a roadmap workstream in
  [`../ROADMAP.md`](../ROADMAP.md).
- **Keep the verdict on the message.** Downstream stages consume the attached
  verdict; re-scanning at every hop wastes the per-message budget.
- **Shard by connection.** State is per-connection, so throughput scales
  horizontally across nodes with no cross-node coordination.

## Verify the integration

- Drive the shared detector fixtures under `fixtures/security/detectors/` through
  the consumer's ingress and assert the expected reason codes.
- Drive the decode contracts, `fixtures/security/decode_contract.json` and
  `fixtures/security/decode_multiencoding_contract.json`, to confirm malformed
  input is rejected at the boundary.
- Confirm identical bytes produce an identical verdict whether scanned in-process
  or through the sidecar.
