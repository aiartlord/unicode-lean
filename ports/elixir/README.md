# unicode-elixir

The Elixir runtime port of the Unicode security reference monitor — all 27
detector families, byte-faithful to the Lean-proven Rust reference, emitting the
same reason codes and verdicts as every other port. It is a standalone Mix
package under `ports/elixir/`; this repository is the source of truth. The
detector reference and coverage matrix are in
[`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md); the architecture and threat
model are in [`../../docs/explanation/`](../../docs/explanation/). It suits
telecom and resilient control-plane integration.

## Depend on it

The package is not published to Hex; consume it as a path dependency in the
consumer's `mix.exs`:

```elixir
defp deps do
  [{:unicode_security, path: "path/to/unicode/ports/elixir"}]
end
```

## The API

The entry point is `UnicodeSecurity.Policy`:

```elixir
# Decode the wire encoding, then classify. Malformed input is rejected before any
# detector runs. Prefer these at a trust boundary. bytes is a binary.
UnicodeSecurity.Policy.scan_utf8(profile, mode, bytes)
UnicodeSecurity.Policy.scan_utf16be(profile, mode, bytes)
UnicodeSecurity.Policy.scan_utf16le(profile, mode, bytes)
UnicodeSecurity.Policy.scan_utf32be(profile, mode, bytes)
UnicodeSecurity.Policy.scan_utf32le(profile, mode, bytes)

# Classify already-decoded scalar values (no decode-boundary enforcement).
UnicodeSecurity.Policy.scan(profile, mode, input)   # input: list of codepoints
```

`mode` is `"observe" | "warn" | "enforce" | "strict"`; `profile` names the
context. The verdict carries an action (`Allow | Reject | Quarantine | Rewrite |
Observe`) and findings, each with a stable reason code
`unicode.security.<layer>.<slug>.<SubThreat>` identical across every port.

## Use it as a sanitization gate

```elixir
verdict = UnicodeSecurity.Policy.scan_utf8(profile, mode, bytes)

# verdict.action is the action string, e.g. "allow".
case verdict.action do
  "allow" -> {:ok, bytes}
  _       -> {:reject, verdict}   # verdict.findings carry the reason codes
end
```

The shared integration contract is in
[`../../docs/how-to/integrate.md`](../../docs/how-to/integrate.md).

## Build and test

From this directory:

```sh
bash scripts/test.sh     # runs mix test
```

Or the reproducible build, which runs the suite as part of the build:

```sh
nix build .#unicode-elixir
```

## Data and contract

Runtime data is vendored under the package and pinned by SHA-256; the port reads
its UCD-derived tables from there and never from a Lean root. It is checked
against the shared fixtures under `fixtures/security/`, so its verdicts match
every other port for the same input. Refresh vendored data only through
`scripts/sync-runtime-data.sh`.
