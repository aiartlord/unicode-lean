# unicode-lua

The Lua runtime port of the Unicode security reference monitor — all 27 detector
families, byte-faithful to the Lean-proven Rust reference, emitting the same
reason codes and verdicts as every other port. It is a standalone module tree
under `ports/lua/`; this repository is the source of truth. The detector
reference and coverage matrix are in
[`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md); the architecture and threat
model are in [`../../docs/explanation/`](../../docs/explanation/). It targets
Lua 5.4 and is suited to NGINX/OpenResty gateway filtering.

## Depend on it

Put `ports/lua/src` on `package.path` and require the policy module:

```lua
package.path = "path/to/unicode/ports/lua/src/?.lua;" .. package.path
local policy = require("unicode_lua.security.policy")
```

## The API

The policy module exposes:

```lua
-- Decode the wire encoding, then classify. Malformed input is rejected before any
-- detector runs. Prefer these at a trust boundary.
policy.scan_utf8(profile, mode, bytes)     -- bytes: table of octets
policy.scan_utf16be(profile, mode, bytes)
policy.scan_utf16le(profile, mode, bytes)
policy.scan_utf32be(profile, mode, bytes)
policy.scan_utf32le(profile, mode, bytes)

-- Classify already-decoded scalar values (no decode-boundary enforcement).
policy.scan(profile, mode, input)          -- input: table of codepoints
```

`mode` is `observe | warn | enforce | strict`; `profile` names the context. The
verdict carries an `action` (`Allow | Reject | Quarantine | Rewrite | Observe`)
and a list of findings, each with a stable reason code
`unicode.security.<layer>.<slug>.<SubThreat>` identical across every port.

## Use it as a sanitization gate

```lua
local verdict = policy.scan_utf8(profile, mode, bytes)
-- verdict.action is the action string, e.g. "allow".
if verdict.action ~= "allow" then
  return reject(verdict)   -- verdict.findings carry the reason codes
end
```

The shared integration contract is in
[`../../docs/how-to/integrate.md`](../../docs/how-to/integrate.md).

## Build and test

From this directory:

```sh
bash scripts/test.sh
```

Or the reproducible build, which runs the suite as part of the build:

```sh
nix build .#unicode-lua
```

## Data and contract

Runtime data is vendored under `data/` and pinned by `data/SHA256SUMS`; the port
reads its UCD-derived tables from there and never from a Lean root. It is checked
against the shared fixtures under `fixtures/security/`, so its verdicts match
every other port for the same input. Refresh vendored data only through
`scripts/sync-runtime-data.sh`.
