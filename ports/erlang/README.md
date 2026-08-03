# unicode-erlang

The Erlang runtime port of the Unicode security reference monitor — all 27
detector families, byte-faithful to the Lean-proven Rust reference, emitting the
same reason codes and verdicts as every other port. It is a standalone
application under `ports/erlang/`; this repository is the source of truth. The
detector reference and coverage matrix are in
[`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md); the architecture and threat
model are in [`../../docs/explanation/`](../../docs/explanation/). It suits
telecom and distributed control-plane integration.

## Depend on it

Add `ports/erlang/src` to the consumer's compile path, or vendor it as an
application dependency. The modules are prefixed `usec_`; the entry point is
`usec_policy`.

## The API

```erlang
%% Decode the wire encoding, then classify. Malformed input is rejected before any
%% detector runs. Prefer these at a trust boundary. Bytes is a binary.
usec_policy:scan_utf8(Profile, Mode, Bytes)
usec_policy:scan_utf16be(Profile, Mode, Bytes)
usec_policy:scan_utf16le(Profile, Mode, Bytes)
usec_policy:scan_utf32be(Profile, Mode, Bytes)
usec_policy:scan_utf32le(Profile, Mode, Bytes)

%% Classify already-decoded scalar values (no decode-boundary enforcement).
usec_policy:scan(Profile, Mode, Input)   %% Input: list of codepoints

%% Reason-code accessor.
usec_policy:reason_code(Family, SubThreat)
```

`Mode` is `<<"observe">> | <<"warn">> | <<"enforce">> | <<"strict">>`; `Profile`
names the context. The verdict carries an action
(`allow | reject | quarantine | rewrite | observe`) and findings, each with a
stable reason code `unicode.security.<layer>.<slug>.<SubThreat>` identical across
every port.

## Use it as a sanitization gate

```erlang
Verdict = usec_policy:scan_utf8(Profile, Mode, Bytes),
%% Verdict is a map; the action is under the `action` key, e.g. <<"allow">>.
case maps:get(action, Verdict) of
    <<"allow">> -> {ok, Bytes};
    _           -> {reject, Verdict}   %% findings carry the reason codes
end.
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
nix build .#unicode-erlang
```

## Data and contract

Runtime data is vendored under the application and pinned by SHA-256; the port
reads its UCD-derived tables from there and never from a Lean root. It is checked
against the shared fixtures under `fixtures/security/`, so its verdicts match
every other port for the same input. Refresh vendored data only through
`scripts/sync-runtime-data.sh`.
