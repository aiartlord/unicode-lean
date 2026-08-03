# unicode-php

The PHP runtime port of the Unicode security reference monitor — all 27 detector
families, byte-faithful to the Lean-proven Rust reference, emitting the same
reason codes and verdicts as every other port. It is a standalone package under
`ports/php/`; this repository is the source of truth. The detector reference and
coverage matrix are in [`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md); the
architecture and threat model are in
[`../../docs/explanation/`](../../docs/explanation/). It suits PHP web-stack and
CMS/plugin integration.

## Depend on it

The package ships a plain autoloader; require it and use the namespace:

```php
require "path/to/unicode/ports/php/src/autoload.php";
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;
use UnicodePhp\Security\Mode;
```

## The API

The entry point is `UnicodePhp\Security\Policy` (static methods):

```php
// Decode the wire encoding, then classify. Malformed input is rejected before any
// detector runs. Prefer these at a trust boundary. $bytes is an array of octets.
Policy::scanUtf8(Profile $profile, Mode $mode, array $bytes): Verdict
Policy::scanUtf16be(Profile $profile, Mode $mode, array $bytes): Verdict
Policy::scanUtf16le(Profile $profile, Mode $mode, array $bytes): Verdict
Policy::scanUtf32be(Profile $profile, Mode $mode, array $bytes): Verdict
Policy::scanUtf32le(Profile $profile, Mode $mode, array $bytes): Verdict

// Classify already-decoded scalar values (no decode-boundary enforcement).
Policy::scan(Profile $profile, Mode $mode, array $input): Verdict   // codepoints
```

`Mode` is `Observe | Warn | Enforce | Strict`; `Profile` names the context. The
`Verdict` carries an action (`Allow | Reject | Quarantine | Rewrite | Observe`)
and findings, each with a stable reason code
`unicode.security.<layer>.<slug>.<SubThreat>` identical across every port.

## Use it as a sanitization gate

```php
$verdict = Policy::scanUtf8($profile, $mode, $bytes);
// $verdict->action is a backed enum; $verdict->action->value is the string, e.g. "allow".
if ($verdict->action->value !== "allow") {
    return reject($verdict);   // $verdict->findings carry the reason codes
}
```

The shared integration contract is in
[`../../docs/how-to/integrate.md`](../../docs/how-to/integrate.md).

## Build and test

From this directory:

```sh
php test/policy_test.php     # or any test/*_test.php
```

Or the reproducible build, which runs the suite as part of the build:

```sh
nix build .#unicode-php
```

## Data and contract

Runtime data is vendored under `data/` and pinned by `data/SHA256SUMS`; the port
reads its UCD-derived tables from there and never from a Lean root. It is checked
against the shared fixtures under `fixtures/security/`, so its verdicts match
every other port for the same input. Refresh vendored data only through
`scripts/sync-runtime-data.sh`.
