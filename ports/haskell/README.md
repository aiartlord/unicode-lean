# unicode-haskell

The Haskell runtime port of the Unicode security reference monitor. It is a
standalone Cabal package under `ports/haskell/`, not a separate repository. This
repository remains the source of truth for the shared fixtures, the policy
contract, the reason-code namespace, and the Lean proofs the port is checked
against.

The package name is `unicode-haskell`. It lets a Haskell service link the
verified monitor in-process without pulling in any Lean build artifacts.

## What it provides

All twenty-seven detector families, byte-faithful to the Lean-proven Rust
reference, plus the codec and identifier substrate they need. A Haskell consumer
gets the same reason codes and verdicts as every other port. The detector
reference and the full coverage matrix are in
[`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md); the architecture and threat
model are in [`../../docs/explanation/`](../../docs/explanation/).

## Depend on it

`unicode-haskell` is not published to Hackage; consume it from this repository.
In a consumer's `cabal.project`, add it as a source-repository-package:

```cabal
source-repository-package
  type: git
  location: https://github.com/aiartlord/unicode-lean
  tag: v1.0.0
  subdir: ports/haskell
```

Or, within the same working tree, as a local path:

```cabal
packages: ./.               -- the consumer
          ../unicode/ports/haskell
```

Then add `unicode-haskell` to the consumer's `build-depends`.

## The API

The public entry point is `Unicode.Security.Policy`:

```haskell
import Unicode.Security.Policy
  ( scanUtf8, scan
  , Profile(..), Mode(..), Action(..)
  , Verdict(..), Finding(..)
  , reasonCode, verdictJson
  )
```

Signatures:

```haskell
-- Decode the wire encoding, then classify. Malformed input is rejected with a
-- specific reason code before any detector runs. Prefer these at a trust boundary.
scanUtf8    :: Profile -> Mode -> ByteString -> Verdict
scanUtf16BE :: Profile -> Mode -> ByteString -> Verdict
scanUtf16LE :: Profile -> Mode -> ByteString -> Verdict
scanUtf32BE :: Profile -> Mode -> ByteString -> Verdict
scanUtf32LE :: Profile -> Mode -> ByteString -> Verdict

-- Classify already-decoded scalar values. Use only when the caller has already
-- validated the encoding; it does not perform decode-boundary enforcement.
scan :: Profile -> Mode -> [Int] -> Verdict

verdictJson :: Verdict -> String   -- the shared cross-port JSON wire shape
```

The verdict carries the decision and every finding:

```haskell
data Verdict = Verdict
  { verdictInput      :: [Int]
  , verdictProfile    :: Profile
  , verdictMode       :: Mode
  , verdictAction     :: Action        -- Allow | Reject | Quarantine | Rewrite | Observe
  , verdictFindings   :: [Finding]     -- each carries a reason code, family, positions
  , verdictNormalized :: Maybe [Int]
  }
```

`Mode` is `Observe | Warn | Enforce | Strict`; `Profile` names the context, for
example `GatewayHeader`, `ChatMessage`, or `SourceCode`. Each finding's reason
code has the form `unicode.security.<layer>.<slug>.<SubThreat>` and is identical
across every port.

## Use it as a sanitization gate

Scan raw request bytes at the trust boundary and branch on the action:

```haskell
import qualified Data.ByteString as BS
import Unicode.Security.Policy

sanitize :: BS.ByteString -> Either Verdict BS.ByteString
sanitize body =
  let verdict = scanUtf8 ChatMessage Enforce body
  in case verdictAction verdict of
       Allow -> Right body
       _     -> Left verdict          -- verdictFindings carry the reason codes
```

For a WAI service this is a middleware that reads the request body, calls
`scanUtf8`, and short-circuits with a 4xx built from `verdictFindings` on a
non-`Allow` action. The general integration contract is in
[`../../docs/how-to/integrate.md`](../../docs/how-to/integrate.md).

## Build and test

From this directory:

```sh
cabal build all --offline
cabal test  all --offline
```

Or the reproducible build, which runs the test suite as part of the build:

```sh
nix build .#unicode-haskell
```

## Data and contract

Runtime data is vendored under `data/` and pinned by `data/SHA256SUMS`; the
policy layer reads the UCD-derived tables from there and never from a Lean root.
The port is checked against this repository's shared fixtures under
`fixtures/security/`, so its verdicts match every other port for the same input.
Refresh vendored data only through `scripts/sync-runtime-data.sh`.
