# unicode-ruby

The Ruby runtime port of the Unicode security reference monitor — all 27 detector
families, byte-faithful to the Lean-proven Rust reference, emitting the same
reason codes and verdicts as every other port. It is a standalone library under
`ports/ruby/`; this repository is the source of truth. The detector reference and
coverage matrix are in [`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md); the
architecture and threat model are in
[`../../docs/explanation/`](../../docs/explanation/).

## Depend on it

The library is not published as a gem; consume it from this repository. Put
`ports/ruby/lib` on the load path and require the entry point:

```ruby
$LOAD_PATH.unshift(File.expand_path("path/to/unicode/ports/ruby/lib"))
require "unicode_ruby"
```

## The API

The entry point is `UnicodeRuby::Security::Policy`:

```ruby
# Decode the wire encoding, then classify. Malformed input is rejected before any
# detector runs. Prefer these at a trust boundary.
Policy.scan_utf8(profile, mode, bytes)   # bytes: Array<Integer> of octets
Policy.scan_utf16be(profile, mode, bytes)
Policy.scan_utf16le(profile, mode, bytes)
Policy.scan_utf32be(profile, mode, bytes)
Policy.scan_utf32le(profile, mode, bytes)

# Classify already-decoded scalar values (no decode-boundary enforcement).
Policy.scan(profile, mode, input)        # input: Array<Integer> of codepoints
```

`profile` and `mode` come from `Policy::Profile` and `Policy::Mode`; `mode` is
`Observe | Warn | Enforce | Strict`. The verdict carries an `action`
(`Allow | Reject | Quarantine | Rewrite | Observe`) and a list of findings, each
with a stable reason code `unicode.security.<layer>.<slug>.<SubThreat>` identical
across every port.

## Use it as a sanitization gate

```ruby
verdict = UnicodeRuby::Security::Policy.scan_utf8(profile, mode, bytes)
# verdict is a Struct; verdict.action is the action string, e.g. "allow".
reject!(verdict) unless verdict.action == "allow"   # verdict.findings carry the reason codes
```

The shared integration contract is in
[`../../docs/how-to/integrate.md`](../../docs/how-to/integrate.md).

## Segmentation

`UnicodeRuby::Segmentation` covers UAX #29 extended grapheme clusters
(`Grapheme.grapheme_breaks`, `Grapheme.grapheme_clusters`) and UAX #14 default
line breaking (`LineBreak.line_breaks`, `LineBreak.line_runs`). Each returns one
boundary flag per position, so a sequence of n code points yields n + 1 flags,
and each is judged against the Unicode Consortium's published corpus for its
algorithm — a segmentation rule reads context on both sides of a boundary, so a
wrong rule survives any vector a person would pick.

A segmentation module takes code points and needs no data directory: its
property ranges are generated into source, while the security layer parses its
own tables out of `data/`. `segmentation/grapheme_tables.rb` carries the UAX #29
properties, and `tools/generate_line_break_tables.py` writes
`segmentation/line_break_tables.rb` — the Line_Break, General_Category and
East_Asian_Width ranges UAX #14 reads — and vendors the published corpus to
`testdata/LineBreakTest.txt`. Both are generated; edit the script and
regenerate.

## Build and test

From this directory:

```sh
ruby -Ilib -Itest test/policy_test.rb   # or any test/*_test.rb
```

Or the reproducible build, which runs the suite as part of the build:

```sh
nix build .#unicode-ruby
```

## Data and contract

Runtime data is vendored under `data/` and pinned by `data/SHA256SUMS`; the port
reads its UCD-derived tables from there and never from a Lean root. It is checked
against the shared fixtures under `fixtures/security/`, so its verdicts match
every other port for the same input. Refresh vendored data only through
`scripts/sync-runtime-data.sh`.
