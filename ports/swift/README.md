# Swift Port

This is the Swift Package Manager surface for the shared Unicode security
runtime contract. It is dependency-free and vendors the security data needed by
the `homoglyph-confusable` detector under package resources.

Run the contract tests:

```bash
scripts/test.sh
```

From the repository root:

```bash
scripts/test-runtime-ports.sh --swift-only
```

The public API mirrors the shared contract:

```swift
let verdict = scan(profile: Profile.gatewayHeader, mode: Mode.enforce, input: [72, 101])
let json = verdictJson(verdict)
```

Raw-byte entry points are available for UTF-8, UTF-16BE/LE, and UTF-32BE/LE.

Runtime data is vendored under
`Sources/UnicodeSecurity/Resources/Data/`: `CaseFolding.txt`,
`confusables.txt`, `KnownAttackTargets.txt`, `StandardizedVariants.txt`, and
`emoji-variation-sequences.txt`.
