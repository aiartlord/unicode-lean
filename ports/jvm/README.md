# Java / Kotlin Port

This is the dependency-free JVM package surface for the shared Unicode
security runtime contract. It is written in Java and is directly consumable
from Kotlin.

The package exports the shared product APIs through `com.unicodesecurity.Security`:

```java
Security.scan(profile, mode, codepoints)
Security.scanUtf8(profile, mode, bytes)
Security.scanUtf16BE(profile, mode, bytes)
Security.scanUtf16LE(profile, mode, bytes)
Security.scanUtf32BE(profile, mode, bytes)
Security.scanUtf32LE(profile, mode, bytes)
Security.verdictJson(verdict)
```

Run from this directory:

```sh
scripts/test.sh
```

Run from the repository root:

```sh
scripts/test-runtime-ports.sh --jvm-only
```

The port vendors `CaseFolding.txt`, `confusables.txt`,
`KnownAttackTargets.txt`, `StandardizedVariants.txt`,
`emoji-variation-sequences.txt`, and local copies of the shared contract
fixtures so the package can be tested from an installed or copied package tree.
