# C# / .NET Port

This is the dependency-free .NET package surface for the shared Unicode
security runtime contract.

The package exports the shared product APIs through `UnicodeSecurity.Security`:

```csharp
Security.Scan(profile, mode, codepoints)
Security.ScanUtf8(profile, mode, bytes)
Security.ScanUtf16BE(profile, mode, bytes)
Security.ScanUtf16LE(profile, mode, bytes)
Security.ScanUtf32BE(profile, mode, bytes)
Security.ScanUtf32LE(profile, mode, bytes)
Security.VerdictJson(verdict)
```

Run from this directory:

```sh
dotnet run --project test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj
```

Run from the repository root:

```sh
scripts/test-runtime-ports.sh --dotnet-only
```

The port vendors `CaseFolding.txt`, `confusables.txt`,
`KnownAttackTargets.txt`, `StandardizedVariants.txt`,
`emoji-variation-sequences.txt`, and local copies of the shared contract
fixtures so the package can be tested from an installed or copied package tree.
