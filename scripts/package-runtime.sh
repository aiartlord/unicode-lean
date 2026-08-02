#!/usr/bin/env bash
# Build installable runtime-port artifacts without building Lean.
# shellcheck disable=SC2030,SC2031

set -euo pipefail

cd "$(dirname "$0")/.."

dist_dir="${UNICODE_RUNTIME_DIST:-dist/runtime}"
jobs="${JOBS:-2}"

case "$dist_dir" in
  /*) dist_abs="$dist_dir" ;;
  *) dist_abs="$PWD/$dist_dir" ;;
esac

mkdir -p "$dist_abs"

version="$(awk -F '"' '/^version = / { print $2; exit }' ports/rust/Cargo.toml)"
commit="$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
tree_state="clean"
if [[ -n "$(git status --porcelain --untracked-files=normal 2>/dev/null)" ]]; then
  tree_state="dirty"
fi
ucd_manifest_sha256="$(sha256sum data/SHA256SUMS | awk '{ print $1 }')"

echo "== rust cli install =="
scripts/install-unicode-security.sh "$dist_abs/rust"

echo "== python wheel/sdist =="
python -m build --no-isolation --outdir "$dist_abs/python" ports/python

echo "== cpp header install tree =="
cmake -Wno-deprecated -S ports/cpp -B build/package-cpp \
  -DUNICODE_CPP_BUILD_TESTS=OFF \
  -DCMAKE_INSTALL_PREFIX="$dist_abs/cpp"
cmake --build build/package-cpp --parallel "$jobs"
cmake --install build/package-cpp

echo "== haskell source distribution =="
(
  cd ports/haskell
  export HOME="$PWD/.home"
  mkdir -p "$HOME"
  cabal sdist --builddir=dist-package --output-dir "$dist_abs/haskell"
)

echo "== jvm package check =="
(
  cd ports/jvm
  scripts/test.sh
)
rm -rf "$dist_abs/jvm"
mkdir -p "$dist_abs/jvm"
cp -R ports/jvm/README.md ports/jvm/scripts ports/jvm/src ports/jvm/testdata "$dist_abs/jvm/"

echo "== go module package check =="
(
  cd ports/go
  export HOME="$PWD/.home"
  export GOCACHE="$PWD/.cache/go-build"
  export GOMODCACHE="$PWD/.cache/go-mod"
  mkdir -p "$HOME" "$GOCACHE" "$GOMODCACHE"
  go list ./... > "$dist_abs/go-packages.txt"
  go test ./...
)
rm -rf "$dist_abs/go"
mkdir -p "$dist_abs/go"
cp -R ports/go/README.md ports/go/go.mod ports/go/security "$dist_abs/go/"

echo "== typescript package check =="
(
  cd ports/typescript
  node --test test/*.test.js
)
rm -rf "$dist_abs/typescript"
mkdir -p "$dist_abs/typescript"
cp -R ports/typescript/README.md ports/typescript/package.json \
  ports/typescript/src ports/typescript/test ports/typescript/testdata \
  "$dist_abs/typescript/"

echo "== dotnet package check =="
(
  cd ports/dotnet
  export DOTNET_CLI_HOME="$PWD/.dotnet-home"
  export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
  export DOTNET_NOLOGO=1
  mkdir -p "$DOTNET_CLI_HOME"
  dotnet run --project test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj
)
rm -rf "$dist_abs/dotnet"
mkdir -p "$dist_abs/dotnet"
cp -R ports/dotnet/README.md ports/dotnet/Data ports/dotnet/src \
  ports/dotnet/test ports/dotnet/testdata "$dist_abs/dotnet/"
find "$dist_abs/dotnet" -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +

echo "== swift package (build+test validated hermetically by .#unicode-swift) =="
# The swift port's build and contract tests run in the pinned-toolchain,
# sandboxed `.#unicode-swift` derivation (checkPhase runs scripts/test.sh under
# swift 5.10.1 from the nixpkgs-swift pin) — that hermetic, reproducible,
# signature-cacheable build is the auditable trust anchor for this port. This
# bare-runtime-shell has only an unwired swift (no Foundation/resource-dir
# search path) and cannot run swiftpm, so packaging here is deterministic file
# assembly only; the derivation, built in the same preflight's nix-packages
# step, is the validation.
rm -rf "$dist_abs/swift"
mkdir -p "$dist_abs/swift"
cp -R ports/swift/README.md ports/swift/Package.swift ports/swift/scripts \
  ports/swift/Sources ports/swift/ContractTests "$dist_abs/swift/"
find "$dist_abs/swift" -type d -name .build -prune -exec rm -rf {} +

echo "== zig library install =="
(
  cd ports/zig
  export ZIG_GLOBAL_CACHE_DIR="$PWD/.cache/zig-global"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR"
  zig build install --prefix "$dist_abs/zig"
)
mkdir -p "$dist_abs/zig/share/unicode-zig"
cp -R ports/zig/README.md ports/zig/build.zig ports/zig/src ports/zig/testdata \
  "$dist_abs/zig/share/unicode-zig/"

echo "== package evidence =="
checksum_tmp="$(mktemp)"
trap 'rm -f "$checksum_tmp"' EXIT
(
  cd "$dist_abs"
  find . -type f \
    ! -name MANIFEST.txt \
    ! -name SHA256SUMS \
    -printf '%P\0' \
    | sort -z \
    | xargs -0 sha256sum
) > "$checksum_tmp"
mv "$checksum_tmp" "$dist_abs/SHA256SUMS"
trap - EXIT

cat > "$dist_abs/MANIFEST.txt" <<MANIFEST
unicode runtime package artifacts

version: $version
git_commit: $commit
git_tree_state: $tree_state
ucd_manifest_sha256: $ucd_manifest_sha256
lean: not built
checksums: SHA256SUMS

rust/
  bin/unicode-security
  UNICODE_SECURITY_INSTALL.txt

python/
  unicode_python wheel and source distribution

cpp/
  installed C++ headers under include/unicode_cpp and runtime data under share/unicode_cpp/data

haskell/
  unicode-haskell Cabal source distribution

jvm/
  installable JVM package tree with vendored security data and contract fixtures

go-packages.txt
  Go module package list verified by go test

go/
  installable Go module tree with vendored security data and contract fixtures

typescript/
  installable TypeScript/JavaScript package tree with vendored security data and contract fixtures

dotnet/
  installable .NET package tree with vendored security data and contract fixtures

swift/
  installable Swift package tree with vendored security data and contract fixtures

zig/
  Zig install prefix containing libunicode_security and importable module source
MANIFEST

scripts/check-runtime-package.sh "$dist_abs"

echo "clean: runtime package artifacts written to $dist_abs"
