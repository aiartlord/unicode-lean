#!/usr/bin/env bash
# Verify installable runtime-port artifacts without building Lean.

set -euo pipefail

cd "$(dirname "$0")/.."

dist_dir="${1:-${UNICODE_RUNTIME_DIST:-dist/runtime}}"

case "$dist_dir" in
  /*) dist_abs="$dist_dir" ;;
  *) dist_abs="$PWD/$dist_dir" ;;
esac

fail() {
  echo "FATAL: $*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "missing file: $path"
}

require_dir() {
  local path="$1"
  [[ -d "$path" ]] || fail "missing directory: $path"
}

require_executable() {
  local path="$1"
  [[ -x "$path" ]] || fail "missing executable: $path"
}

require_real_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || fail "missing real file: $path"
}

cleanup_paths=()
cleanup() {
  local path
  for path in "${cleanup_paths[@]}"; do
    rm -rf "$path"
  done
}
trap cleanup EXIT

make_temp_dir() {
  local dir
  dir="$(mktemp -d)"
  cleanup_paths+=("$dir")
  printf '%s\n' "$dir"
}

require_file "$dist_abs/MANIFEST.txt"
require_file "$dist_abs/SHA256SUMS"

grep -Eq '^version: [0-9][0-9A-Za-z._+-]*$' "$dist_abs/MANIFEST.txt" \
  || fail "runtime package manifest missing version"
grep -Eq '^git_commit: ([0-9a-f]{40}|unknown)$' "$dist_abs/MANIFEST.txt" \
  || fail "runtime package manifest missing git commit"
grep -Eq '^git_tree_state: (clean|dirty)$' "$dist_abs/MANIFEST.txt" \
  || fail "runtime package manifest missing git tree state"
grep -Eq '^ucd_manifest_sha256: [0-9a-f]{64}$' "$dist_abs/MANIFEST.txt" \
  || fail "runtime package manifest missing UCD manifest hash"
grep -Fqx 'lean: not built' "$dist_abs/MANIFEST.txt" \
  || fail "runtime package manifest must state that Lean was not built"
grep -Fqx 'checksums: SHA256SUMS' "$dist_abs/MANIFEST.txt" \
  || fail "runtime package manifest missing checksum pointer"

(
  cd "$dist_abs"
  sha256sum -c SHA256SUMS >/dev/null
) || fail "runtime package checksum verification failed"

rust_bin="$dist_abs/rust/bin/unicode-security"
require_executable "$rust_bin"
require_file "$dist_abs/rust/UNICODE_SECURITY_INSTALL.txt"

python_bin="${PYTHON:-python}"
command -v "$python_bin" >/dev/null 2>&1 || fail "Python not found: $python_bin"

rust_version="$("$rust_bin" --version)"
[[ "$rust_version" == unicode-security* ]] \
  || fail "unicode-security --version returned unexpected output: $rust_version"

rust_smoke="$(printf 'Hello' | "$rust_bin" scan --profile gateway-header --mode enforce --json)"
expected_rust_smoke='{"action":"allow","profile":"gateway-header","mode":"enforce","input":[72,101,108,108,111],"findings":[],"normalized":null}'
[[ "$rust_smoke" == "$expected_rust_smoke" ]] \
  || fail "unicode-security smoke scan mismatch"

if ! "$python_bin" - "$rust_bin" <<'PY'
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

bin_path = sys.argv[1]


def request_unix(socket_path, method, path, body=None, content_type=None):
    body_bytes = (body or "").encode("utf-8")
    headers = [
        f"{method} {path} HTTP/1.1",
        "Host: localhost",
        f"Content-Length: {len(body_bytes)}",
        "Connection: close",
    ]
    if content_type is not None:
        headers.append(f"Content-Type: {content_type}")
    request_bytes = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body_bytes
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    client.connect(socket_path)
    client.sendall(request_bytes)
    client.shutdown(socket.SHUT_WR)
    response = b""
    while True:
        chunk = client.recv(4096)
        if not chunk:
            break
        response += chunk
    client.close()
    header, payload = response.split(b"\r\n\r\n", 1)
    return int(header.split(b" ", 2)[1]), payload.decode("utf-8")


sock = socket.socket()
sock.bind(("127.0.0.1", 0))
host, port = sock.getsockname()
sock.close()

proc = subprocess.Popen(
    [
        bin_path,
        "serve",
        "--listen",
        f"{host}:{port}",
        "--profile",
        "source-code",
        "--mode",
        "strict",
    ],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

try:
    deadline = time.time() + 5
    while True:
        if time.time() > deadline:
            raise RuntimeError("server did not become ready")
        try:
            conn = http.client.HTTPConnection(host, port, timeout=1)
            conn.request("GET", "/healthz")
            response = conn.getresponse()
            body = response.read().decode("utf-8")
            conn.close()
            if response.status == 200 and body == '{"status":"ok"}':
                break
        except OSError:
            time.sleep(0.05)

    body = json.dumps({"text": "a\u200bb"}, separators=(",", ":"))
    conn = http.client.HTTPConnection(host, port, timeout=2)
    conn.request(
        "POST",
        "/scan",
        body=body,
        headers={"Content-Type": "application/json"},
    )
    response = conn.getresponse()
    payload = response.read().decode("utf-8")
    conn.close()
    if response.status != 200:
        raise RuntimeError(f"scan status {response.status}: {payload}")
    verdict = json.loads(payload)
    if verdict.get("action") != "reject":
        raise RuntimeError(f"unexpected action: {payload}")
    codes = [finding.get("code") for finding in verdict.get("findings", [])]
    if "unicode.security.C.zero-width-payload.BareZeroWidth" not in codes:
        raise RuntimeError(f"missing zero-width finding: {payload}")

    batch_body = "\n".join(
        [
            json.dumps({"id": "ok", "text": "Hi"}, separators=(",", ":")),
            json.dumps({"id": "bad", "text": "a\u200bb"}, separators=(",", ":")),
            "",
        ]
    )
    conn = http.client.HTTPConnection(host, port, timeout=2)
    conn.request(
        "POST",
        "/batch",
        body=batch_body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    response = conn.getresponse()
    payload = response.read().decode("utf-8")
    conn.close()
    if response.status != 200:
        raise RuntimeError(f"batch status {response.status}: {payload}")
    rows = [json.loads(line) for line in payload.splitlines() if line]
    if len(rows) != 2:
        raise RuntimeError(f"expected 2 batch rows: {payload}")
    if rows[0].get("id") != "ok" or rows[0].get("action") != "allow":
        raise RuntimeError(f"unexpected first batch row: {payload}")
    if rows[1].get("id") != "bad" or rows[1].get("action") != "reject":
        raise RuntimeError(f"unexpected second batch row: {payload}")

    conn = http.client.HTTPConnection(host, port, timeout=2)
    conn.request("GET", "/metrics")
    response = conn.getresponse()
    payload = response.read().decode("utf-8")
    conn.close()
    if response.status != 200:
        raise RuntimeError(f"metrics status {response.status}: {payload}")
    metrics = json.loads(payload)
    if metrics.get("scan_requests_total") != 1:
        raise RuntimeError(f"unexpected scan count: {payload}")
    if metrics.get("batch_requests_total") != 1:
        raise RuntimeError(f"unexpected batch count: {payload}")
    if metrics.get("actions", {}).get("allow") != 1:
        raise RuntimeError(f"unexpected allow count: {payload}")
    if metrics.get("actions", {}).get("reject") != 2:
        raise RuntimeError(f"unexpected reject count: {payload}")
    reason_codes = metrics.get("reason_codes", {})
    if reason_codes.get("unicode.security.C.zero-width-payload.BareZeroWidth") != 2:
        raise RuntimeError(f"unexpected reason-code count: {payload}")
    latency = metrics.get("latency_ms", {})
    if latency.get("scan", {}).get("count") != 1:
        raise RuntimeError(f"unexpected scan latency count: {payload}")
    if latency.get("batch", {}).get("count") != 1:
        raise RuntimeError(f"unexpected batch latency count: {payload}")
    if "le_1" not in latency.get("scan", {}).get("buckets", {}):
        raise RuntimeError(f"missing scan latency buckets: {payload}")

    framed = subprocess.run(
        [
            bin_path,
            "serve",
            "--stdio-jsonl",
            "--profile",
            "source-code",
            "--mode",
            "strict",
        ],
        input=(
            json.dumps({"id": "ok", "text": "Hi"}, separators=(",", ":"))
            + "\n"
            + json.dumps({"id": "bad", "text": "a\u200bb"}, separators=(",", ":"))
            + "\n"
        ),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    framed_rows = [json.loads(line) for line in framed.stdout.splitlines() if line]
    if len(framed_rows) != 2:
        raise RuntimeError(f"expected 2 stdio-jsonl rows: {framed.stdout}")
    if framed_rows[0].get("id") != "ok" or framed_rows[0].get("action") != "allow":
        raise RuntimeError(f"unexpected stdio-jsonl allow row: {framed.stdout}")
    if framed_rows[1].get("id") != "bad" or framed_rows[1].get("action") != "reject":
        raise RuntimeError(f"unexpected stdio-jsonl reject row: {framed.stdout}")

    with tempfile.TemporaryDirectory() as tmp:
        unix_path = os.path.join(tmp, "unicode-security.sock")
        unix_proc = subprocess.Popen(
            [
                bin_path,
                "serve",
                "--unix-socket",
                unix_path,
                "--profile",
                "source-code",
                "--mode",
                "strict",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 5
            while True:
                if time.time() > deadline:
                    raise RuntimeError("unix server did not become ready")
                try:
                    status, unix_payload = request_unix(unix_path, "GET", "/healthz")
                    if status == 200 and unix_payload == '{"status":"ok"}':
                        break
                except OSError:
                    time.sleep(0.05)
            status, unix_payload = request_unix(
                unix_path,
                "POST",
                "/scan",
                json.dumps({"text": "a\u200bb"}, separators=(",", ":")),
                "application/json",
            )
            if status != 200:
                raise RuntimeError(f"unix scan status {status}: {unix_payload}")
            unix_verdict = json.loads(unix_payload)
            if unix_verdict.get("action") != "reject":
                raise RuntimeError(f"unexpected unix action: {unix_payload}")
        finally:
            unix_proc.terminate()
            try:
                unix_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                unix_proc.kill()
                unix_proc.wait()
finally:
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
PY
then
  fail "unicode-security serve smoke failed"
fi

require_dir "$dist_abs/python"
shopt -s nullglob
python_wheels=("$dist_abs"/python/unicode_python-*.whl)
python_sdists=("$dist_abs"/python/unicode_python-*.tar.gz)
shopt -u nullglob
(( ${#python_wheels[@]} > 0 )) || fail "missing Python wheel under $dist_abs/python"
(( ${#python_sdists[@]} > 0 )) || fail "missing Python source distribution under $dist_abs/python"

"$python_bin" -m pip --version >/dev/null 2>&1 \
  || fail "Python pip not found; run through nix develop .#runtime or set PYTHON to a Python with pip"
python_target="$(make_temp_dir)/python-target"
"$python_bin" -m pip install --no-index --no-deps --quiet \
  --target "$python_target" "${python_wheels[0]}" \
  || fail "Python wheel install smoke failed"
require_file "$python_target/unicode_python/data/CaseFolding.txt"
require_file "$python_target/unicode_python/data/confusables.txt"
require_file "$python_target/unicode_python/data/KnownAttackTargets.txt"
require_file "$python_target/unicode_python/data/StandardizedVariants.txt"
require_file "$python_target/unicode_python/data/emoji-variation-sequences.txt"
require_file "$python_target/unicode_python/data/UnicodeData.txt"
if ! PYTHONPATH="$python_target" "$python_bin" - <<'PY'
import unicode_python

assert unicode_python.is_valid_utf8(b"Hello")
assert unicode_python.decode_to_codepoints(b"Hi") == [72, 105]
PY
then
  fail "Python wheel import smoke failed"
fi

require_file "$dist_abs/cpp/include/unicode_cpp/utf8.hpp"
require_file "$dist_abs/cpp/include/unicode_cpp/security/policy.hpp"
require_real_file "$dist_abs/cpp/share/unicode_cpp/data/CaseFolding.txt"
require_real_file "$dist_abs/cpp/share/unicode_cpp/data/CompositionExclusions.txt"
require_real_file "$dist_abs/cpp/share/unicode_cpp/data/DerivedCoreProperties.txt"
require_real_file "$dist_abs/cpp/share/unicode_cpp/data/confusables.txt"
require_real_file "$dist_abs/cpp/share/unicode_cpp/data/KnownAttackTargets.txt"
require_real_file "$dist_abs/cpp/share/unicode_cpp/data/PropertyValueAliases.txt"
require_real_file "$dist_abs/cpp/share/unicode_cpp/data/ScriptExtensions.txt"
require_real_file "$dist_abs/cpp/share/unicode_cpp/data/Scripts.txt"
require_real_file "$dist_abs/cpp/share/unicode_cpp/data/IdentifierStatus.txt"
require_real_file "$dist_abs/cpp/share/unicode_cpp/data/UnicodeData.txt"

cpp_smoke_dir="$(make_temp_dir)"
cat > "$cpp_smoke_dir/installed_header_smoke.cpp" <<'CPP'
#include <cstdint>
#include <span>
#include <vector>

#include "unicode_cpp/security/policy.hpp"
#include "unicode_cpp/utf8.hpp"

int main() {
  using unicode_cpp::security::policy::Action;
  using unicode_cpp::security::policy::Mode;
  using unicode_cpp::security::policy::Profile;

  const std::vector<std::uint8_t> bytes = {'H', 'e', 'l', 'l', 'o'};
  const std::span<const std::uint8_t> input{bytes.data(), bytes.size()};
  if (!unicode_cpp::is_valid_utf8(input)) return 1;
  const auto verdict =
      unicode_cpp::security::policy::scan_utf8(Profile::GatewayHeader,
                                               Mode::Enforce, input);
  return verdict.action == Action::Allow ? 0 : 2;
}
CPP
cxx="${CXX:-c++}"
command -v "$cxx" >/dev/null 2>&1 || fail "C++ compiler not found: $cxx"
"$cxx" -std=c++20 -I "$dist_abs/cpp/include" \
  "$cpp_smoke_dir/installed_header_smoke.cpp" \
  -o "$cpp_smoke_dir/installed_header_smoke" \
  || fail "C++ installed-header compile smoke failed"
"$cpp_smoke_dir/installed_header_smoke" \
  || fail "C++ installed-header runtime smoke failed"

require_dir "$dist_abs/haskell"
shopt -s nullglob
haskell_sdists=("$dist_abs"/haskell/unicode-haskell-*.tar.gz)
shopt -u nullglob
(( ${#haskell_sdists[@]} > 0 )) || fail "missing Haskell source distribution under $dist_abs/haskell"
haskell_sdist_dir="$(make_temp_dir)"
tar -xzf "${haskell_sdists[0]}" -C "$haskell_sdist_dir" \
  || fail "Haskell source distribution unpack smoke failed"
mapfile -t haskell_sdist_roots < <(
  find "$haskell_sdist_dir" -mindepth 1 -maxdepth 1 -type d | sort
)
(( ${#haskell_sdist_roots[@]} == 1 )) \
  || fail "Haskell source distribution unpacked to ${#haskell_sdist_roots[@]} roots"
haskell_sdist_root="${haskell_sdist_roots[0]}"
require_file "$haskell_sdist_root/unicode-haskell.cabal"
require_file "$haskell_sdist_root/data/UCD-VERSION"
require_file "$haskell_sdist_root/data/SHA256SUMS"
require_file "$haskell_sdist_root/data/CaseFolding.txt"
require_file "$haskell_sdist_root/data/confusables.txt"
require_file "$haskell_sdist_root/data/KnownAttackTargets.txt"
require_file "$haskell_sdist_root/data/StandardizedVariants.txt"
require_file "$haskell_sdist_root/data/emoji-variation-sequences.txt"
require_file "$haskell_sdist_root/testdata/fixtures/security/policy_contract.json"
require_file "$haskell_sdist_root/testdata/fixtures/security/detectors/homoglyph_confusable.json"
require_file "$haskell_sdist_root/testdata/fixtures/security/detectors/mixed_script_admissibility.json"

require_dir "$dist_abs/jvm"
require_file "$dist_abs/jvm/src/main/java/com/unicodesecurity/Security.java"
require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/SHA256SUMS"
require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/CaseFolding.txt"
require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/confusables.txt"
require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/KnownAttackTargets.txt"
require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/StandardizedVariants.txt"
require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/emoji-variation-sequences.txt"
require_file "$dist_abs/jvm/src/test/java/com/unicodesecurity/SecurityContractTest.java"
require_file "$dist_abs/jvm/testdata/fixtures/security/policy_contract.json"
javac_bin="${JAVAC:-javac}"
java_bin="${JAVA:-java}"
command -v "$javac_bin" >/dev/null 2>&1 || fail "javac not found: $javac_bin"
command -v "$java_bin" >/dev/null 2>&1 || fail "java not found: $java_bin"
jvm_smoke_dir="$(make_temp_dir)"
cp -R "$dist_abs/jvm" "$jvm_smoke_dir/jvm"
chmod -R u+w "$jvm_smoke_dir/jvm"
(
  cd "$jvm_smoke_dir/jvm"
  PATH="$(dirname "$(command -v "$javac_bin")"):$PATH" \
    JVM_BUILD_DIR="$jvm_smoke_dir/jvm-build" \
    scripts/test.sh
) || fail "JVM packaged-module test smoke failed"

require_file "$dist_abs/go-packages.txt"
grep -Fqx 'unicode.local/ports/go/security' "$dist_abs/go-packages.txt" \
  || fail "go package evidence missing unicode.local/ports/go/security"
require_dir "$dist_abs/go"
require_file "$dist_abs/go/go.mod"
require_file "$dist_abs/go/security/policy.go"
require_file "$dist_abs/go/security/data/SHA256SUMS"
require_file "$dist_abs/go/security/data/CaseFolding.txt"
require_file "$dist_abs/go/security/data/confusables.txt"
require_file "$dist_abs/go/security/data/KnownAttackTargets.txt"
require_file "$dist_abs/go/security/data/StandardizedVariants.txt"
require_file "$dist_abs/go/security/data/emoji-variation-sequences.txt"
require_file "$dist_abs/go/security/data/UnicodeData.txt"
require_file "$dist_abs/go/security/testdata/fixtures/security/policy_contract.json"
go_bin="${GO:-go}"
command -v "$go_bin" >/dev/null 2>&1 || fail "Go not found: $go_bin"
go_smoke_dir="$(make_temp_dir)"
(
  cd "$dist_abs/go"
  export HOME="$go_smoke_dir/home"
  export GOCACHE="$go_smoke_dir/go-build"
  export GOMODCACHE="$go_smoke_dir/go-mod"
  mkdir -p "$HOME" "$GOCACHE" "$GOMODCACHE"
  "$go_bin" test ./...
) || fail "Go packaged-module test smoke failed"

require_dir "$dist_abs/typescript"
require_file "$dist_abs/typescript/package.json"
require_file "$dist_abs/typescript/src/security-core.js"
require_file "$dist_abs/typescript/src/security.js"
require_file "$dist_abs/typescript/src/edge.js"
require_file "$dist_abs/typescript/src/security.d.ts"
require_file "$dist_abs/typescript/src/edge.d.ts"
require_file "$dist_abs/typescript/src/data/SHA256SUMS"
require_file "$dist_abs/typescript/src/data/CaseFolding.txt"
require_file "$dist_abs/typescript/src/data/confusables.txt"
require_file "$dist_abs/typescript/src/data/KnownAttackTargets.txt"
require_file "$dist_abs/typescript/src/data/StandardizedVariants.txt"
require_file "$dist_abs/typescript/src/data/emoji-variation-sequences.txt"
require_file "$dist_abs/typescript/test/security.test.js"
require_file "$dist_abs/typescript/testdata/fixtures/security/policy_contract.json"
node_bin="${NODE:-node}"
command -v "$node_bin" >/dev/null 2>&1 || fail "Node.js not found: $node_bin"
(
  cd "$dist_abs/typescript"
  "$node_bin" --test test/*.test.js
) || fail "TypeScript packaged-module test smoke failed"

require_dir "$dist_abs/dotnet"
require_file "$dist_abs/dotnet/src/UnicodeSecurity/UnicodeSecurity.csproj"
require_file "$dist_abs/dotnet/src/UnicodeSecurity/Security.cs"
require_file "$dist_abs/dotnet/Data/SHA256SUMS"
require_file "$dist_abs/dotnet/Data/CaseFolding.txt"
require_file "$dist_abs/dotnet/Data/confusables.txt"
require_file "$dist_abs/dotnet/Data/KnownAttackTargets.txt"
require_file "$dist_abs/dotnet/Data/StandardizedVariants.txt"
require_file "$dist_abs/dotnet/Data/emoji-variation-sequences.txt"
require_file "$dist_abs/dotnet/test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj"
require_file "$dist_abs/dotnet/test/UnicodeSecurity.Tests/Program.cs"
require_file "$dist_abs/dotnet/testdata/fixtures/security/policy_contract.json"
mapfile -t dotnet_generated_dirs < <(
  find "$dist_abs/dotnet" -type d \( -name bin -o -name obj \) | sort
)
(( ${#dotnet_generated_dirs[@]} == 0 )) \
  || fail ".NET package contains generated build directories: ${dotnet_generated_dirs[*]}"
dotnet_bin="${DOTNET:-dotnet}"
command -v "$dotnet_bin" >/dev/null 2>&1 || fail ".NET SDK not found: $dotnet_bin"
dotnet_smoke_dir="$(make_temp_dir)"
cp -R "$dist_abs/dotnet" "$dotnet_smoke_dir/dotnet"
chmod -R u+w "$dotnet_smoke_dir/dotnet"
(
  cd "$dotnet_smoke_dir/dotnet"
  export DOTNET_CLI_HOME="$dotnet_smoke_dir/dotnet-home"
  export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
  export DOTNET_NOLOGO=1
  mkdir -p "$DOTNET_CLI_HOME"
  "$dotnet_bin" run --project test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj
) || fail ".NET packaged-module test smoke failed"

require_dir "$dist_abs/swift"
require_file "$dist_abs/swift/Package.swift"
require_file "$dist_abs/swift/scripts/test.sh"
require_file "$dist_abs/swift/Sources/UnicodeSecurity/UnicodeSecurity.swift"
require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/SHA256SUMS"
require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/CaseFolding.txt"
require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/confusables.txt"
require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/KnownAttackTargets.txt"
require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/StandardizedVariants.txt"
require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/emoji-variation-sequences.txt"
require_file "$dist_abs/swift/ContractTests/SecurityContractTests.swift"
require_file "$dist_abs/swift/ContractTests/Resources/fixtures/security/policy_contract.json"
mapfile -t swift_generated_dirs < <(
  find "$dist_abs/swift" -type d -name .build | sort
)
(( ${#swift_generated_dirs[@]} == 0 )) \
  || fail "Swift package contains generated build directories: ${swift_generated_dirs[*]}"
# Swift build+test is validated hermetically by the `.#unicode-swift`
# derivation (checkPhase runs scripts/test.sh under the pinned swift 5.10.1 from
# the nixpkgs-swift input, in a sandbox) — that reproducible, signature-cacheable
# build is the auditable trust anchor, and the nix-package check asserts its
# output tree. The ambient runtime shell carries only an unwired swift (no
# Foundation/resource-dir search path), so swiftpm cannot parse target info here;
# the packaged-swift smoke is therefore the structural assertions above, and the
# executable build+test is delegated to the derivation.
echo "== swift packaged-module: structure verified; build+test via .#unicode-swift =="

require_dir "$dist_abs/zig"
mapfile -t zig_artifacts < <(
  find "$dist_abs/zig" -type f \
    \( -name 'libunicode_security*' -o -name 'unicode_security*' \) \
    | sort
)
(( ${#zig_artifacts[@]} > 0 )) || fail "missing Zig unicode_security install artifact under $dist_abs/zig"
require_file "$dist_abs/zig/share/unicode-zig/src/security.zig"
require_file "$dist_abs/zig/share/unicode-zig/src/case_folding_data.zig"
require_file "$dist_abs/zig/share/unicode-zig/src/confusables_data.zig"
require_file "$dist_abs/zig/share/unicode-zig/src/normalization_data.zig"
require_file "$dist_abs/zig/share/unicode-zig/src/data/CaseFolding.txt"
require_file "$dist_abs/zig/share/unicode-zig/src/data/confusables.txt"
require_file "$dist_abs/zig/share/unicode-zig/src/data/KnownAttackTargets.txt"
require_file "$dist_abs/zig/share/unicode-zig/src/data/StandardizedVariants.txt"
require_file "$dist_abs/zig/share/unicode-zig/src/data/emoji-variation-sequences.txt"
require_file "$dist_abs/zig/share/unicode-zig/src/data/UnicodeData.txt"
require_file "$dist_abs/zig/share/unicode-zig/testdata/fixtures/security/policy_contract.json"
require_file "$dist_abs/zig/share/unicode-zig/testdata/fixtures/security/detectors/homoglyph_confusable.json"
require_file "$dist_abs/zig/share/unicode-zig/testdata/fixtures/security/detectors/mixed_script_admissibility.json"

echo "clean: runtime package artifacts verified at $dist_abs"
