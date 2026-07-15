#!/usr/bin/env bash
# Smoke downstream deployment consumers against packaged runtime artifacts.
# shellcheck disable=SC2030,SC2031

set -euo pipefail

cd "$(dirname "$0")/.."

dist_dir="${UNICODE_RUNTIME_DIST:-dist/runtime}"
run_gateway=1
run_python=1
run_cpp=1
run_haskell=1
run_jvm=1
run_go=1
run_typescript=1
run_dotnet=1
run_swift=1
run_zig=1
only_seen=0

usage() {
  cat <<'USAGE'
Usage: scripts/check-deployment-smokes.sh [options]

Smoke downstream deployment consumers against an existing runtime package tree.
This gate is runtime-only and never invokes Lean assurance/full-conformance
builds.

Options:
  --dist-dir DIR       Runtime package tree. Defaults to UNICODE_RUNTIME_DIST
                       or dist/runtime.
  --gateway-only       Run only the Rust gateway sidecar smoke.
  --python-only        Run only the Python wheel consumer smoke.
  --cpp-only           Run only the C++ installed-header consumer smoke.
  --haskell-only       Run only the Haskell sdist consumer smoke.
  --jvm-only           Run only the JVM source/resource consumer smoke.
  --go-only            Run only the Go reverse-proxy consumer smoke.
  --typescript-only    Run only the TypeScript edge-worker consumer smoke.
  --dotnet-only        Run only the .NET project consumer smoke.
  --swift-only         Run only the Swift package consumer smoke.
  --zig-only           Run only the Zig module/install consumer smoke.
  --no-gateway         Skip the Rust gateway sidecar smoke.
  --no-python          Skip the Python wheel consumer smoke.
  --no-cpp             Skip the C++ installed-header consumer smoke.
  --no-haskell         Skip the Haskell sdist consumer smoke.
  --no-jvm             Skip the JVM source/resource consumer smoke.
  --no-go              Skip the Go reverse-proxy consumer smoke.
  --no-typescript      Skip the TypeScript edge-worker consumer smoke.
  --no-dotnet          Skip the .NET project consumer smoke.
  --no-swift           Skip the Swift package consumer smoke.
  --no-zig             Skip the Zig module/install consumer smoke.
  -h, --help           Show this help.

Environment:
  CABAL=cabal          Cabal tool used for the Haskell consumer smoke.
  CXX=c++              C++ compiler used for the C++ consumer smoke.
  DOTNET=dotnet        .NET SDK used for the .NET consumer smoke.
  GO=go                Go tool used for the Go consumer smoke.
  JAVA=java            Java runtime used for the JVM consumer smoke.
  JAVAC=javac          Java compiler used for the JVM consumer smoke.
  NODE=node            Node.js tool used for the TypeScript edge smoke.
  PYTHON=python        Python tool used for the gateway HTTP smoke harness.
  SWIFT=swift          Swift tool used for the SwiftPM consumer smoke.
  ZIG=zig              Zig tool used for the Zig consumer smoke.
USAGE
}

fail() {
  echo "FATAL: $*" >&2
  exit 1
}

enable_only() {
  if [[ "$only_seen" -eq 0 ]]; then
    run_gateway=0
    run_python=0
    run_cpp=0
    run_haskell=0
    run_jvm=0
    run_go=0
    run_typescript=0
    run_dotnet=0
    run_swift=0
    run_zig=0
    only_seen=1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist-dir)
      [[ $# -ge 2 ]] || fail "--dist-dir requires a value"
      dist_dir="$2"
      shift
      ;;
    --gateway-only)
      enable_only
      run_gateway=1
      ;;
    --python-only)
      enable_only
      run_python=1
      ;;
    --cpp-only)
      enable_only
      run_cpp=1
      ;;
    --haskell-only)
      enable_only
      run_haskell=1
      ;;
    --jvm-only)
      enable_only
      run_jvm=1
      ;;
    --go-only)
      enable_only
      run_go=1
      ;;
    --typescript-only)
      enable_only
      run_typescript=1
      ;;
    --dotnet-only)
      enable_only
      run_dotnet=1
      ;;
    --swift-only)
      enable_only
      run_swift=1
      ;;
    --zig-only)
      enable_only
      run_zig=1
      ;;
    --no-gateway)
      run_gateway=0
      ;;
    --no-python)
      run_python=0
      ;;
    --no-cpp)
      run_cpp=0
      ;;
    --no-haskell)
      run_haskell=0
      ;;
    --no-jvm)
      run_jvm=0
      ;;
    --no-go)
      run_go=0
      ;;
    --no-typescript)
      run_typescript=0
      ;;
    --no-dotnet)
      run_dotnet=0
      ;;
    --no-swift)
      run_swift=0
      ;;
    --no-zig)
      run_zig=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

case "$dist_dir" in
  /*) dist_abs="$dist_dir" ;;
  *) dist_abs="$PWD/$dist_dir" ;;
esac

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

configure_swift_runtime_libs() {
  local swift_bin="$1"
  local tool
  local tool_path
  local root
  local swift_lib_dirs
  local closure_roots=()

  if ! command -v nix-store >/dev/null 2>&1; then
    return 0
  fi

  for tool in "$swift_bin" swift-run swift-test swift-package; do
    if command -v "$tool" >/dev/null 2>&1; then
      tool_path="$(readlink -f "$(command -v "$tool")")"
      while IFS= read -r root; do
        closure_roots+=("$root")
      done < <(nix-store -qR "$tool_path" 2>/dev/null || true)
    fi
  done

  if [[ "${#closure_roots[@]}" -eq 0 ]]; then
    return 0
  fi

  swift_lib_dirs="$(
    find "${closure_roots[@]}" -type f \
      \( -name 'libdispatch.so' -o -name 'libFoundation.so' \) \
      -printf '%h\n' 2>/dev/null | sort -u | paste -sd:
  )"
  if [[ -n "$swift_lib_dirs" ]]; then
    export LD_LIBRARY_PATH="$swift_lib_dirs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  fi
}

require_dir "$dist_abs"
require_file "$dist_abs/MANIFEST.txt"
grep -Fqx 'lean: not built' "$dist_abs/MANIFEST.txt" \
  || fail "runtime package manifest must state that Lean was not built"

if [[ "$run_gateway" -eq 1 ]]; then
  echo "== gateway sidecar deployment smoke =="
  rust_bin="$dist_abs/rust/bin/unicode-security"
  require_executable "$rust_bin"

  python_bin="${PYTHON:-python}"
  command -v "$python_bin" >/dev/null 2>&1 || fail "Python not found: $python_bin"
  gateway_log="$(make_temp_dir)/gateway.log"

  if ! "$python_bin" - "$rust_bin" "$gateway_log" <<'PY'
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

bin_path = sys.argv[1]
log_path = sys.argv[2]
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
host, port = sock.getsockname()
sock.close()

log = open(log_path, "wb")
proc = subprocess.Popen(
    [
        bin_path,
        "serve",
        "--listen",
        f"{host}:{port}",
        "--profile",
        "gateway-header",
        "--mode",
        "enforce",
        "--max-request-bytes",
        "4096",
        "--max-batch-records",
        "2",
        "--log-requests",
    ],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=log,
)


def request(method, path, body=None, content_type=None):
    headers = {}
    if content_type is not None:
        headers["Content-Type"] = content_type
    conn = http.client.HTTPConnection(host, port, timeout=2)
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    payload = response.read().decode("utf-8")
    conn.close()
    return response.status, payload


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


try:
    deadline = time.time() + 5
    while True:
        if time.time() > deadline:
            raise RuntimeError("server did not become ready")
        try:
            status, payload = request("GET", "/healthz")
            if status == 200 and payload == '{"status":"ok"}':
                break
        except OSError:
            time.sleep(0.05)

    status, payload = request(
        "POST",
        "/scan",
        json.dumps({"text": "Hello"}, separators=(",", ":")),
        "application/json",
    )
    if status != 200:
        raise RuntimeError(f"allow scan status {status}: {payload}")
    verdict = json.loads(payload)
    if verdict.get("action") != "allow":
        raise RuntimeError(f"safe scan was not allowed: {payload}")

    status, payload = request(
        "POST",
        "/scan",
        json.dumps({"text": "pay\u200bload"}, separators=(",", ":")),
        "application/json",
    )
    if status != 200:
        raise RuntimeError(f"reject scan status {status}: {payload}")
    verdict = json.loads(payload)
    codes = {finding.get("code") for finding in verdict.get("findings", [])}
    if verdict.get("action") != "reject":
        raise RuntimeError(f"zero-width scan was not rejected: {payload}")
    if "unicode.security.C.zero-width-payload.BareZeroWidth" not in codes:
        raise RuntimeError(f"zero-width reason code missing: {payload}")

    batch_body = "\n".join(
        [
            json.dumps({"id": "safe", "text": "Hello"}, separators=(",", ":")),
            json.dumps({"id": "blocked", "text": "pay\u200bload"}, separators=(",", ":")),
            "",
        ]
    )
    status, payload = request("POST", "/batch", batch_body, "application/x-ndjson")
    if status != 200:
        raise RuntimeError(f"batch status {status}: {payload}")
    rows = [json.loads(line) for line in payload.splitlines() if line]
    if len(rows) != 2:
        raise RuntimeError(f"expected two batch rows: {payload}")
    if rows[0].get("id") != "safe" or rows[0].get("action") != "allow":
        raise RuntimeError(f"unexpected safe batch row: {payload}")
    if rows[1].get("id") != "blocked" or rows[1].get("action") != "reject":
        raise RuntimeError(f"unexpected blocked batch row: {payload}")

    status, payload = request("GET", "/metrics")
    if status != 200:
        raise RuntimeError(f"metrics status {status}: {payload}")
    metrics = json.loads(payload)
    if metrics.get("scan_requests_total") != 2:
        raise RuntimeError(f"unexpected scan count: {payload}")
    if metrics.get("batch_requests_total") != 1:
        raise RuntimeError(f"unexpected batch count: {payload}")
    if metrics.get("actions", {}).get("allow") != 2:
        raise RuntimeError(f"unexpected allow count: {payload}")
    if metrics.get("actions", {}).get("reject") != 2:
        raise RuntimeError(f"unexpected reject count: {payload}")
    latency = metrics.get("latency_ms", {})
    if latency.get("scan", {}).get("count") != 2:
        raise RuntimeError(f"unexpected scan latency count: {payload}")
    if latency.get("batch", {}).get("count") != 1:
        raise RuntimeError(f"unexpected batch latency count: {payload}")
    if "le_1" not in latency.get("batch", {}).get("buckets", {}):
        raise RuntimeError(f"missing batch latency buckets: {payload}")

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
            json.dumps({"id": "safe", "text": "Hello"}, separators=(",", ":"))
            + "\n"
            + json.dumps({"id": "blocked", "text": "pay\u200bload"}, separators=(",", ":"))
            + "\n"
        ),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    framed_rows = [json.loads(line) for line in framed.stdout.splitlines() if line]
    if len(framed_rows) != 2:
        raise RuntimeError(f"expected two stdio-jsonl rows: {framed.stdout}")
    if framed_rows[0].get("id") != "safe" or framed_rows[0].get("action") != "allow":
        raise RuntimeError(f"unexpected stdio-jsonl safe row: {framed.stdout}")
    if framed_rows[1].get("id") != "blocked" or framed_rows[1].get("action") != "reject":
        raise RuntimeError(f"unexpected stdio-jsonl blocked row: {framed.stdout}")

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
                json.dumps({"text": "pay\u200bload"}, separators=(",", ":")),
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
    log.close()

with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
    logs = handle.read()
if "pay\u200bload" in logs or "Hello" in logs:
    raise RuntimeError("request log included raw payload text")
if '"event":"request"' not in logs:
    raise RuntimeError("request log did not include request events")
PY
  then
    fail "gateway sidecar deployment smoke failed"
  fi
fi

if [[ "$run_python" -eq 1 ]]; then
  echo "== Python wheel consumer smoke =="
  require_dir "$dist_abs/python"
  python_bin="${PYTHON:-python}"
  command -v "$python_bin" >/dev/null 2>&1 || fail "Python not found: $python_bin"
  shopt -s nullglob
  python_wheels=("$dist_abs"/python/unicode_python-*.whl)
  shopt -u nullglob
  (( ${#python_wheels[@]} > 0 )) || fail "missing Python wheel under $dist_abs/python"

  python_target="$(make_temp_dir)/python-target"
  "$python_bin" -m pip install --no-index --no-deps --quiet \
    --target "$python_target" "${python_wheels[0]}" \
    || fail "Python wheel install failed"
  if ! PYTHONPATH="$python_target" "$python_bin" - <<'PY'
from unicode_python.security.policy import (
    Action,
    Mode,
    Profile,
    scan_utf8,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def has_code(verdict, code: str) -> bool:
    return any(finding.code == code for finding in verdict.findings)


safe = scan_utf8(Profile.GATEWAY_HEADER, Mode.ENFORCE, b"Hello")
require(safe.action is Action.ALLOW, "safe gateway text was not allowed")

blocked = scan_utf8(Profile.SOURCE_CODE, Mode.STRICT, b"a\xe2\x80\x8bb")
require(blocked.action is Action.REJECT, "zero-width source text was not rejected")
require(
    has_code(blocked, "unicode.security.C.zero-width-payload.BareZeroWidth"),
    "zero-width reason code missing",
)

malformed = scan_utf8(Profile.GATEWAY_HEADER, Mode.STRICT, bytes([0xC0, 0xAF]))
require(malformed.action is Action.REJECT, "malformed UTF-8 was not rejected")
require(
    has_code(malformed, "unicode.security.C.malformed-utf8.InvalidStartByte"),
    "malformed UTF-8 reason code missing",
)
PY
  then
    fail "Python wheel consumer smoke failed"
  fi
fi

if [[ "$run_cpp" -eq 1 ]]; then
  echo "== C++ installed-header consumer smoke =="
  require_file "$dist_abs/cpp/include/unicode_cpp/security/policy.hpp"
  require_file "$dist_abs/cpp/include/unicode_cpp/utf8.hpp"
  require_file "$dist_abs/cpp/share/unicode_cpp/data/CaseFolding.txt"
  require_file "$dist_abs/cpp/share/unicode_cpp/data/CompositionExclusions.txt"
  require_file "$dist_abs/cpp/share/unicode_cpp/data/DerivedCoreProperties.txt"
  require_file "$dist_abs/cpp/share/unicode_cpp/data/confusables.txt"
  require_file "$dist_abs/cpp/share/unicode_cpp/data/KnownAttackTargets.txt"
  require_file "$dist_abs/cpp/share/unicode_cpp/data/IdentifierStatus.txt"
  require_file "$dist_abs/cpp/share/unicode_cpp/data/PropertyValueAliases.txt"
  require_file "$dist_abs/cpp/share/unicode_cpp/data/ScriptExtensions.txt"
  require_file "$dist_abs/cpp/share/unicode_cpp/data/Scripts.txt"
  require_file "$dist_abs/cpp/share/unicode_cpp/data/UnicodeData.txt"

  cxx="${CXX:-c++}"
  command -v "$cxx" >/dev/null 2>&1 || fail "C++ compiler not found: $cxx"
  cpp_smoke_dir="$(make_temp_dir)"
  cat > "$cpp_smoke_dir/deployment_smoke.cpp" <<'CPP'
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include "unicode_cpp/security/policy.hpp"

namespace policy = unicode_cpp::security::policy;

bool has_code(const policy::Verdict& verdict, std::string_view code) {
  for (const auto& finding : verdict.findings) {
    if (finding.code == code) return true;
  }
  return false;
}

int require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    return 1;
  }
  return 0;
}

int main() {
  const std::vector<std::uint8_t> safe_bytes = {'H', 'e', 'l', 'l', 'o'};
  const auto safe = policy::scan_utf8(
      policy::Profile::GatewayHeader,
      policy::Mode::Enforce,
      std::span<const std::uint8_t>(safe_bytes.data(), safe_bytes.size()));
  if (require(safe.action == policy::Action::Allow,
              "safe gateway text was not allowed")) return 1;

  const std::vector<std::uint8_t> blocked_bytes = {
      'a', 0xe2, 0x80, 0x8b, 'b'};
  const auto blocked = policy::scan_utf8(
      policy::Profile::SourceCode,
      policy::Mode::Strict,
      std::span<const std::uint8_t>(blocked_bytes.data(),
                                    blocked_bytes.size()));
  if (require(blocked.action == policy::Action::Reject,
              "zero-width source text was not rejected")) return 1;
  if (require(has_code(blocked,
                       "unicode.security.C.zero-width-payload.BareZeroWidth"),
              "zero-width reason code missing")) return 1;

  const std::vector<std::uint8_t> malformed_bytes = {0xc0, 0xaf};
  const auto malformed = policy::scan_utf8(
      policy::Profile::GatewayHeader,
      policy::Mode::Strict,
      std::span<const std::uint8_t>(malformed_bytes.data(),
                                    malformed_bytes.size()));
  if (require(malformed.action == policy::Action::Reject,
              "malformed UTF-8 was not rejected")) return 1;
  if (require(has_code(malformed,
                       "unicode.security.C.malformed-utf8.InvalidStartByte"),
              "malformed UTF-8 reason code missing")) return 1;
}
CPP
  "$cxx" -std=c++20 -I "$dist_abs/cpp/include" \
    "$cpp_smoke_dir/deployment_smoke.cpp" \
    -o "$cpp_smoke_dir/deployment_smoke" \
    || fail "C++ installed-header compile failed"
  "$cpp_smoke_dir/deployment_smoke" \
    || fail "C++ installed-header consumer smoke failed"
fi

if [[ "$run_haskell" -eq 1 ]]; then
  echo "== Haskell sdist consumer smoke =="
  require_dir "$dist_abs/haskell"
  cabal_bin="${CABAL:-cabal}"
  command -v "$cabal_bin" >/dev/null 2>&1 || fail "Cabal not found: $cabal_bin"
  shopt -s nullglob
  haskell_sdists=("$dist_abs"/haskell/unicode-haskell-*.tar.gz)
  shopt -u nullglob
  (( ${#haskell_sdists[@]} > 0 )) || fail "missing Haskell source distribution under $dist_abs/haskell"

  haskell_smoke_dir="$(make_temp_dir)"
  tar -xzf "${haskell_sdists[0]}" -C "$haskell_smoke_dir" \
    || fail "Haskell source distribution unpack failed"
  mapfile -t haskell_roots < <(
    find "$haskell_smoke_dir" -mindepth 1 -maxdepth 1 -type d -name 'unicode-haskell-*' | sort
  )
  (( ${#haskell_roots[@]} == 1 )) \
    || fail "Haskell source distribution unpacked to ${#haskell_roots[@]} roots"
  require_file "${haskell_roots[0]}/data/CaseFolding.txt"
  require_file "${haskell_roots[0]}/data/confusables.txt"
  require_file "${haskell_roots[0]}/data/KnownAttackTargets.txt"
  require_file "${haskell_roots[0]}/data/StandardizedVariants.txt"
  require_file "${haskell_roots[0]}/data/emoji-variation-sequences.txt"
  mkdir -p "$haskell_smoke_dir/smoke/app"
  cat > "$haskell_smoke_dir/cabal.project" <<CABAL_PROJECT
packages:
  ${haskell_roots[0]}
  ./smoke
CABAL_PROJECT
  cat > "$haskell_smoke_dir/smoke/unicode-deployment-smoke.cabal" <<'CABAL'
cabal-version: 3.0
name: unicode-deployment-smoke
version: 0.1.0.0
build-type: Simple

executable unicode-deployment-smoke
  main-is: Main.hs
  hs-source-dirs: app
  default-language: GHC2021
  ghc-options: -Wall -Werror
  build-depends:
      base
    , bytestring
    , unicode-haskell
CABAL
  cat > "$haskell_smoke_dir/smoke/app/Main.hs" <<'HS'
module Main (main) where

import qualified Data.ByteString as BS
import Unicode.Security.Policy

require :: Bool -> String -> IO ()
require True _ = pure ()
require False message = fail message

hasCode :: Verdict -> String -> Bool
hasCode verdict code =
  any ((== code) . findingCode) (verdictFindings verdict)

main :: IO ()
main = do
  let safe =
        scanUtf8
          ProfileGatewayHeader
          ModeEnforce
          (BS.pack [72, 101, 108, 108, 111])
  require (verdictAction safe == ActionAllow) "safe gateway text was not allowed"

  let blocked =
        scanUtf8
          ProfileSourceCode
          ModeStrict
          (BS.pack [97, 0xe2, 0x80, 0x8b, 98])
  require (verdictAction blocked == ActionReject) "zero-width source text was not rejected"
  require
    (hasCode blocked "unicode.security.C.zero-width-payload.BareZeroWidth")
    "zero-width reason code missing"

  let malformed =
        scanUtf8
          ProfileGatewayHeader
          ModeStrict
          (BS.pack [0xc0, 0xaf])
  require (verdictAction malformed == ActionReject) "malformed UTF-8 was not rejected"
  require
    (hasCode malformed "unicode.security.C.malformed-utf8.InvalidStartByte")
    "malformed UTF-8 reason code missing"
HS
  (
    cd "$haskell_smoke_dir"
    export HOME="$haskell_smoke_dir/home"
    export CABAL_DIR="$haskell_smoke_dir/cabal"
    mkdir -p "$HOME" "$CABAL_DIR"
    "$cabal_bin" v2-run --offline unicode-deployment-smoke
  ) || fail "Haskell sdist consumer smoke failed"
fi

if [[ "$run_jvm" -eq 1 ]]; then
  echo "== JVM package consumer smoke =="
  require_file "$dist_abs/jvm/src/main/java/com/unicodesecurity/Security.java"
  require_dir "$dist_abs/jvm/src/main/resources"
  require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/CaseFolding.txt"
  require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/confusables.txt"
  require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/KnownAttackTargets.txt"
  require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/StandardizedVariants.txt"
  require_file "$dist_abs/jvm/src/main/resources/com/unicodesecurity/data/emoji-variation-sequences.txt"

  javac_bin="${JAVAC:-javac}"
  java_bin="${JAVA:-java}"
  command -v "$javac_bin" >/dev/null 2>&1 || fail "javac not found: $javac_bin"
  command -v "$java_bin" >/dev/null 2>&1 || fail "java not found: $java_bin"
  jvm_smoke_dir="$(make_temp_dir)"
  mkdir -p "$jvm_smoke_dir/classes"
  cat > "$jvm_smoke_dir/DeploymentSmoke.java" <<'JAVA'
import com.unicodesecurity.Security;

public final class DeploymentSmoke {
  private static void require(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }

  private static boolean hasCode(Security.Verdict verdict, String code) {
    for (Security.Finding finding : verdict.findings()) {
      if (finding.code().equals(code)) return true;
    }
    return false;
  }

  public static void main(String[] args) {
    Security.Verdict safe = Security.scanUtf8(
        Security.Profile.GATEWAY_HEADER,
        Security.Mode.ENFORCE,
        new byte[] {72, 101, 108, 108, 111});
    require(safe.action().equals(Security.Action.ALLOW), "safe gateway text was not allowed");

    Security.Verdict blocked = Security.scanUtf8(
        Security.Profile.SOURCE_CODE,
        Security.Mode.STRICT,
        new byte[] {97, (byte) 0xe2, (byte) 0x80, (byte) 0x8b, 98});
    require(blocked.action().equals(Security.Action.REJECT), "zero-width source text was not rejected");
    require(
        hasCode(blocked, "unicode.security.C.zero-width-payload.BareZeroWidth"),
        "zero-width reason code missing");

    Security.Verdict malformed = Security.scanUtf8(
        Security.Profile.GATEWAY_HEADER,
        Security.Mode.STRICT,
        new byte[] {(byte) 0xc0, (byte) 0xaf});
    require(malformed.action().equals(Security.Action.REJECT), "malformed UTF-8 was not rejected");
    require(
        hasCode(malformed, "unicode.security.C.malformed-utf8.InvalidStartByte"),
        "malformed UTF-8 reason code missing");
  }
}
JAVA
  "$javac_bin" -d "$jvm_smoke_dir/classes" \
    "$dist_abs/jvm/src/main/java/com/unicodesecurity/Security.java" \
    "$jvm_smoke_dir/DeploymentSmoke.java" \
    || fail "JVM consumer compile failed"
  "$java_bin" -cp "$jvm_smoke_dir/classes:$dist_abs/jvm/src/main/resources" DeploymentSmoke \
    || fail "JVM package consumer smoke failed"
fi

if [[ "$run_go" -eq 1 ]]; then
  echo "== Go reverse-proxy consumer smoke =="
  require_dir "$dist_abs/go"
  require_file "$dist_abs/go/go.mod"
  require_file "$dist_abs/go/security/policy.go"
  require_file "$dist_abs/go/security/utf8_policy.go"
  require_file "$dist_abs/go/security/data/CaseFolding.txt"
  require_file "$dist_abs/go/security/data/confusables.txt"
  require_file "$dist_abs/go/security/data/KnownAttackTargets.txt"
  require_file "$dist_abs/go/security/data/StandardizedVariants.txt"
  require_file "$dist_abs/go/security/data/emoji-variation-sequences.txt"
  require_file "$dist_abs/go/security/data/UnicodeData.txt"

  go_bin="${GO:-go}"
  command -v "$go_bin" >/dev/null 2>&1 || fail "Go not found: $go_bin"
  go_smoke_dir="$(make_temp_dir)"

  cat > "$go_smoke_dir/go.mod" <<GO_MOD
module unicode-deployment-smoke

go 1.23

require unicode.local/ports/go v0.0.0

replace unicode.local/ports/go => $dist_abs/go
GO_MOD
  cat > "$go_smoke_dir/main.go" <<'GO'
package main

import (
	"fmt"
	"os"

	"unicode.local/ports/go/security"
)

func require(ok bool, message string) {
	if !ok {
		fmt.Fprintln(os.Stderr, message)
		os.Exit(1)
	}
}

func hasCode(verdict security.Verdict, code string) bool {
	for _, finding := range verdict.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func main() {
	safe := security.ScanUTF8(
		security.ProfileGatewayHeader,
		security.ModeEnforce,
		[]byte("Hello"),
	)
	require(safe.Action == security.ActionAllow, "safe gateway text was not allowed")

	blocked := security.ScanUTF8(
		security.ProfileSourceCode,
		security.ModeStrict,
		[]byte{'a', 0xe2, 0x80, 0x8b, 'b'},
	)
	require(blocked.Action == security.ActionReject, "zero-width source text was not rejected")
	require(
		hasCode(blocked, "unicode.security.C.zero-width-payload.BareZeroWidth"),
		"zero-width reason code missing",
	)

	malformed := security.ScanUTF8(
		security.ProfileGatewayHeader,
		security.ModeStrict,
		[]byte{0xc0, 0xaf},
	)
	require(malformed.Action == security.ActionReject, "malformed UTF-8 was not rejected")
	require(
		hasCode(malformed, "unicode.security.C.malformed-utf8.InvalidStartByte"),
		"malformed UTF-8 reason code missing",
	)
}
GO
  (
    cd "$go_smoke_dir"
    export HOME="$go_smoke_dir/home"
    export GOCACHE="$go_smoke_dir/go-build"
    export GOMODCACHE="$go_smoke_dir/go-mod"
    mkdir -p "$HOME" "$GOCACHE" "$GOMODCACHE"
    "$go_bin" run .
  ) || fail "Go reverse-proxy consumer smoke failed"
fi

if [[ "$run_typescript" -eq 1 ]]; then
  echo "== TypeScript edge-worker consumer smoke =="
  require_dir "$dist_abs/typescript"
  require_file "$dist_abs/typescript/package.json"
  require_file "$dist_abs/typescript/src/edge.js"
  require_file "$dist_abs/typescript/src/data/CaseFolding.txt"
  require_file "$dist_abs/typescript/src/data/confusables.txt"
  require_file "$dist_abs/typescript/src/data/KnownAttackTargets.txt"
  require_file "$dist_abs/typescript/src/data/StandardizedVariants.txt"
  require_file "$dist_abs/typescript/src/data/emoji-variation-sequences.txt"

  node_bin="${NODE:-node}"
  command -v "$node_bin" >/dev/null 2>&1 || fail "Node.js not found: $node_bin"
  ts_smoke_dir="$(make_temp_dir)"
  mkdir -p "$ts_smoke_dir/node_modules/@unicode-security"
  ln -s "$dist_abs/typescript" "$ts_smoke_dir/node_modules/@unicode-security/runtime"

  cat > "$ts_smoke_dir/edge-smoke.mjs" <<'JS'
import { readFileSync } from "node:fs";
import { strict as assert } from "node:assert";
import { instantiateSecurity } from "@unicode-security/runtime/edge";

const dataDir = process.env.UNICODE_TYPESCRIPT_DATA_DIR;
const security = await instantiateSecurity({
  data: {
    confusables: readFileSync(`${dataDir}/confusables.txt`, "utf8"),
    caseFolding: readFileSync(`${dataDir}/CaseFolding.txt`, "utf8"),
    knownAttackTargets: readFileSync(`${dataDir}/KnownAttackTargets.txt`, "utf8"),
    standardizedVariants: readFileSync(`${dataDir}/StandardizedVariants.txt`, "utf8"),
    emojiVariationSequences: readFileSync(`${dataDir}/emoji-variation-sequences.txt`, "utf8"),
  },
});

const safe = security.scanUtf8("gateway-header", "enforce", [72, 101, 108, 108, 111]);
assert.equal(safe.action, "allow");

const blocked = security.scanUtf8("source-code", "strict", [97, 0xe2, 0x80, 0x8b, 98]);
assert.equal(blocked.action, "reject");
assert.ok(
  blocked.findings.some(
    (finding) => finding.code === "unicode.security.C.zero-width-payload.BareZeroWidth",
  ),
);

const malformed = security.scanUtf8("gateway-header", "strict", [0xc0, 0xaf]);
assert.equal(malformed.action, "reject");
assert.ok(
  malformed.findings.some(
    (finding) => finding.code === "unicode.security.C.malformed-utf8.InvalidStartByte",
  ),
);
JS
  (
    cd "$ts_smoke_dir"
    UNICODE_TYPESCRIPT_DATA_DIR="$dist_abs/typescript/src/data" "$node_bin" edge-smoke.mjs
  ) || fail "TypeScript edge-worker consumer smoke failed"
fi

if [[ "$run_dotnet" -eq 1 ]]; then
  echo "== .NET project consumer smoke =="
  require_file "$dist_abs/dotnet/src/UnicodeSecurity/UnicodeSecurity.csproj"
  require_file "$dist_abs/dotnet/src/UnicodeSecurity/Security.cs"
  require_file "$dist_abs/dotnet/Data/CaseFolding.txt"
  require_file "$dist_abs/dotnet/Data/confusables.txt"
  require_file "$dist_abs/dotnet/Data/KnownAttackTargets.txt"
  require_file "$dist_abs/dotnet/Data/StandardizedVariants.txt"
  require_file "$dist_abs/dotnet/Data/emoji-variation-sequences.txt"

  dotnet_bin="${DOTNET:-dotnet}"
  command -v "$dotnet_bin" >/dev/null 2>&1 || fail ".NET SDK not found: $dotnet_bin"
  dotnet_smoke_dir="$(make_temp_dir)"
  cat > "$dotnet_smoke_dir/UnicodeDeploymentSmoke.csproj" <<DOTNET_CSPROJ
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="$dist_abs/dotnet/src/UnicodeSecurity/UnicodeSecurity.csproj" />
  </ItemGroup>
</Project>
DOTNET_CSPROJ
  cat > "$dotnet_smoke_dir/Program.cs" <<'CS'
using UnicodeSecurity;

static void Require(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

static bool HasCode(Security.Verdict verdict, string code) =>
    verdict.Findings.Any(finding => finding.Code == code);

var safe = Security.ScanUtf8(
    Security.Profile.GatewayHeader,
    Security.Mode.Enforce,
    "Hello"u8.ToArray());
Require(safe.Action == Security.Action.Allow, "safe gateway text was not allowed");

var blocked = Security.ScanUtf8(
    Security.Profile.SourceCode,
    Security.Mode.Strict,
    new byte[] { 97, 0xe2, 0x80, 0x8b, 98 });
Require(blocked.Action == Security.Action.Reject, "zero-width source text was not rejected");
Require(
    HasCode(blocked, "unicode.security.C.zero-width-payload.BareZeroWidth"),
    "zero-width reason code missing");

var malformed = Security.ScanUtf8(
    Security.Profile.GatewayHeader,
    Security.Mode.Strict,
    new byte[] { 0xc0, 0xaf });
Require(malformed.Action == Security.Action.Reject, "malformed UTF-8 was not rejected");
Require(
    HasCode(malformed, "unicode.security.C.malformed-utf8.InvalidStartByte"),
    "malformed UTF-8 reason code missing");
CS
  (
    cd "$dotnet_smoke_dir"
    export DOTNET_CLI_HOME="$dotnet_smoke_dir/dotnet-home"
    export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
    export DOTNET_NOLOGO=1
    mkdir -p "$DOTNET_CLI_HOME"
    "$dotnet_bin" run --project UnicodeDeploymentSmoke.csproj
  ) || fail ".NET project consumer smoke failed"
fi

if [[ "$run_swift" -eq 1 ]]; then
  echo "== Swift package consumer smoke =="
  require_dir "$dist_abs/swift"
  require_file "$dist_abs/swift/Package.swift"
  require_file "$dist_abs/swift/Sources/UnicodeSecurity/UnicodeSecurity.swift"
  require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/CaseFolding.txt"
  require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/confusables.txt"
  require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/KnownAttackTargets.txt"
  require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/StandardizedVariants.txt"
  require_file "$dist_abs/swift/Sources/UnicodeSecurity/Resources/Data/emoji-variation-sequences.txt"

  swift_bin="${SWIFT:-swift}"
  command -v "$swift_bin" >/dev/null 2>&1 || fail "Swift not found: $swift_bin"
  configure_swift_runtime_libs "$swift_bin"
  swift_smoke_dir="$(make_temp_dir)"

  mkdir -p "$swift_smoke_dir/Sources/UnicodeDeploymentSmoke"
  cat > "$swift_smoke_dir/Package.swift" <<SWIFT_PACKAGE
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "UnicodeDeploymentSmoke",
    dependencies: [
        .package(name: "unicode-security-swift", path: "$dist_abs/swift"),
    ],
    targets: [
        .executableTarget(
            name: "UnicodeDeploymentSmoke",
            dependencies: [
                .product(name: "UnicodeSecurity", package: "unicode-security-swift"),
            ]
        ),
    ]
)
SWIFT_PACKAGE
  cat > "$swift_smoke_dir/Sources/UnicodeDeploymentSmoke/main.swift" <<'SWIFT'
import Foundation
import UnicodeSecurity

func require(_ condition: Bool, _ message: String) {
    if !condition {
        FileHandle.standardError.write(Data((message + "\n").utf8))
        exit(1)
    }
}

func hasCode(_ verdict: Verdict, _ code: String) -> Bool {
    verdict.findings.contains { finding in finding.code == code }
}

let safe = scanUtf8(
    profile: Profile.gatewayHeader,
    mode: Mode.enforce,
    input: Array("Hello".utf8)
)
require(safe.action == Action.allow, "safe gateway text was not allowed")

let blocked = scanUtf8(
    profile: Profile.sourceCode,
    mode: Mode.strict,
    input: [97, 0xe2, 0x80, 0x8b, 98]
)
require(blocked.action == Action.reject, "zero-width source text was not rejected")
require(
    hasCode(blocked, "unicode.security.C.zero-width-payload.BareZeroWidth"),
    "zero-width reason code missing"
)

let malformed = scanUtf8(
    profile: Profile.gatewayHeader,
    mode: Mode.strict,
    input: [0xc0, 0xaf]
)
require(malformed.action == Action.reject, "malformed UTF-8 was not rejected")
require(
    hasCode(malformed, "unicode.security.C.malformed-utf8.InvalidStartByte"),
    "malformed UTF-8 reason code missing"
)
SWIFT
  (
    cd "$swift_smoke_dir"
    "$swift_bin" run UnicodeDeploymentSmoke
  ) || fail "Swift package consumer smoke failed"
fi

if [[ "$run_zig" -eq 1 ]]; then
  echo "== Zig module consumer smoke =="
  require_file "$dist_abs/zig/lib/libunicode_security.a"
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

  zig_bin="${ZIG:-zig}"
  command -v "$zig_bin" >/dev/null 2>&1 || fail "Zig not found: $zig_bin"
  zig_smoke_dir="$(make_temp_dir)"
  mkdir -p "$zig_smoke_dir/src"
  cat > "$zig_smoke_dir/build.zig" <<ZIG_BUILD
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const unicode_security = b.addModule("unicode_security", .{
        .root_source_file = .{ .cwd_relative = "$dist_abs/zig/share/unicode-zig/src/security.zig" },
        .target = target,
        .optimize = optimize,
    });

    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_module.addImport("unicode_security", unicode_security);
    const exe = b.addExecutable(.{
        .name = "unicode-deployment-smoke",
        .root_module = exe_module,
    });

    const run = b.addRunArtifact(exe);
    const smoke = b.step("smoke", "Run deployment smoke");
    smoke.dependOn(&run.step);
}
ZIG_BUILD
  cat > "$zig_smoke_dir/src/main.zig" <<'ZIG'
const std = @import("std");
const security = @import("unicode_security");

fn require(condition: bool, message: []const u8) !void {
    if (!condition) {
        std.debug.print("{s}\n", .{message});
        return error.SmokeFailed;
    }
}

pub fn main() !void {
    var decoded_buffer: [64]u32 = undefined;

    const safe = security.scanUtf8(
        .gateway_header,
        .enforce,
        "Hello",
        decoded_buffer[0..],
    );
    try require(safe.action == .allow, "safe gateway text was not allowed");

    const blocked = security.scanUtf8(
        .source_code,
        .strict,
        &[_]u8{ 97, 0xe2, 0x80, 0x8b, 98 },
        decoded_buffer[0..],
    );
    try require(blocked.action == .reject, "zero-width source text was not rejected");
    try require(
        blocked.findings.containsCode("unicode.security.C.zero-width-payload.BareZeroWidth"),
        "zero-width reason code missing",
    );

    const malformed = security.scanUtf8(
        .gateway_header,
        .strict,
        &[_]u8{ 0xc0, 0xaf },
        decoded_buffer[0..],
    );
    try require(malformed.action == .reject, "malformed UTF-8 was not rejected");
    try require(
        malformed.findings.containsCode("unicode.security.C.malformed-utf8.InvalidStartByte"),
        "malformed UTF-8 reason code missing",
    );
}
ZIG
  (
    cd "$zig_smoke_dir"
    export ZIG_GLOBAL_CACHE_DIR="$zig_smoke_dir/zig-global"
    mkdir -p "$ZIG_GLOBAL_CACHE_DIR"
    "$zig_bin" build smoke
  ) || fail "Zig module consumer smoke failed"
fi

echo "clean: deployment smokes passed for $dist_abs"
