#!/usr/bin/env python3
"""Generate fixtures/security/differential_corpus.json from the Rust reference.

ROADMAP §7 asks for a differential runner covering all sixteen ports. The
existing runner under `ports/{rust,python,cpp}/tests/diff_runner.*` compares
three ports on one detector family, because each port that joins it needs its
own corpus parser, PRNG and emitter written in its own language.

This takes the other route. Every port already runs
`fixtures/security/verdict_contract.json` through a loop that calls
`scan(profile, mode, input)` and compares the wire verdict byte-for-byte, so a
generated corpus in that same `unicode-security-verdict-v0` schema is a
differential test across every port that reads it, with no new per-port
machinery. Going through `scan` also widens the comparison from one family to
every family the policy layer dispatches.

The input shape is the one the existing runner proved useful: the same
xorshift64 stream, the same seed, and the same class mix of ASCII,
Latin-Cyrillic look-alikes, math-alpha and fullwidth, combining marks,
default-ignorables and free scalars. The profile cycles so the policy layer is
exercised alongside the detectors.

Verdicts come from the Rust reference in one batch through its `--jsonl` mode,
and are projected onto the wire shape with the same `FINDING_FIELDS` the
verdict-contract generator uses. That module is imported rather than copied, so
the projection and the port-copy sync cannot drift between the two fixtures.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "security" / "differential_corpus.json"
DEFAULT_BIN = ROOT / "ports" / "rust" / "target" / "debug" / "unicode-security"

# The verdict-contract generator owns the projection onto the wire shape and the
# port-copy sync. Its filename is not an identifier, so it is loaded by path
# rather than imported by name; the alternative is a second copy of both, which
# is exactly the drift this fixture exists to catch.
_CONTRACT_PATH = ROOT / "scripts" / "regenerate-verdict-contract.py"
_spec = importlib.util.spec_from_file_location("verdict_contract_gen", _CONTRACT_PATH)
if _spec is None or _spec.loader is None:
    raise SystemExit(f"cannot load {_CONTRACT_PATH}")
_contract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_contract)

FINDING_FIELDS = _contract.FINDING_FIELDS
sync_fixture = _contract.sync_fixture

# The stream is shared with ports/rust/tests/diff_runner.rs so a case index here
# names the same input there.
SEED = 0xC0FFEE_1234_5678
MAX_LEN = 32

# Every profile, so the corpus exercises the policy layer's grading and not only
# the detectors. `scan` derives its detector context from the profile, so a case
# under `username` asks a different question of the same bytes than one under
# `source-code`.
PROFILES = (
    "gateway-header",
    "domain-name",
    "dns-label",
    "url",
    "username",
    "display-name",
    "chat-message",
    "source-code",
    "opaque-secret",
    "binary-blob",
)

LATIN_CYRILLIC_LOOKALIKES = (
    0x61, 0x65, 0x6F, 0x70, 0x63, 0x79, 0x78,
    0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0443, 0x0445,
)
COMBINING_OR_LATIN = (0x0300, 0x0301, 0x0308, 0x0061)
DEFAULT_IGNORABLE_OR_SPACE = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202F)

MASK64 = (1 << 64) - 1


class Xorshift:
    """xorshift64 with the constants used by the Rust runner."""

    def __init__(self, seed: int = SEED) -> None:
        self.state = seed

    def next_u64(self) -> int:
        x = self.state
        x ^= (x << 13) & MASK64
        x ^= x >> 7
        x ^= (x << 17) & MASK64
        self.state = x
        return x


def gen_input(rng: Xorshift) -> list[int]:
    """One corpus input, drawn from the class mix the Rust runner established."""
    length = rng.next_u64() % (MAX_LEN + 1)
    cls = rng.next_u64() % 10
    out: list[int] = []
    while len(out) < length:
        if cls <= 3:
            r = rng.next_u64() % 62
            if r < 26:
                cp = 0x61 + r
            elif r < 52:
                cp = 0x41 + (r - 26)
            else:
                cp = 0x30 + (r - 52)
        elif cls <= 5:
            cp = LATIN_CYRILLIC_LOOKALIKES[rng.next_u64() % len(LATIN_CYRILLIC_LOOKALIKES)]
        elif cls == 6:
            if rng.next_u64() % 2 == 0:
                cp = 0x1D400 + (rng.next_u64() % 0x400)
            else:
                cp = 0xFF21 + (rng.next_u64() % 0x5A)
        elif cls == 7:
            pick = COMBINING_OR_LATIN[rng.next_u64() % len(COMBINING_OR_LATIN)]
            cp = 0x0061 + (rng.next_u64() % 26) if pick == 0x0061 else pick
        elif cls == 8:
            cp = DEFAULT_IGNORABLE_OR_SPACE[rng.next_u64() % len(DEFAULT_IGNORABLE_OR_SPACE)]
        else:
            r = rng.next_u64() % 0x110000
            cp = r + 0x800 if 0xD800 <= r <= 0xDFFF else r
        out.append(cp)
    return out


def reference_verdicts(
    binary: Path, cases: list[tuple[str, str, list[int]]]
) -> list[dict]:
    """Run every case through the reference in one batch.

    The CLI's `--jsonl` mode takes one profile and mode for the whole batch, so
    the cases are grouped by profile and each group is one invocation. That is
    ten subprocesses for the whole corpus rather than one per case.
    """
    verdicts: dict[str, dict] = {}
    for profile in PROFILES:
        group = [
            (name, cps) for name, case_profile, cps in cases if case_profile == profile
        ]
        if not group:
            continue
        records = "".join(
            json.dumps({"id": name, "text": "".join(chr(cp) for cp in cps)}) + "\n"
            for name, cps in group
        )
        completed = subprocess.run(
            [str(binary), "scan", "--jsonl", "--profile", profile, "--mode", "enforce"],
            input=records.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        emitted = [line for line in completed.stdout.decode().splitlines() if line.strip()]
        if len(emitted) != len(group):
            raise SystemExit(
                f"reference emitted {len(emitted)} verdicts for {len(group)} "
                f"{profile} cases: {completed.stderr.decode(errors='replace').strip()}"
            )
        for line in emitted:
            record = json.loads(line)
            name = record.pop("id")
            record["findings"] = [
                {field: finding[field] for field in FINDING_FIELDS}
                for finding in record["findings"]
            ]
            verdicts[name] = record
    return [verdicts[name] for name, _profile, _cps in cases]


def build_document(binary: Path, count: int) -> dict:
    rng = Xorshift()
    cases: list[tuple[str, str, list[int]]] = []
    for index in range(count):
        cps = gen_input(rng)
        profile = PROFILES[index % len(PROFILES)]
        cases.append((f"diff-{index:05d}", profile, cps))
    verdicts = reference_verdicts(binary, cases)
    return {
        # Same schema and contract name as verdict_contract.json, so a port
        # validates this file with the loop it already runs over that one.
        "schema": 1,
        "contract": "unicode-security-verdict-v0",
        "cases": [
            {
                "name": name,
                "profile": profile,
                "mode": "enforce",
                "input": cps,
                "verdict": verdict,
            }
            for (name, profile, cps), verdict in zip(cases, verdicts)
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BIN)
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report whether the committed fixture matches a fresh generation",
    )
    parser.add_argument("--sync-ports", action="store_true")
    args = parser.parse_args()

    if not args.binary.exists():
        print(f"reference CLI not found: {args.binary}", file=sys.stderr)
        print("build it with: cd ports/rust && cargo build", file=sys.stderr)
        return 2

    document = build_document(args.binary, args.count)
    serialized = json.dumps(document, indent=2) + "\n"

    if args.check:
        if not FIXTURE.exists():
            print(f"missing {FIXTURE.relative_to(ROOT)}", file=sys.stderr)
            return 1
        if FIXTURE.read_text() == serialized:
            print(f"clean: {len(document['cases'])} corpus cases match the reference")
            return 0
        print(
            f"{FIXTURE.relative_to(ROOT)} differs from a fresh generation",
            file=sys.stderr,
        )
        return 1

    FIXTURE.write_text(serialized)
    print(f"wrote {FIXTURE.relative_to(ROOT)} ({len(document['cases'])} cases)")
    if args.sync_ports:
        print(f"synced {sync_fixture(FIXTURE)} vendored copies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
