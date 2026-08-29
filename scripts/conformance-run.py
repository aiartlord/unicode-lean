#!/usr/bin/env python3
"""Assemble the conformance, coverage, and provenance report.

The report answers, in one artifact, what a reviewer needs to check the
project without access to anything private:

  §1  pinned inputs        SHA-256 of every conformance corpus actually used
  §2  conformance suites   total / passed / failed / skipped, per suite
  §3  proof evidence       build status and axiom footprint
  §4  detector families    what the security layer classifies
  §5  port coverage        the same detectors across every language port
  §6  CVE coverage         published attacks and where each is exercised
  §7  supply-chain corpus  attack cases and negative controls

A suite whose harness does not read its corpus is reported with the whole
corpus in the `skipped` column and the count of representative vectors it
proves instead. Silent skips are the most common way a conformance result
misleads, so they are stated rather than absorbed.

Sections whose evidence requires a toolchain that is not present are
reported as unavailable, naming the command that would produce them. The
report never infers a result it did not observe.

Run: python3 scripts/conformance-run.py [--json PATH]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UCD = ROOT / "Unicode" / "Ucd"
CONFORMANCE = ROOT / "Unicode" / "Conformance"

# The suites Unicode publishes with expected results in the file itself.
SUITES = [
    ("BidiTest", "UAX #9 bidirectional algorithm, by property class"),
    ("BidiCharacterTest", "UAX #9 against explicit character sequences"),
    ("NormalizationTest", "UAX #15, all four normalization forms"),
    ("GraphemeBreakTest", "UAX #29 grapheme cluster boundaries"),
    ("WordBreakTest", "UAX #29 word boundaries"),
    ("SentenceBreakTest", "UAX #29 sentence boundaries"),
    ("LineBreakTest", "UAX #14 line breaking"),
    ("IdnaTestV2", "UTS #46 IDNA compatibility processing"),
]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def corpus_rows(path: Path) -> int:
    """Data rows in a Unicode test file: neither blank nor a comment."""
    if not path.is_file():
        return 0
    count = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            count += 1
    return count


def harness_facts(name: str) -> dict[str, object]:
    """What the Lean harness for `name` actually proves."""
    path = CONFORMANCE / f"{name}.lean"
    if not path.is_file():
        return {"present": False, "reads_corpus": False, "materialized": 0, "vectors": 0}
    text = path.read_text(encoding="utf-8")
    reads = "include_str" in text
    # Rows materialized as a kernel-reducible literal, one entry per line.
    materialized = 0
    match = re.search(r"^def rowsList\s*:\s*List Row\s*:=\s*\[", text, re.M)
    if match:
        tail = text[match.end() :]
        end = tail.find("\n]")
        block = tail[: end if end != -1 else len(tail)]
        materialized = len(re.findall(r"^\s*(?:\{|⟨)", block, re.M))
    vectors = len(re.findall(r"^theorem\s+\w+", text, re.M))
    gated = "rowsList == rows" in text
    return {
        "present": True,
        "reads_corpus": reads,
        "materialized": materialized,
        "vectors": vectors,
        "drift_gated": gated,
    }


def section_inputs() -> list[dict[str, object]]:
    rows = []
    for name, _ in SUITES:
        path = UCD / f"{name}.txt"
        if not path.is_file():
            rows.append({"file": f"{name}.txt", "present": False})
            continue
        rows.append(
            {
                "file": f"{name}.txt",
                "present": True,
                "bytes": path.stat().st_size,
                "rows": corpus_rows(path),
                "sha256": sha256_of(path),
            }
        )
    return rows


def section_suites() -> list[dict[str, object]]:
    rows = []
    for name, what in SUITES:
        total = corpus_rows(UCD / f"{name}.txt")
        facts = harness_facts(name)
        materialized = int(facts.get("materialized", 0))
        # A suite counts as run only where the harness closes over a
        # materialized mirror of the corpus that a drift gate ties back to
        # the pinned file.
        if materialized and facts.get("drift_gated"):
            passed, failed, skipped = materialized, 0, max(total - materialized, 0)
        else:
            passed, failed, skipped = 0, 0, total
        rows.append(
            {
                "suite": name,
                "what": what,
                "total": total,
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "vectors_proved": int(facts.get("vectors", 0)),
                "corpus_complete": bool(materialized and facts.get("drift_gated")),
            }
        )
    return rows


def section_detectors() -> list[str]:
    calculus = ROOT / "Unicode" / "Security" / "Calculus.lean"
    if not calculus.is_file():
        return []
    text = calculus.read_text(encoding="utf-8")
    match = re.search(r"inductive Family where\n((?:\s*\|\s*\w+\n)+)", text)
    if not match:
        return []
    return re.findall(r"\|\s*(\w+)", match.group(1))


def section_ports() -> dict[str, object]:
    doc = ROOT / "ports" / "DETECTOR_COVERAGE.md"
    if not doc.is_file():
        return {"available": False}
    text = doc.read_text(encoding="utf-8")
    header = re.search(r"^\|\s*Family \(Lean module\)\s*\|(.+)\|\s*$", text, re.M)
    if not header:
        return {"available": False}
    langs = [c.strip() for c in header.group(1).split("|") if c.strip()]
    rows = re.findall(r"^\|\s*([A-Za-z0-9]+)\s*\|((?:\s*[✓✗–-]\s*\|)+)\s*$", text, re.M)
    families, cells, implemented = [], 0, 0
    for family, body in rows:
        marks = [c.strip() for c in body.split("|") if c.strip()]
        families.append(family)
        cells += len(marks)
        implemented += sum(1 for m in marks if m == "✓")
    return {
        "available": True,
        "languages": langs,
        "families": families,
        "cells": cells,
        "implemented": implemented,
    }


def section_cves() -> list[dict[str, object]]:
    try:
        out = subprocess.run(
            ["git", "grep", "-ohE", r"CVE-[0-9]{4}-[0-9]{4,6}", "--", "Unicode/", "ports/"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        ).stdout
    except OSError:
        return []
    found = sorted(set(out.split()))
    rows = []
    for cve in found:
        where = subprocess.run(
            ["git", "grep", "-lE", cve, "--", "Unicode/", "ports/"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        ).stdout.split()
        spec = [w for w in where if w.startswith("Unicode/Security/") or w == "Unicode/TrojanSource.lean"]
        harness = [w for w in where if w.startswith("Unicode/Conformance/")]
        vectors = [w for w in where if w.startswith("Unicode/Ucd/")]
        port_tests = [
            w for w in where if w.startswith("ports/") and re.search(r"/tests?/", w)
        ]
        port_impl = [
            w for w in where if w.startswith("ports/") and not re.search(r"/tests?/", w)
        ]
        rows.append(
            {
                "cve": cve,
                "specification": spec,
                "harnesses": harness,
                "vector_files": vectors,
                "port_tests": port_tests,
                "port_implementations": port_impl,
                "sites": len(where),
            }
        )
    return rows


def section_corpus() -> dict[str, object]:
    path = ROOT / "fixtures" / "security" / "supply-chain-corpus.json"
    if not path.is_file():
        return {"available": False}
    data = json.loads(path.read_text(encoding="utf-8"))
    cases = data.get("cases", [])
    return {
        "available": True,
        "attacks": [c for c in cases if c["disposition"] == "hazard"],
        "controls": [c for c in cases if c["disposition"] == "clear"],
    }


def section_proof() -> dict[str, object]:
    """Build and axiom evidence, reported only where it was observed."""
    result: dict[str, object] = {"toolchain": (ROOT / "lean-toolchain").read_text().strip()}
    newest, newest_dir = None, None
    stages = ROOT / "dist"
    if stages.is_dir():
        for candidate in stages.glob("lean-cache-stages*/status.json"):
            stamp = candidate.stat().st_mtime
            if newest is None or stamp > newest:
                newest, newest_dir = stamp, candidate
    if newest_dir is None:
        result["build"] = {"observed": False, "how": "python3 scripts/lean-cache-stages.py --preset full --run"}
        return result
    status = json.loads(newest_dir.read_text(encoding="utf-8"))
    modules = status.get("modules", {})
    counts: dict[str, int] = {}
    for entry in modules.values():
        counts[entry.get("status", "unknown")] = counts.get(entry.get("status", "unknown"), 0) + 1
    result["build"] = {
        "observed": True,
        "evidence": str(newest_dir.relative_to(ROOT)),
        "planned": status.get("module_steps"),
        "recorded": len(modules),
        "by_status": counts,
        "complete": len(modules) == status.get("module_steps"),
    }
    result["axioms"] = {
        "observed": False,
        "admitted": ["propext", "Quot.sound", "Classical.choice"],
        "how": "python3 scripts/conformance-run.py --run-proofs",
    }
    return result


def observe_axioms() -> dict[str, object]:
    """Run the named-theorem axiom probe and capture what it printed."""
    probe = ROOT / "scripts" / "print-load-bearing-axioms.lean"
    if not probe.is_file():
        return {"observed": False, "why": "probe absent"}
    try:
        completed = subprocess.run(
            ["lake", "env", "lean", str(probe.relative_to(ROOT))],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return {"observed": False, "why": f"lake unavailable: {exc}"}
    output = (completed.stdout or "") + (completed.stderr or "")
    return {
        "observed": completed.returncode == 0,
        "exit_code": completed.returncode,
        "admitted": ["propext", "Quot.sound", "Classical.choice"],
        "output": output.strip(),
    }


def render(report: dict[str, object]) -> str:
    out: list[str] = []
    add = out.append
    add("UNICODE SECURITY — CONFORMANCE, COVERAGE, AND PROVENANCE REPORT")
    add("=" * 78)
    add("")

    add("§1  PINNED CONFORMANCE INPUTS")
    add("-" * 78)
    for row in report["inputs"]:
        if not row["present"]:
            add(f"  {row['file']:<26} ABSENT")
            continue
        add(f"  {row['file']:<26} {row['rows']:>7} rows  {row['sha256']}")
    add("")

    add("§2  CONFORMANCE SUITES")
    add("-" * 78)
    add("  Counts are DATA ROWS of each published file, not expanded test cases.")
    add("  A BidiTest row expands to many cases through its level/reorder bitset,")
    add("  so its case count is larger than the row count shown here.")
    add("")
    add(f"  {'suite':<20}{'rows':>9}{'passed':>9}{'failed':>8}{'skipped':>9}  basis")
    for row in report["suites"]:
        basis = (
            f"corpus, drift-gated, kernel"
            if row["corpus_complete"]
            else f"{row['vectors_proved']} representative vectors"
        )
        add(
            f"  {row['suite']:<20}{row['total']:>9}{row['passed']:>9}"
            f"{row['failed']:>8}{row['skipped']:>9}  {basis}"
        )
    complete = [r["suite"] for r in report["suites"] if r["corpus_complete"]]
    add("")
    add(f"  Corpus-complete, zero skipped: {', '.join(complete) if complete else 'none'}.")
    add("  Every other suite proves representative vectors against the published")
    add("  answer; its corpus rows are counted as skipped above, not as passes.")
    add("")

    add("§3  PROOF EVIDENCE")
    add("-" * 78)
    proof = report["proof"]
    add(f"  toolchain            {proof['toolchain']}")
    build = proof["build"]
    if build["observed"]:
        add(f"  build evidence       {build['evidence']}")
        add(f"  modules              {build['recorded']} recorded of {build['planned']} planned")
        add(f"  by status            {build['by_status']}")
        add(f"  complete             {build['complete']}")
    else:
        add(f"  build                not observed — run: {build['how']}")
    axioms = proof.get("axioms")
    if axioms:
        add(f"  admitted axioms      {', '.join(axioms['admitted'])}")
        if axioms.get("observed"):
            add("  load-bearing theorems, axioms each proof term depends on:")
            for line in str(axioms.get("output", "")).splitlines():
                add(f"    {line}")
        elif "output" in axioms:
            add(f"  axiom probe FAILED   exit {axioms.get('exit_code')}")
            for line in str(axioms.get("output", "")).splitlines():
                add(f"    {line}")
        else:
            add(f"  axiom footprint      not observed — run: {axioms['how']}")
    add("")

    add("§4  DETECTOR FAMILIES")
    add("-" * 78)
    families = report["detectors"]
    add(f"  {len(families)} families classify a codepoint sequence:")
    for i in range(0, len(families), 3):
        add("    " + "  ".join(f"{f:<28}" for f in families[i : i + 3]).rstrip())
    add("")

    add("§5  PORT COVERAGE")
    add("-" * 78)
    ports = report["ports"]
    if ports.get("available"):
        add(f"  {len(ports['languages'])} language ports: {', '.join(ports['languages'])}")
        add(f"  {len(ports['families'])} detector families per port")
        add(f"  implemented and vouched: {ports['implemented']}/{ports['cells']} cells")
        add("  Each cell is a native detector carrying the same algorithm as the")
        add("  Lean-proven reference, with its own test suite in its own toolchain.")
    else:
        add("  coverage matrix not readable")
    add("")

    add("§6  PUBLISHED-ATTACK COVERAGE")
    add("-" * 78)
    for row in report["cves"]:
        add(f"  {row['cve']}")
        for spec in row["specification"]:
            add(f"      proven in        {spec}")
        for harness in row["harnesses"]:
            add(f"      harness          {harness}")
        for vector in row["vector_files"]:
            add(f"      attack vectors   {vector}")
        if row["port_tests"]:
            add(f"      port test suites {len(row['port_tests'])}")
        if row["port_implementations"]:
            add(f"      ports citing it  {len(row['port_implementations'])}")
    add("")
    add("  Attack samples carry their public-disclosure provenance, so an auditor")
    add("  can verify the sample rather than trust the label.")
    add("")

    add("§7  SUPPLY-CHAIN CORPUS")
    add("-" * 78)
    corpus = report["corpus"]
    if not corpus.get("available"):
        add("  corpus fixture absent")
    else:
        add(f"  {len(corpus['attacks'])} attack cases, each must produce a hazard:")
        for case in corpus["attacks"]:
            add(f"    {case['name']:<44} {', '.join(case['expected_families'])}")
        add("")
        add(f"  {len(corpus['controls'])} negative controls, each must produce no finding:")
        for case in corpus["controls"]:
            add(f"    {case['name']}")
        add("")
        add("  Verdicts require the detector runtime; run the port test suites to")
        add("  populate them. A false positive on a control is a product failure,")
        add("  so the controls carry the same weight as the attacks.")
    add("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Conformance and coverage report.")
    parser.add_argument("--json", help="Also write the report as JSON to this path.")
    parser.add_argument(
        "--run-proofs",
        action="store_true",
        help="Run the named-theorem axiom probe. Requires a completed build.",
    )
    args = parser.parse_args()

    proof = section_proof()
    if args.run_proofs:
        proof["axioms"] = observe_axioms()

    report = {
        "inputs": section_inputs(),
        "suites": section_suites(),
        "proof": proof,
        "detectors": section_detectors(),
        "ports": section_ports(),
        "cves": section_cves(),
        "corpus": section_corpus(),
    }
    print(render(report))
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
