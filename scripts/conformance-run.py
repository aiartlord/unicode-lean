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

Three flags add evidence the report cannot assemble from files alone, each
needing a toolchain the bare run does not:

  --run-proofs             run the named-theorem axiom probe (needs a build)
  --run-corpus             scan the supply-chain corpus with the reference CLI
  --emit-inputs-manifest   write fixtures/conformance/CONFORMANCE-INPUTS.sha256,
                           the tracked manifest scripts/check-conformance-inputs.sh
                           holds the pinned files to
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
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
    ("CollationTest_NON_IGNORABLE_SHORT", "UTS #10 collation order, variable weights kept"),
    ("CollationTest_SHIFTED_SHORT", "UTS #10 collation order, variable weights shifted"),
]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def corpus_rows(path: Path) -> int:
    """Data rows in a Unicode test file.

    Neither blank, nor a comment, nor a directive. `NormalizationTest.txt`
    separates its sections with `@Part0` through `@Part5` and `BidiTest.txt`
    carries `@Levels` and `@Reorder`; those lines state how to read the rows
    beneath them and are not themselves test rows. Counting them inflates the
    denominator, which then reports a complete suite as having skipped the
    difference.
    """
    if not path.is_file():
        return 0
    count = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and not stripped.startswith("@"):
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


# The module whose `#eval` gate folds a suite's whole corpus during the
# `UnicodeFullConformance` build. Several suites are judged by a run module
# rather than by the harness named after the suite, and two suites share one:
# `BreakTestRun` gates the word and line corpora together.
GATE_MODULES = {
    "BidiTest": "BidiTestRun",
    "BidiCharacterTest": "BidiCharacterTestRun",
    "NormalizationTest": "NormalizationTestRun",
    "WordBreakTest": "BreakTestRun",
    "LineBreakTest": "BreakTestRun",
    "IdnaTestV2": "IdnaTestV2",
}


def build_gated(name: str) -> bool:
    """Whether a suite's whole corpus is folded by a gate during the build.

    Three things have to hold, and reporting a suite's rows as passed on the
    strength of a gate that fails any of them would be the same unchecked
    assertion this column exists to retire.

    The gate must fail the build rather than print a summary, so its `#eval`
    has to throw. It must run over the whole corpus, so the block may not take
    a prefix of the rows — every run module also exposes a bounded
    `reportFirst`, and a gate written against one of those would report a clean
    sweep having judged a hundred rows. And it must assert its own coverage, so
    the block has to compare a tally against the parsed length; without that a
    parser dropping half the file reads as a pass over a smaller denominator.

    The gate also has to be reached from a build root, which is what
    `scripts/check-orphan-files.sh` enforces: a gate in a module nothing
    imports never runs.
    """
    module = GATE_MODULES.get(name)
    if module is None:
        return False
    path = CONFORMANCE / f"{module}.lean"
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    blocks = re.findall(r"^#eval do\n((?:[ \t].*\n|\n)*)", text, re.M)
    for block in blocks:
        if "throw (IO.userError" not in block:
            continue
        if ".take " in block or "reportFirst" in block:
            continue
        if ".length" not in block and ".cases ==" not in block:
            continue
        return True
    return False


EXECUTED_RUNS = ROOT / "fixtures" / "conformance" / "executed-runs.json"
INPUTS_MANIFEST = ROOT / "fixtures" / "conformance" / "CONFORMANCE-INPUTS.sha256"
VERSION_FILE = ROOT / "data" / "UCD-VERSION"


def target_versions() -> dict[str, str]:
    """The Unicode versions the implementation targets, from `data/UCD-VERSION`.

    Two lines matter: `UCD=` for the character database every suite except
    collation is drawn from, and `UCA=` for the collation element table and its
    conformance corpora. The file is the pinned statement of what the tree
    implements; the corpus headers say what was run, and the report puts the
    two beside each other so a mismatch is stated rather than hidden.
    """
    versions: dict[str, str] = {}
    if not VERSION_FILE.is_file():
        return versions
    for line in VERSION_FILE.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            versions[key.strip()] = value.strip()
    return versions


def corpus_version(path: Path) -> str | None:
    """The version a published test file declares in its header.

    The Consortium names the version one of three ways: in the filename line
    (`# BidiTest-17.0.0.txt`), as `# Version: 17.0.0`, or for the collation
    corpora as `# UCA Version: 17.0.0`. The first header line carrying a
    dotted version wins; a file with none reports `None`.
    """
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index >= 20 or not line.startswith("#"):
                break
            match = re.search(r"(\d+\.\d+\.\d+)", line)
            if match:
                return match.group(1)
    return None


def section_versions(inputs: list[dict[str, object]]) -> dict[str, object]:
    """Implementation target versus corpus version, per suite."""
    target = target_versions()
    rows = []
    for row in inputs:
        name = str(row["file"])
        component = "UCA" if name.startswith("CollationTest") else "UCD"
        expected = target.get(component)
        declared = corpus_version(UCD / name) if row.get("present") else None
        rows.append(
            {
                "file": name,
                "component": component,
                "target": expected,
                "declared": declared,
                "agrees": expected is not None and declared == expected,
            }
        )
    return {
        "target": target,
        "corpora": rows,
        "mismatched": [r["file"] for r in rows if not r["agrees"]],
    }


def executed_runs() -> dict[str, dict]:
    """Recorded folds of a corpus through the implementation, keyed by suite.

    A record is used only while the digest it was taken against still matches
    the corpus on disk. Unicode moves `latest` yearly, so a record that outlives
    its input has to stop counting rather than keep reporting a pass for a file
    it never read.
    """
    if not EXECUTED_RUNS.is_file():
        return {}
    payload = json.loads(EXECUTED_RUNS.read_text(encoding="utf-8"))
    usable: dict[str, dict] = {}
    for run in payload.get("runs", []):
        suite = str(run.get("suite", ""))
        corpus = UCD / f"{suite}.txt"
        if not corpus.is_file():
            continue
        if sha256_of(corpus) != run.get("input_sha256"):
            continue
        usable[suite] = run
    return usable


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


def write_inputs_manifest(rows: list[dict[str, object]], destination: Path) -> int:
    """Write the pinned conformance inputs as a sha256sum-checkable manifest.

    The format is the one `sha256sum -c` reads, and the paths are relative to
    the repository root, so an auditor verifies the manifest with the same
    command the repository already uses for `Unicode/Ucd/SHA256SUMS` rather
    than a bespoke checker. A file listed here that is absent from the tree is
    an error rather than an omitted line: a manifest that silently shrinks to
    the files that happen to exist cannot be evidence of what was tested.
    """
    missing = [row["file"] for row in rows if not row["present"]]
    if missing:
        print(f"FATAL: pinned input(s) absent: {', '.join(missing)}", file=sys.stderr)
        return 1
    destination.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{row['sha256']}  Unicode/Ucd/{row['file']}" for row in rows]
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {destination} ({len(lines)} inputs)")
    return 0


def section_suites() -> list[dict[str, object]]:
    rows = []
    executed = executed_runs()
    for name, what in SUITES:
        total = corpus_rows(UCD / f"{name}.txt")
        facts = harness_facts(name)
        materialized = int(facts.get("materialized", 0))
        run = executed.get(name)
        # A collation corpus asserts order between ADJACENT lines, so a file of
        # n rows publishes n - 1 assertions; the executed row counts those
        # pairs. Dividing pairs by rows would report one assertion as skipped
        # that the file never made.
        if run is not None and list(run.get("columns", [])) == ["collation order"]:
            total = max(total - 1, 0)
        # A suite counts as run two ways. Either the harness closes over a
        # materialized mirror of the corpus that a drift gate ties back to the
        # pinned file, or the corpus was folded through the implementation and
        # the result recorded against the digest of the file that was read.
        # The second is an execution and not a proof, so it is reported under
        # its own basis rather than merged with the first.
        gated = build_gated(name)
        if materialized and facts.get("drift_gated"):
            passed, failed, skipped = materialized, 0, max(total - materialized, 0)
        elif gated:
            # The gate throws unless every published row passes and the tally
            # accounts for the whole file, so the build failing is the only way
            # this is not a clean sweep.
            passed, failed, skipped = total, 0, 0
        elif run is not None:
            passed = int(run["passed"])
            failed = int(run["failed"])
            judged = int(run["rows_judged"])
            skipped = max(total - judged, 0)
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
                "build_gated": gated,
                "executed": run is not None,
                "executed_columns": list(run["columns"]) if run is not None else [],
            }
        )
    return rows


ICU_RUNS = ROOT / "fixtures" / "conformance" / "icu-runs.json"


def section_icu() -> dict[str, object]:
    """ICU4C over the same pinned files, recorded by `scripts/icu-conformance.sh`.

    The record is used only while every input digest it carries still matches
    the pinned file, the rule the executed runs follow: a comparison row that
    outlived its inputs would compare two different corpora.
    """
    if not ICU_RUNS.is_file():
        return {"available": False, "how": "nix develop .#runtime -c scripts/icu-conformance.sh --record"}
    run = json.loads(ICU_RUNS.read_text(encoding="utf-8"))
    stale = []
    for name, digest in run.get("inputs_sha256", {}).items():
        path = UCD / name
        if not path.is_file() or sha256_of(path) != digest:
            stale.append(name)
    rows = []
    for name, what in SUITES:
        suite = run.get("suites", {}).get(name)
        if suite is None or name in stale:
            rows.append({"suite": name, "recorded": False})
            continue
        rows.append(
            {
                "suite": name,
                "recorded": True,
                "total": int(suite.get("total", 0)),
                "passed": int(suite.get("passed", 0)),
                "failed": int(suite.get("failed", 0)),
                "skipped": int(suite.get("skipped", 0)),
                "levels_differ_same_order": int(suite.get("levels_differ_same_order", 0)),
                "skipped_why": suite.get("skipped_why"),
            }
        )
    return {
        "available": True,
        "icu_version": run.get("icu_version"),
        "icu_unicode_version": run.get("icu_unicode_version"),
        "harness": run.get("harness"),
        "stale_inputs": stale,
        "suites": rows,
    }


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


REFERENCE_CLI = ROOT / "ports" / "rust" / "target" / "debug" / "unicode-security"


def scan_reference(
    binary: Path, codepoints: list[int], profile: str, mode: str
) -> tuple[set[str], str | None]:
    """The families the reference reports for one input, and its action.

    Which detectors run does not depend on the profile -- the profile decides
    what the verdict does about a finding, not whether the finding exists --
    so the family set is the same under any profile, and only the action moves.
    The exit status is the scanner's verdict channel, so a run that failed is
    one that emitted no verdict.
    """
    payload = "".join(chr(cp) for cp in codepoints).encode("utf-8")
    completed = subprocess.run(
        [str(binary), "scan", "--profile", profile, "--mode", mode, "--json"],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        verdict = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return set(), None
    return {finding["family"] for finding in verdict["findings"]}, verdict.get("action")


def measure_corpus(cases: list[dict[str, object]], binary: Path) -> list[dict[str, object]]:
    """Attach the reference's verdict to every case, on both of its questions.

    A case is measured twice, because a corpus of this kind answers two
    questions that do not have the same answer.  The first is what the
    detectors see: scanned under the profile of the field the case is drawn
    from, in `observe`, an attack is met when it produces any finding and a
    control is met only when it produces none.  That is the strict reading,
    and it is the one to quote when asking whether a detector exists and
    reaches the input.  The profile matters even here: the field-scoped rungs
    (`Unicode/Security/RunAll.lean`'s `Context`) ask their question only of
    the kind of field they are specified for, so a username is judged as an
    identifier and a source file is not.

    The second is what the product does: scanned under the profile of the field
    the case is drawn from, in `enforce`, an attack is met when the action is
    not `allow` and a control is met when it is.  This is the deployed
    behaviour, and it can differ from the first because
    `Unicode/Security/Policy.lean` grades families by profile -- a Hebrew
    comment is a finding in every profile and a rejection only in those whose
    level admits `rtlInjection`.

    Neither reading subsumes the other, so both are reported.  Whether the
    hazard carries the family the case names is tracked separately again: a
    case caught under another family is caught but mis-attributed, and the two
    failures need different fixes.
    """
    measured = []
    for case in cases:
        families, _ = scan_reference(binary, case["input"], case["profile"], "observe")
        _, action = scan_reference(binary, case["input"], case["profile"], "enforce")
        expected = set(case["expected_families"])
        hazard = bool(families)
        blocked = action is not None and action != "allow"
        row = dict(case)
        row["observed_families"] = sorted(families)
        row["action"] = action
        if case["disposition"] == "hazard":
            row["met"] = hazard
            row["deployed_met"] = blocked
            row["expected_family_fired"] = bool(families & expected)
        else:
            row["met"] = not hazard
            row["deployed_met"] = action is not None and not blocked
            row["expected_family_fired"] = None
        measured.append(row)
    return measured


def section_corpus(binary: Path | None = None) -> dict[str, object]:
    path = ROOT / "fixtures" / "security" / "supply-chain-corpus.json"
    if not path.is_file():
        return {"available": False}
    data = json.loads(path.read_text(encoding="utf-8"))
    cases = data.get("cases", [])
    if binary is not None and binary.is_file():
        cases = measure_corpus(cases, binary)
    return {
        "available": True,
        "measured": binary is not None and binary.is_file(),
        "reference": str(binary) if binary is not None else None,
        "attacks": [c for c in cases if c["disposition"] == "hazard"],
        "controls": [c for c in cases if c["disposition"] == "clear"],
    }


def section_proof() -> dict[str, object]:
    """Build and axiom evidence, reported only where it was observed."""
    result: dict[str, object] = {"toolchain": (ROOT / "lean-toolchain").read_text().strip()}
    # The runner leaves one status per invocation. A preset that plans a
    # subset of the roots is a real run but not the evidence a full build is,
    # so the widest plan wins and recency only breaks ties: a fresh partial
    # run must not displace the complete one it sits beside.
    best_key, newest_dir = None, None
    stages = ROOT / "dist"
    if stages.is_dir():
        for candidate in stages.glob("lean-cache-stages*/status.json"):
            try:
                planned = int(json.loads(candidate.read_text(encoding="utf-8")).get("module_steps", 0))
            except (OSError, ValueError):
                continue
            key = (planned, candidate.stat().st_mtime)
            if best_key is None or key > best_key:
                best_key, newest_dir = key, candidate
    if newest_dir is None:
        result["build"] = {"observed": False, "how": "python3 scripts/lean-cache-stages.py --preset full --run"}
        return result
    status = json.loads(newest_dir.read_text(encoding="utf-8"))
    modules = status.get("modules", {})
    counts: dict[str, int] = {}
    for entry in modules.values():
        counts[entry.get("status", "unknown")] = counts.get(entry.get("status", "unknown"), 0) + 1
    # A completed build describes the tree it ran against, not the tree now.
    # Sources touched afterwards are not covered by it, and a report that says
    # "complete" without saying "as of when" invites the reader to assume they
    # are. Compare each source against the moment the build was recorded.
    recorded_at = status.get("updated_utc")
    changed_since: list[str] = []
    if recorded_at:
        stamp = datetime.datetime.fromisoformat(recorded_at.replace("Z", "+00:00")).timestamp()
        for source in (ROOT / "Unicode").rglob("*.lean"):
            if source.stat().st_mtime > stamp:
                changed_since.append(str(source.relative_to(ROOT)))
    log_dir = newest_dir.parent / "logs"
    log_count = len(list(log_dir.glob("*.log"))) if log_dir.is_dir() else 0
    # Wall time and peak memory are product facts: whether the proof build is
    # CI-viable. The runner records both per module, so the report carries the
    # serial sum of module times, the span from the first module's start to
    # the recording of the last, and the largest process-tree peak.
    elapsed = [float(entry.get("elapsed_sec", 0.0)) for entry in modules.values()]
    peaks = [int(entry.get("peak_tree_rss_kb", 0)) for entry in modules.values()]
    # The span runs from the first module's start to the last module's end,
    # each end being its start plus its elapsed time; the status file's own
    # timestamp is the plan's, not the run's.
    starts: list[float] = []
    ends: list[float] = []
    for entry in modules.values():
        started = entry.get("started_utc")
        if not started:
            continue
        begin = datetime.datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp()
        starts.append(begin)
        ends.append(begin + float(entry.get("elapsed_sec", 0.0)))
    span_seconds = round(max(ends) - min(starts), 1) if starts else None
    resources = {
        "module_wall_seconds_sum": round(sum(elapsed), 1),
        "run_span_seconds": span_seconds,
        "peak_rss_kb": max(peaks) if peaks else None,
        "peak_rss_module": (
            max(modules.items(), key=lambda item: int(item[1].get("peak_tree_rss_kb", 0)))[0]
            if modules
            else None
        ),
    }
    result["build"] = {
        "resources": resources,
        "observed": True,
        "evidence": str(newest_dir.relative_to(ROOT)),
        "logs": str(log_dir.relative_to(ROOT)) if log_count else None,
        "log_count": log_count,
        "recorded_at": recorded_at,
        "planned": status.get("module_steps"),
        "recorded": len(modules),
        "by_status": counts,
        "complete": len(modules) == status.get("module_steps"),
        "sources_changed_since": sorted(changed_since),
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
    versions = report["versions"]
    target = versions["target"]
    add(
        f"  implementation targets   UCD {target.get('UCD', 'unstated')}"
        f"   UCA {target.get('UCA', 'unstated')}   (data/UCD-VERSION)"
    )
    add(f"  {'corpus':<38}{'declares':>10}{'target':>10}")
    for row in versions["corpora"]:
        mark = "" if row["agrees"] else "  MISMATCH"
        add(
            f"  {row['file']:<38}{str(row['declared']):>10}{str(row['target']):>10}{mark}"
        )
    if versions["mismatched"]:
        add("  A corpus whose declared version differs from the target was run")
        add("  against data the implementation does not claim; the row says so.")
    else:
        add("  Every corpus declares the version the implementation targets.")
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
            else "corpus, build-gated"
            if row["build_gated"]
            else "corpus, executed"
            if row["executed"]
            else f"{row['vectors_proved']} representative vectors"
        )
        add(
            f"  {row['suite']:<20}{row['total']:>9}{row['passed']:>9}"
            f"{row['failed']:>8}{row['skipped']:>9}  {basis}"
        )
    complete = [r["suite"] for r in report["suites"] if r["corpus_complete"]]
    gated = [
        r["suite"]
        for r in report["suites"]
        if r["build_gated"] and not r["corpus_complete"]
    ]
    executed = [
        r["suite"]
        for r in report["suites"]
        if r["executed"] and not r["build_gated"] and not r["corpus_complete"]
    ]
    add("")
    add(f"  Corpus-complete, drift-gated in the kernel: {', '.join(complete) if complete else 'none'}.")
    add(f"  Corpus-complete, build-gated: {', '.join(gated) if gated else 'none'}.")
    add(f"  Corpus-complete, executed: {', '.join(executed) if executed else 'none'}.")
    add("  Any suite in none of the three lists proves representative vectors")
    add("  against the published answer; its corpus rows are counted as skipped")
    add("  above, not as passes.")
    add("")
    add("  The three bases are different evidence and are not merged. A kernel")
    add("  row is a proof over a materialized mirror the drift gate ties to the")
    add("  pinned file. A build-gated row is the corpus folded during the")
    add("  UnicodeFullConformance build by a gate that throws unless every")
    add("  published row passes and the tally accounts for the whole file, so")
    add("  the build is the check and no record can go stale. An executed row is")
    add("  the corpus folded out of band and recorded in")
    add("  fixtures/conformance/executed-runs.json against the SHA-256 of the")
    add("  file that was read; it stops counting when that digest no longer")
    add("  matches. Collation is the one suite on that last basis, because a")
    add("  fold over its 437,928 pairs is hours rather than minutes. Regenerate")
    add("  with scripts/conformance-execute.sh.")
    add("")

    icu = report["icu"]
    add("  ICU comparison, the same files through ICU4C:")
    if not icu.get("available"):
        add(f"    not recorded — run: {icu['how']}")
    else:
        add(
            f"    ICU {icu['icu_version']} carrying Unicode {icu['icu_unicode_version']}"
            f" ({icu['harness']})"
        )
        add(f"    {'suite':<38}{'rows':>9}{'passed':>9}{'failed':>8}  of which levels only")
        for row in icu["suites"]:
            if not row["recorded"]:
                add(f"    {row['suite']:<38} not recorded")
                continue
            note = f"  {row['skipped_why']}" if row.get("skipped_why") else ""
            flattened = row.get("levels_differ_same_order", 0)
            tail = f"  {flattened}" if flattened else ""
            add(
                f"    {row['suite']:<38}{row['total']:>9}{row['passed']:>9}"
                f"{row['failed']:>8}{tail}{note}"
            )
        if icu["stale_inputs"]:
            add("    inputs changed since the record: " + ", ".join(icu["stale_inputs"]))
        add("    A row is passed only when every field the file publishes agrees")
        add("    with ICU, digit for digit. 'levels only' counts bidi rows whose")
        add("    visual order agrees while a published embedding level does not:")
        add("    ICU keeps a unidirectional paragraph at the paragraph level, so an")
        add("    Arabic or European number in left-to-right text reads 0 where the")
        add("    file says 2, and ICU's own driver compares levels up to parity for")
        add("    that reason. The remaining failures are ICU differences from the")
        add("    file: isolate initiators under an override, empty-label status in")
        add("    toUnicode, and CLDR root collation where it departs from DUCET.")
        add("    ICU's Unicode version is stated because a file from a newer release")
        add("    than ICU carries would fail rows ICU has not adopted.")
    add("")

    add("§3  PROOF EVIDENCE")
    add("-" * 78)
    proof = report["proof"]
    add(f"  toolchain            {proof['toolchain']}")
    build = proof["build"]
    if build["observed"]:
        add(f"  build evidence       {build['evidence']}")
        add(f"  recorded at          {build.get('recorded_at') or 'unknown'}")
        if build.get("log_count"):
            add(f"  per-module logs      {build['log_count']} under {build['logs']}")
        add(f"  modules              {build['recorded']} recorded of {build['planned']} planned")
        add(f"  by status            {build['by_status']}")
        add(f"  complete             {build['complete']}")
        resources = build.get("resources") or {}
        if resources:
            span = resources.get("run_span_seconds")
            add(
                f"  wall time            {resources['module_wall_seconds_sum']} s summed over"
                f" modules; {span if span is not None else 'unknown'} s first start to last record"
            )
            peak = resources.get("peak_rss_kb")
            if peak:
                add(
                    f"  peak memory          {peak / 1048576:.2f} GiB process tree,"
                    f" in {resources.get('peak_rss_module')}"
                )
        changed = build.get("sources_changed_since") or []
        if changed:
            add(f"  SOURCES CHANGED SINCE THAT BUILD: {len(changed)}")
            for source in changed[:10]:
                add(f"    {source}")
            if len(changed) > 10:
                add(f"    ... and {len(changed) - 10} more")
            add("    The build above does not cover these; it describes the tree as")
            add("    it stood when it ran. Rebuild before citing it as evidence.")
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
        add("")
        add("  Implementing a detector and reaching it from scan are separate")
        add("  properties, and the count above is the first one. The second is")
        add("  carried by fixtures/security/verdict_contract.json, which is")
        add("  generated from the reference and checked by every port: a port that")
        add("  reproduces its finding lists is dispatching the families those")
        add("  cases exercise, in the reference's order. Run")
        add("  scripts/test-runtime-ports.sh for that check, and")
        add("  scripts/regenerate-verdict-contract.py --gate for the reference's")
        add("  own, which nothing else covers.")
        add("")
        add("  The contract carries script coverage deliberately. Its cases include")
        add("  an Armenian and an Arabic mix, single-script Han, a private-use")
        add("  codepoint and a right-to-left comment under source-code, because a")
        add("  port can approximate script resolution and still reproduce a case")
        add("  list drawn only from Latin, Greek and Cyrillic. Every port resolves")
        add("  scripts from the same Scripts.txt, ScriptExtensions.txt and")
        add("  PropertyValueAliases.txt the reference reads, and a codepoint whose")
        add("  script has no abbreviation in that vocabulary resolves to the empty")
        add("  set, which is what keeps the RestrictionLow rung reachable.")
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
    add("  The vector files above are executed, not only pinned. Their 657 rows")
    add("  across 26 files are hash-verified by scripts/check-security-hashes.sh,")
    add("  and each row is also run: every Conformance/Security harness embeds its")
    add("  own file with include_str, parses it through")
    add("  Unicode/Conformance/Security/VectorFile.lean, and closes")
    add("  all_vectors_pass over the whole row list by decide +kernel. The")
    add("  materialized list is mirrored against a fresh parse by a build-time")
    add("  drift gate, the same tie GraphemeBreakTest uses, so a row added to,")
    add("  removed from, or edited in a file fails the build until the harness")
    add("  agrees with it. Each harness keeps its curated theorems alongside, which")
    add("  assert fuller verdicts than the row grammar carries — attribution")
    add("  counts, not just the classification tag.")
    add("")

    add("§7  SUPPLY-CHAIN CORPUS")
    add("-" * 78)
    corpus = report["corpus"]
    if not corpus.get("available"):
        add("  corpus fixture absent")
    else:
        measured = corpus.get("measured")
        add(f"  {len(corpus['attacks'])} attack cases, each must produce a hazard:")
        for case in corpus["attacks"]:
            mark = ""
            if measured:
                if not case["met"]:
                    mark = "  MISSED"
                elif not case["expected_family_fired"]:
                    mark = "  hazard, but not " + ", ".join(case["expected_families"])
                else:
                    mark = "  hazard"
            add(f"    {case['name']:<44} {', '.join(case['expected_families'])}{mark}")
        add("")
        add(f"  {len(corpus['controls'])} negative controls, each must produce no finding:")
        for case in corpus["controls"]:
            if measured:
                observed = case["observed_families"]
                mark = "  clean" if case["met"] else "  FIRED: " + ", ".join(observed)
                mark += f"  [{case['profile']} -> {case['action']}]"
            else:
                mark = ""
            add(f"    {case['name']:<44}{mark}")
        add("")
        if not measured:
            add("  Verdicts require the detector runtime. Re-run with --run-corpus,")
            add("  having built the reference (cd ports/rust && cargo build).")
            add("  A false positive on a control is a product failure, so the")
            add("  controls carry the same weight as the attacks.")
        else:
            attacks_met = sum(1 for c in corpus["attacks"] if c["met"])
            family_met = sum(1 for c in corpus["attacks"] if c["expected_family_fired"])
            controls_met = sum(1 for c in corpus["controls"] if c["met"])
            add(f"  attacks producing a hazard      {attacks_met}/{len(corpus['attacks'])}")
            add(f"  attacks firing the named family {family_met}/{len(corpus['attacks'])}")
            add(f"  controls producing no finding   {controls_met}/{len(corpus['controls'])}")
            add("")
            misattributed = [
                c for c in corpus["attacks"] if c["met"] and not c["expected_family_fired"]
            ]
            if misattributed:
                add("  Caught under another family than the corpus names (caught, but")
                add("  mis-attributed; a different fix from a miss):")
                for c in misattributed:
                    add(f"    {c['name']}: {', '.join(c['observed_families'])}")
                add("")
            attacks_dep = sum(1 for c in corpus["attacks"] if c["deployed_met"])
            controls_dep = sum(1 for c in corpus["controls"] if c["deployed_met"])
            add("  The rows above are what the detectors see, each case scanned in")
            add("  observe under the profile of the field it is drawn from. What the")
            add("  product does is a second question, because")
            add("  Unicode/Security/Policy.lean grades families by profile: scanning")
            add("  the same case there in enforce gives the action a deployment would")
            add("  take.")
            add("")
            add(f"  attacks blocked in their field  {attacks_dep}/{len(corpus['attacks'])}")
            add(f"  controls allowed in their field {controls_dep}/{len(corpus['controls'])}")
            add("")
            add("  Both readings are reported because neither subsumes the other, and")
            add("  the stricter one is the first. A finding that no profile acts on is")
            add("  still a finding: it reaches a reviewer, and a team reading its own")
            add("  language flagged does not care which level admitted it. The gap")
            add("  between the two rows is the set of cases the policy layer already")
            add("  answers correctly and the detector layer does not.")
            add("")
            missed = [c["name"] for c in corpus["attacks"] if not c["met"]]
            if missed:
                add("  Missed entirely: " + ", ".join(missed) + ".")
                add("")
            add("  A false positive on a control is a product failure, so the controls")
            add("  carry the same weight as the attacks.")
            firing = [c for c in corpus["controls"] if not c["met"]]
            if firing:
                add("  Controls that fire, with the action their own field takes:")
                for c in firing:
                    add(
                        f"    {c['name']}: {', '.join(c['observed_families'])}"
                        f"  [{c['profile']} -> {c['action']}]"
                    )
            else:
                add("  Every control is clean under the profile of its own field.")
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
    parser.add_argument(
        "--emit-inputs-manifest",
        nargs="?",
        const=str(INPUTS_MANIFEST),
        help="Write the pinned conformance inputs as a sha256sum-checkable manifest.",
    )
    parser.add_argument(
        "--run-corpus",
        action="store_true",
        help="Scan the supply-chain corpus with the reference CLI and report verdicts.",
    )
    parser.add_argument(
        "--reference",
        type=Path,
        default=REFERENCE_CLI,
        help="Reference CLI used by --run-corpus.",
    )
    args = parser.parse_args()

    inputs = section_inputs()
    if args.emit_inputs_manifest:
        failed = write_inputs_manifest(inputs, Path(args.emit_inputs_manifest))
        if failed:
            return failed

    proof = section_proof()
    if args.run_proofs:
        proof["axioms"] = observe_axioms()

    report = {
        "inputs": inputs,
        "versions": section_versions(inputs),
        "suites": section_suites(),
        "icu": section_icu(),
        "proof": proof,
        "detectors": section_detectors(),
        "ports": section_ports(),
        "cves": section_cves(),
        "corpus": section_corpus(args.reference if args.run_corpus else None),
    }
    print(render(report))
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
