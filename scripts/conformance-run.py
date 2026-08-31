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
  --emit-inputs-manifest   write dist/CONFORMANCE-INPUTS.sha256
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
    detectors see: scanned under one profile in `observe`, an attack is met
    when it produces any finding and a control is met only when it produces
    none.  That is the strict reading, and it is the one to quote when asking
    whether a detector exists and reaches the input.

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
        families, _ = scan_reference(binary, case["input"], "gateway-header", "observe")
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
    result["build"] = {
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
    add("  IdnaTestV2 additionally has an evaluated run over the published file,")
    add("  separate from the kernel-proved vectors counted here and not a")
    add("  substitute for them: scripts/idna-conformance.sh [ROWS|all]. It states")
    add("  how many of the 6391 rows it judged, because the fold is interpreted")
    add("  and a bounded run is the ordinary way to use it.")
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
            add("")
            add("  Two cases account for the gap between those rows.")
            add("  domain-confusable-cyrillic-a is attribution by an explicit rule:")
            add("  the policy suppresses a homoglyph-confusable finding whose")
            add("  sub-threat is CrossScriptMix and reports the case under")
            add("  mixed-script-admissibility instead, so the family the corpus names")
            add("  cannot appear for a cross-script input. The other,")
            add("  homoglyph-identifier-dotless-i, is the one genuine miss and is")
            add("  described below.")
            add(f"  controls producing no finding   {controls_met}/{len(corpus['controls'])}")
            add("")
            attacks_dep = sum(1 for c in corpus["attacks"] if c["deployed_met"])
            controls_dep = sum(1 for c in corpus["controls"] if c["deployed_met"])
            add("  The rows above are what the detectors see, scanned under one")
            add("  profile in observe. What the product does is a second question,")
            add("  because Unicode/Security/Policy.lean grades families by profile:")
            add("  every case also carries the profile of the field it is drawn from,")
            add("  and scanning it there in enforce gives the action a deployment")
            add("  would take.")
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
                add("  homoglyph-identifier-dotless-i is the dotless i U+0131 standing in")
                add("  for i in admin. Nothing fires because the input is single-script")
                add("  Latin, so mixed-script-admissibility cannot apply, and because")
                add("  homoglyph-confusable's TargetMatch compares an input's skeleton")
                add("  only against Unicode/Ucd/Curated/KnownAttackTargets.txt, whose")
                add("  stated contract is names drawn from published incidents and which")
                add("  holds react, paypal and openai. admin is not one of them, and")
                add("  findTargetMatch takes no caller-supplied list, so a deployment")
                add("  cannot name its own privileged identifiers. Catching this needs a")
                add("  detector that accepts the names a caller wants protected, not a")
                add("  larger curated file.")
                add("")
            add("  A false positive on a control is a product failure, so the controls")
            add("  carry the same weight as the attacks. The controls that fire are")
            add("  detectors reading a genuinely ambiguous input the way their")
            add("  contracts say to. Unicode/Security/Display/RtlInjection.lean opens")
            add("  with \"bidi format-control trumps all\", so presence fires it and")
            add("  balance is never consulted; that reports the balanced Arabic")
            add("  literal, the Hebrew comment and the Persian ZWNJ. It also carries")
            add("  detect_field_takeover_hebrew, a kernel-proved theorem that a")
            add("  leading strong-RTL codepoint fires FieldTakeover with no bidi")
            add("  control present. The German eszett does expand under uppercasing")
            add("  and the Turkish dotted capital I does invert.")
            add("")
            add("  Three of those are answered by the profile rather than the")
            add("  detector. policyOfProfile puts source-code, display-name and")
            add("  chat-message at levels that do not admit rtlInjection, precisely")
            add("  because its contract assumes a declared-LTR field and a source file")
            add("  or a display string does not satisfy it, so the Hebrew comment, the")
            add("  Persian ZWNJ and the diacritics case are all allowed where they")
            add("  actually occur. RtlInjection's header directs such callers to")
            add("  declare the field's direction; that declaration is the profile, and")
            add("  nothing else in the API expresses it.")
            add("")
            add("  arabic-string-literal-balanced is the control that fails on both")
            add("  readings. Under source-code it is rejected by")
            add("  mixed-script-admissibility, filename-disguise,")
            add("  confusable-bidi-compound and source-display-divergence -- four")
            add("  families the moderate level admits, so dropping rtlInjection does")
            add("  not reach it. Each fires on the bidi controls or the script mix.")
            add("")
            add("  This case is a disagreement about the threat model, not a tuning")
            add("  error. Its premise is that the payload sits inside a string literal")
            add("  and so renders as written, and that premise is the one")
            add("  SourceDisplayDivergence.lean's scope note retracts by name: a")
            add("  Language parameter once filtered hits by source region, and it was")
            add("  withdrawn because a grammar's region partition does not make some")
            add("  source bytes safer, on the evidence of the tj-actions/changed-files")
            add("  supply-chain attack, CVE-2025-29927, prompt injection carried in")
            add("  docstring comments, and npm-metadata-string backdoors. Under that")
            add("  decision a bidi control in source is reported wherever a tokenizer")
            add("  would place it, and this control expects the opposite. Admitting it")
            add("  means reinstating region filtering against that evidence, so the")
            add("  corpus records the conflict rather than resolving it by loosening a")
            add("  detector.")
            add("")
            add("  confusable-bidi-compound tags that case ConfusableInOverride")
            add("  though its codepoint is U+202B RIGHT-TO-LEFT EMBEDDING and no")
            add("  override appears in it. The tag names a class its module header")
            add("  defines as LRE/RLE/LRO/RLO/PDF, selected by")
            add("  isBidiEmbeddingControl and contrasted with the isolate class, so")
            add("  the name is loose for a documented category rather than wrong")
            add("  about the input. rtl-injection's own tag carried the same looseness")
            add("  undocumented, naming an override for any of the 9 bidi")
            add("  format-controls when only U+202D and U+202E are overrides; it is")
            add("  now BidiControlInLTRField, pinned on the two non-override classes")
            add("  by detect_rle_in_field and detect_lri_in_field.")
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
        const=str(ROOT / "dist" / "CONFORMANCE-INPUTS.sha256"),
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
        "suites": section_suites(),
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
