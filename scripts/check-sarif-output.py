#!/usr/bin/env python3
"""Validate a SARIF log the scanner emits, as a code-scanning platform would.

Two checks, both required:

  1. The log validates against the SARIF 2.1.0 JSON schema vendored at
     `fixtures/sarif/sarif-schema-2.1.0.json`. The schema is pinned by SHA-256
     below; a schema that does not match the pin is refused, so the check
     cannot be weakened by editing the fixture.

  2. The log satisfies the ingestion rules GitHub code scanning applies on
     upload, which the schema does not express: at most 20 runs per file,
     25,000 results and 25,000 rules per run, 1,000 locations per result and
     20 tags per rule; every result names a rule the driver declares, carries a
     message and a level the platform grades, and locates itself by a
     relative artifact URI whose region, when it states a line, starts at
     line 1 or later.

Usage:

  scripts/check-sarif-output.py --log PATH
      validate an existing log (`-` reads stdin)

  scripts/check-sarif-output.py --binary CLI [--corpus PATH]
      scan the supply-chain corpus through `CLI scan --jsonl --sarif` and
      validate what comes out; the default corpus is
      fixtures/security/supply-chain-corpus.json

Exit status is 0 only when both checks pass. Every violation is printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"
SCHEMA_SHA256 = "7c9688f0a1c4a4e1649ecc78521087e664729c1dff56ee8212ff195c7b16132a"
CORPUS = ROOT / "fixtures" / "security" / "supply-chain-corpus.json"

LEVELS = {"none", "note", "warning", "error"}
MAX_RUNS = 20
MAX_RESULTS_PER_RUN = 25_000
MAX_RULES_PER_RUN = 25_000
MAX_LOCATIONS_PER_RESULT = 1_000
MAX_TAGS_PER_RULE = 20


def load_schema() -> dict:
    raw = SCHEMA.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SCHEMA_SHA256:
        print(f"FATAL: {SCHEMA} sha256 {digest} != pinned {SCHEMA_SHA256}", file=sys.stderr)
        raise SystemExit(1)
    return json.loads(raw)


def schema_violations(log: object, schema: dict) -> list[str]:
    validator = jsonschema.Draft7Validator(schema)
    out = []
    for error in sorted(validator.iter_errors(log), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in error.absolute_path) or "<root>"
        out.append(f"schema: {where}: {error.message}")
    return out


def relative_uri(uri: str) -> bool:
    if not uri:
        return False
    if "://" in uri or uri.startswith("/") or uri.startswith("\\"):
        return False
    return True


def ingestion_violations(log: dict) -> list[str]:
    out = []
    if log.get("version") != "2.1.0":
        out.append(f"ingestion: version is {log.get('version')!r}, expected '2.1.0'")
    runs = log.get("runs", [])
    if not runs:
        out.append("ingestion: no runs")
    if len(runs) > MAX_RUNS:
        out.append(f"ingestion: {len(runs)} runs exceeds {MAX_RUNS}")
    for run_index, run in enumerate(runs):
        prefix = f"runs/{run_index}"
        driver = run.get("tool", {}).get("driver", {})
        if not driver.get("name"):
            out.append(f"ingestion: {prefix}: tool.driver.name missing")
        rules = driver.get("rules", [])
        if len(rules) > MAX_RULES_PER_RUN:
            out.append(f"ingestion: {prefix}: {len(rules)} rules exceeds {MAX_RULES_PER_RUN}")
        rule_ids = set()
        for rule_index, rule in enumerate(rules):
            rule_id = rule.get("id")
            if not rule_id:
                out.append(f"ingestion: {prefix}/rules/{rule_index}: id missing")
                continue
            if rule_id in rule_ids:
                out.append(f"ingestion: {prefix}/rules/{rule_index}: duplicate id {rule_id}")
            rule_ids.add(rule_id)
            tags = rule.get("properties", {}).get("tags", [])
            if len(tags) > MAX_TAGS_PER_RULE:
                out.append(f"ingestion: {prefix}/rules/{rule_index}: {len(tags)} tags exceeds {MAX_TAGS_PER_RULE}")
        results = run.get("results", [])
        if len(results) > MAX_RESULTS_PER_RUN:
            out.append(f"ingestion: {prefix}: {len(results)} results exceeds {MAX_RESULTS_PER_RUN}")
        for result_index, result in enumerate(results):
            where = f"{prefix}/results/{result_index}"
            rule_id = result.get("ruleId")
            if not rule_id:
                out.append(f"ingestion: {where}: ruleId missing")
            elif rule_id not in rule_ids:
                out.append(f"ingestion: {where}: ruleId {rule_id} not declared by the driver")
            level = result.get("level")
            if level not in LEVELS:
                out.append(f"ingestion: {where}: level {level!r} not one of {sorted(LEVELS)}")
            if not result.get("message", {}).get("text"):
                out.append(f"ingestion: {where}: message.text missing")
            locations = result.get("locations", [])
            if not locations:
                out.append(f"ingestion: {where}: no locations")
            if len(locations) > MAX_LOCATIONS_PER_RESULT:
                out.append(f"ingestion: {where}: {len(locations)} locations exceeds {MAX_LOCATIONS_PER_RESULT}")
            for location_index, location in enumerate(locations):
                physical = location.get("physicalLocation", {})
                uri = physical.get("artifactLocation", {}).get("uri", "")
                if not relative_uri(uri):
                    out.append(f"ingestion: {where}/locations/{location_index}: artifact uri {uri!r} is not a relative path")
                region = physical.get("region")
                if region is not None:
                    start_line = region.get("startLine")
                    if start_line is not None and start_line < 1:
                        out.append(f"ingestion: {where}/locations/{location_index}: startLine {start_line} < 1")
                    start_column = region.get("startColumn")
                    if start_column is not None and start_column < 1:
                        out.append(f"ingestion: {where}/locations/{location_index}: startColumn {start_column} < 1")
    return out


def corpus_jsonl(corpus_path: Path) -> bytes:
    """One JSONL record per corpus case, the input carried as UTF-8 bytes so a
    case built from surrogates or noncharacters reaches the scanner intact."""
    data = json.loads(corpus_path.read_text(encoding="utf-8"))
    lines = []
    for case in data.get("cases", []):
        text = "".join(chr(cp) for cp in case["input"])
        payload = list(text.encode("utf-8", "surrogatepass"))
        record = {
            "id": f"corpus/{case['name']}",
            "profile": case["profile"],
            "mode": "observe",
            "bytes": payload,
        }
        lines.append(json.dumps(record, separators=(",", ":")))
    return ("\n".join(lines) + "\n").encode("utf-8")


def scan_corpus(binary: Path, corpus_path: Path) -> bytes:
    completed = subprocess.run(
        [str(binary), "scan", "--jsonl", "--sarif"],
        input=corpus_jsonl(corpus_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode == 2:
        print(f"FATAL: scanner failed: {completed.stderr.decode('utf-8', 'replace')}", file=sys.stderr)
        raise SystemExit(1)
    return completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate scanner SARIF output.")
    parser.add_argument("--log", help="SARIF log to validate; '-' reads stdin.")
    parser.add_argument("--binary", type=Path, help="Scanner CLI; scans --corpus and validates the log.")
    parser.add_argument("--corpus", type=Path, default=CORPUS, help="Corpus scanned with --binary.")
    args = parser.parse_args()
    if (args.log is None) == (args.binary is None):
        parser.error("exactly one of --log or --binary is required")

    if args.log is not None:
        raw = sys.stdin.buffer.read() if args.log == "-" else Path(args.log).read_bytes()
        source = "stdin" if args.log == "-" else args.log
    else:
        raw = scan_corpus(args.binary, args.corpus)
        source = f"{args.binary} over {args.corpus}"

    try:
        log = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"FATAL: {source}: not JSON: {exc}", file=sys.stderr)
        return 1

    schema = load_schema()
    violations = schema_violations(log, schema)
    if isinstance(log, dict):
        violations += ingestion_violations(log)
    for violation in violations:
        print(violation)
    if violations:
        print(f"FATAL: {len(violations)} violation(s) in SARIF from {source}", file=sys.stderr)
        return 1
    runs = log.get("runs", [])
    results = sum(len(run.get("results", [])) for run in runs)
    rules = sum(len(run.get("tool", {}).get("driver", {}).get("rules", [])) for run in runs)
    print(
        f"clean: SARIF 2.1.0 from {source} — {len(runs)} run(s), {rules} rule(s), "
        f"{results} result(s), {len(raw)} bytes; schema and code-scanning ingestion rules hold"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
