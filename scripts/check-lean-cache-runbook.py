#!/usr/bin/env python3
"""Validate Lean-cache runbook command examples without invoking Lean."""

from __future__ import annotations

from pathlib import Path
import shlex
import subprocess
import sys


def bash_commands(markdown: str) -> list[str]:
    commands: list[str] = []
    in_bash = False
    current: list[str] = []

    for line in markdown.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_bash:
                if current:
                    commands.append(" ".join(current))
                    current = []
                in_bash = False
            else:
                in_bash = stripped in {"```bash", "```sh"}
            continue

        if not in_bash or not stripped:
            continue

        if stripped.endswith("\\"):
            current.append(stripped[:-1].strip())
        else:
            current.append(stripped)
            commands.append(" ".join(current))
            current = []

    return commands


def run(command: list[str]) -> tuple[int, str]:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout


def main() -> int:
    path = Path("docs/RUNBOOK.md")
    commands = bash_commands(path.read_text(encoding="utf-8"))
    failed = False

    for command in commands:
        fields = shlex.split(command)
        if not fields:
            continue
        exe = fields[0]
        if exe == "scripts/lean-cache-stages.py":
            status, output = run(fields + ["--validate-args-only"])
            if status != 0:
                print(f"runbook command failed to parse: {command}\n{output}", file=sys.stderr)
                failed = True
            continue
        if exe.startswith("scripts/"):
            local = Path(exe)
            if not local.exists():
                print(f"runbook references missing script: {exe}", file=sys.stderr)
                failed = True

    if failed:
        return 1
    print("clean: Lean cache runbook commands parse")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
