#!/usr/bin/env python3
"""Fail if the documentation cites a Lean declaration that does not exist.

The Markdown under this repository names theorems, definitions and modules as the
evidence behind its claims. A name that no longer resolves reads exactly like one
that does, so a renamed or never-written declaration leaves the claim standing and
unchecked. This gate resolves every cited name against the Lean sources.

A citation is a backticked dotted name such as `Conformance.GraphemeBreakTest.all_pass`.
Brace alternation is expanded first, so `Conformance.{A,B}Test.all_pass` is two
citations; that form is why the missing names this gate was written for went
unnoticed by a plain search.

Two rules keep the gate precise. Scope: a citation is checked only when its first
component is a segment of this repository's own module tree, which leaves prose
such as `file.pdf.exe` or `latency_ms.batch` alone. Resolution: the whole dotted
path must match a module file or a fully qualified declaration, prefix-matched
against the namespace it sits in, so a citation that names the right leaf under
the wrong namespace is still a miss.

Usage:  scripts/check-doc-claims.py
Source-only; reads the Lean files as text and does not invoke a toolchain.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# A citation names Lean, not a file. Anything carrying one of these suffixes is a
# path the prose points at and is resolved by the reader, not by this gate.
FILE_SUFFIXES = (
    ".txt", ".lean", ".json", ".md", ".sh", ".py", ".yml", ".yaml",
    ".toml", ".rs", ".hs", ".go", ".ts", ".cs", ".zig", ".rb", ".php",
    ".lua", ".ex", ".erl", ".cbl", ".swift", ".java", ".nix", ".c", ".h",
    ".lock", ".exe", ".pdf",
)

DECL_KEYWORDS = (
    "theorem", "def", "abbrev", "structure", "inductive", "class",
    "instance", "opaque", "axiom",
)

CITATION = re.compile(r"`([A-Za-z_][A-Za-z0-9_.{},']*\.[A-Za-z_][A-Za-z0-9_{},']*)`")
BRACE = re.compile(r"\{([^{}]*)\}")
NAMESPACE = re.compile(r"^\s*namespace\s+([A-Za-z_][A-Za-z0-9_.']*)", re.MULTILINE)
END = re.compile(r"^\s*end\s+([A-Za-z_][A-Za-z0-9_.']*)", re.MULTILINE)
DECL = re.compile(
    r"^\s*(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+|partial\s+|unsafe\s+|noncomputable\s+)*"
    r"(?:" + "|".join(DECL_KEYWORDS) + r")\s+([A-Za-z_][A-Za-z0-9_.']*)",
    re.MULTILINE,
)


def expand_braces(name):
    """Every alternative a brace-alternated citation stands for."""
    match = BRACE.search(name)
    if match is None:
        return [name]
    out = []
    for option in match.group(1).split(","):
        expanded = name[: match.start()] + option.strip() + name[match.end() :]
        out.extend(expand_braces(expanded))
    return out


def code_lines(text):
    """The lines of `text` that are Lean code, with comments removed.

    Prose inside a block comment can open with the word `namespace` — a
    docstring ending "...resolved in the enclosing namespace directly." reads as
    a namespace declaration to a line-wise scan, and the bogus level it pushes
    then mis-qualifies every declaration beneath it.
    """
    depth = 0
    for raw in text.splitlines():
        line = ""
        i = 0
        while i < len(raw):
            if raw.startswith("/-", i):
                depth += 1
                i += 2
            elif raw.startswith("-/", i):
                depth = max(0, depth - 1)
                i += 2
            elif depth == 0 and raw.startswith("--", i):
                break
            else:
                if depth == 0:
                    line += raw[i]
                i += 1
        yield line


def lean_files():
    files = sorted(ROOT.glob("Unicode/**/*.lean"))
    root_module = ROOT / "Unicode.lean"
    if root_module.is_file():
        files.append(root_module)
    return files


def qualified_names():
    """Every module path and fully qualified declaration under `Unicode/`.

    Namespaces are tracked as a stack so a declaration is recorded under the
    namespace actually open at its line, rather than under the file's first one.
    """
    names = set()

    def add_with_prefixes(qualified):
        """Record `qualified` and every dotted prefix of it.

        A namespace is written in one line as `namespace Unicode.Bidi.Algorithm`,
        which opens `Unicode.Bidi` as well; documentation cites the intermediate
        levels, so they have to be known too.
        """
        parts = qualified.split(".")
        for i in range(1, len(parts) + 1):
            names.add(".".join(parts[:i]))

    for path in lean_files():
        add_with_prefixes(".".join(path.relative_to(ROOT).with_suffix("").parts))
        text = path.read_text(encoding="utf-8", errors="replace")
        stack = []
        for line in code_lines(text):
            opened = NAMESPACE.match(line)
            if opened is not None:
                stack.append(opened.group(1))
                add_with_prefixes(".".join(stack))
                continue
            closed = END.match(line)
            if closed is not None:
                if stack and stack[-1] == closed.group(1):
                    stack.pop()
                continue
            declared = DECL.match(line)
            if declared is not None:
                names.add(".".join(stack + [declared.group(1)]))
    return names


def scope_segments(names):
    """First components a citation may legitimately start with."""
    segments = set()
    for name in names:
        for part in name.split("."):
            segments.add(part)
    return segments


def resolves(name, names):
    """Whether `name` matches a known path, allowing an elided leading prefix.

    Documentation writes `Conformance.IdnaTestV2` for what Lean calls
    `Unicode.Conformance.IdnaTestV2`, so a citation resolves when it is a
    dot-aligned suffix of a known qualified name.
    """
    if name in names:
        return True
    suffix = "." + name
    return any(known.endswith(suffix) for known in names)


def main():
    names = qualified_names()
    segments = scope_segments(names)
    # A changelog records what each release did, including declarations a later
    # release renamed or removed. Those entries are correct as history and are
    # not claims about the tree as it stands.
    docs = [p for p in sorted(ROOT.glob("*.md")) if p.name != "CHANGELOG.md"]
    docs += sorted(ROOT.glob("docs/**/*.md"))
    missing = []
    checked = 0
    for path in docs:
        text = path.read_text(encoding="utf-8", errors="replace")
        for raw in CITATION.findall(text):
            for name in expand_braces(raw):
                if name.endswith(FILE_SUFFIXES):
                    continue
                parts = name.split(".")
                if any(part == "" for part in parts):
                    continue
                if parts[0] not in segments:
                    continue
                checked += 1
                if not resolves(name, names):
                    missing.append((path.relative_to(ROOT), name))

    if missing:
        print(
            f"FATAL: {len(missing)} documented Lean citation(s) resolve to nothing "
            f"under Unicode/:"
        )
        for path, name in sorted(set(missing)):
            print(f"  {path}: {name}")
        return 1

    print(f"clean: {checked} documented Lean citation(s) resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
