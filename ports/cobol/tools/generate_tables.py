#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = ROOT / "src" / "generated"


def strip_comment(line):
    return line.split("#", 1)[0].strip()


def parse_range_token(token):
    if ".." in token:
        lo, hi = token.split("..", 1)
        return int(lo, 16), int(hi, 16)
    value = int(token, 16)
    return value, value


def coalesce(ranges):
    ranges = sorted(ranges)
    out = []
    for lo, hi in ranges:
        if not out or lo > out[-1][1] + 1:
            out.append([lo, hi])
        else:
            out[-1][1] = max(out[-1][1], hi)
    return [(lo, hi) for lo, hi in out]


def codepoints(field):
    return [int(part, 16) for part in field.split() if part]


def parse_property_ranges(path, wanted):
    ranges = []
    for line in path.read_text(encoding="utf-8").splitlines():
        body = strip_comment(line)
        if not body or ";" not in body:
            continue
        left, prop, *_ = [part.strip() for part in body.split(";")]
        if prop in wanted:
            ranges.append(parse_range_token(left))
    return coalesce(ranges)


def parse_bidi_ranges(path):
    ranges = []
    for line in path.read_text(encoding="utf-8").splitlines():
        body = strip_comment(line)
        if not body or ";" not in body:
            continue
        left, klass, *_ = [part.strip() for part in body.split(";")]
        if klass in {"R", "AL"}:
            ranges.append(parse_range_token(left))
    return coalesce(ranges)


def parse_script_ranges(path):
    wanted = {"Latin": "LATN", "Greek": "GREK", "Cyrillic": "CYRL"}
    ranges = {value: [] for value in wanted.values()}
    for line in path.read_text(encoding="utf-8").splitlines():
        body = strip_comment(line)
        if not body or ";" not in body:
            continue
        left, script, *_ = [part.strip() for part in body.split(";")]
        if script in wanted:
            ranges[wanted[script]].append(parse_range_token(left))
    return {script: coalesce(items) for script, items in ranges.items()}


def parse_variation_pairs():
    pairs = set()
    for name in ("StandardizedVariants.txt", "emoji-variation-sequences.txt"):
        for line in (DATA / name).read_text(encoding="utf-8").splitlines():
            body = strip_comment(line)
            if not body or ";" not in body:
                continue
            cps = codepoints(body.split(";", 1)[0])
            if len(cps) >= 2:
                pairs.add((cps[0], cps[1]))
    return sorted(pairs)


def parse_confusable_sources():
    values = set()
    for line in (DATA / "confusables.txt").read_text(encoding="utf-8").splitlines():
        body = strip_comment(line)
        if not body or ";" not in body:
            continue
        left = body.split(";", 1)[0].strip()
        if left:
            values.add(int(left, 16))
    return sorted(values)


def emit_range_eval(path, ranges, success_line):
    lines = ["EVALUATE TRUE"]
    for lo, hi in ranges:
        if lo == hi:
            lines.append(f"    WHEN LOOKUP-CP = {lo}")
        else:
            lines.append(f"    WHEN LOOKUP-CP >= {lo} AND LOOKUP-CP <= {hi}")
    lines.append(f"        {success_line}")
    lines.append("END-EVALUATE.")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def emit_value_eval(path, values, success_line):
    lines = ["EVALUATE LOOKUP-CP"]
    for value in values:
        lines.append(f"    WHEN {value}")
    lines.append(f"        {success_line}")
    lines.append("END-EVALUATE.")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def emit_variation_pairs(path, pairs):
    lines = ["EVALUATE TRUE"]
    for base, vs in pairs:
        lines.append(f"    WHEN PAIR-BASE = {base} AND PAIR-VS = {vs}")
    lines.append("        MOVE 1 TO TABLE-FLAG")
    lines.append("END-EVALUATE.")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def emit_script_flags(path, script_ranges):
    lines = ["EVALUATE TRUE"]
    for script, ranges in script_ranges.items():
        for lo, hi in ranges:
            if lo == hi:
                lines.append(f"    WHEN LOOKUP-CP = {lo}")
            else:
                lines.append(f"    WHEN LOOKUP-CP >= {lo} AND LOOKUP-CP <= {hi}")
            lines.append(f"        MOVE 1 TO HAS-{script}")
    lines.append("END-EVALUATE.")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    emit_variation_pairs(OUT / "legal_variation.cpy", parse_variation_pairs())
    emit_value_eval(OUT / "confusable_source.cpy", parse_confusable_sources(), "MOVE 1 TO TABLE-FLAG")
    emit_script_flags(OUT / "script_flags.cpy", parse_script_ranges(DATA / "Scripts.txt"))
    emit_range_eval(OUT / "strong_rtl.cpy", parse_bidi_ranges(DATA / "DerivedBidiClass.txt"), "MOVE 1 TO TABLE-FLAG")
    emit_range_eval(
        OUT / "default_ignorable.cpy",
        parse_property_ranges(DATA / "DerivedCoreProperties.txt", {"Default_Ignorable_Code_Point"}),
        "MOVE 1 TO TABLE-FLAG",
    )
    print("generated COBOL Unicode lookup copybooks")


if __name__ == "__main__":
    main()
