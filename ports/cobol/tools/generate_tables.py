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


GCB_CODE = {
    "Prepend": 1,
    "CR": 2,
    "LF": 3,
    "Control": 4,
    "Extend": 5,
    "Regional_Indicator": 6,
    "SpacingMark": 7,
    "L": 8,
    "V": 9,
    "T": 10,
    "LV": 11,
    "LVT": 12,
    "ZWJ": 13,
}

INCB_CODE = {"Linker": 1, "Consonant": 2, "Extend": 3}


def parse_gcb_ranges(path):
    by_class = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        body = strip_comment(line)
        if not body or ";" not in body:
            continue
        left, prop, *_ = [part.strip() for part in body.split(";")]
        if prop in GCB_CODE:
            by_class.setdefault(GCB_CODE[prop], []).append(parse_range_token(left))
    out = []
    for code, ranges in sorted(by_class.items()):
        for lo, hi in coalesce(ranges):
            out.append((lo, hi, code))
    return out


def parse_incb_ranges(path):
    by_class = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        body = strip_comment(line)
        if not body or ";" not in body:
            continue
        fields = [part.strip() for part in body.split(";")]
        if len(fields) >= 3 and fields[1] == "InCB" and fields[2] in INCB_CODE:
            by_class.setdefault(INCB_CODE[fields[2]], []).append(parse_range_token(fields[0]))
    out = []
    for code, ranges in sorted(by_class.items()):
        for lo, hi in coalesce(ranges):
            out.append((lo, hi, code))
    return out


def parse_bip39_word_keys():
    keys = set()
    for path in sorted((DATA / "bip39").glob("*.txt")):
        for line in path.read_text(encoding="utf-8").splitlines():
            word = line.strip()
            if word:
                keys.add(",".join(str(ord(ch)) for ch in word))
    return sorted(keys)


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


def emit_class_eval(path, entries, target):
    lines = ["EVALUATE TRUE"]
    for lo, hi, code in entries:
        if lo == hi:
            lines.append(f"    WHEN LOOKUP-CP = {lo}")
        else:
            lines.append(f"    WHEN LOOKUP-CP >= {lo} AND LOOKUP-CP <= {hi}")
        lines.append(f"        MOVE {code} TO {target}")
    lines.append("END-EVALUATE.")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def emit_bip39_words(path, keys):
    lines = ["EVALUATE FUNCTION TRIM(WORD-KEY)"]
    for key in keys:
        lines.append(f"    WHEN \"{key}\"")
    lines.append("        MOVE 1 TO TABLE-FLAG")
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
    emit_bip39_words(OUT / "bip39_words.cpy", parse_bip39_word_keys())
    emit_class_eval(OUT / "gcb_class.cpy", parse_gcb_ranges(DATA / "GraphemeBreakProperty.txt"), "GCB-CLASS")
    emit_class_eval(OUT / "incb_class.cpy", parse_incb_ranges(DATA / "DerivedCoreProperties.txt"), "INCB-CLASS")
    emit_range_eval(
        OUT / "extpict.cpy",
        parse_property_ranges(DATA / "emoji-data.txt", {"Extended_Pictographic"}),
        "MOVE 1 TO IS-EP-FLAG",
    )
    print("generated COBOL Unicode lookup copybooks")


if __name__ == "__main__":
    main()
