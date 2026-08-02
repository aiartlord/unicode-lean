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


# ─────────────────────────────────────────────────────────────────────
# NFC support tables: canonical combining class, full canonical
# decomposition, and the canonical composition map.  These mirror the
# verified Rust reference `security/identity/ucd.rs` byte for byte:
# `ccc`, `canonical_decompose` (fully expanded here so the COBOL side
# needs only a single-level lookup), and `build_composition_table`.
# ─────────────────────────────────────────────────────────────────────

HANGUL_S_BASE = 0xAC00
HANGUL_L_BASE = 0x1100
HANGUL_V_BASE = 0x1161
HANGUL_T_BASE = 0x11A7
HANGUL_L_COUNT = 19
HANGUL_V_COUNT = 21
HANGUL_T_COUNT = 28
HANGUL_N_COUNT = HANGUL_V_COUNT * HANGUL_T_COUNT
HANGUL_S_COUNT = HANGUL_L_COUNT * HANGUL_N_COUNT


def parse_unicode_data():
    """cp -> (ccc, canonical_decomp | None), canonical only (no <tag>)."""
    table = {}
    for line in (DATA / "UnicodeData.txt").read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(";")
        if len(fields) < 6:
            continue
        cp = int(fields[0], 16)
        ccc = int(fields[3])
        decomp_field = fields[5].strip()
        canonical = None
        if decomp_field and not decomp_field.startswith("<"):
            canonical = [int(part, 16) for part in decomp_field.split() if part]
        table[cp] = (ccc, canonical)
    return table


def hangul_decompose(cp):
    if cp < HANGUL_S_BASE or cp >= HANGUL_S_BASE + HANGUL_S_COUNT:
        return None
    s_index = cp - HANGUL_S_BASE
    out = [
        HANGUL_L_BASE + s_index // HANGUL_N_COUNT,
        HANGUL_V_BASE + (s_index % HANGUL_N_COUNT) // HANGUL_T_COUNT,
    ]
    t_index = s_index % HANGUL_T_COUNT
    if t_index != 0:
        out.append(HANGUL_T_BASE + t_index)
    return out


def full_decompose(cp, table, out):
    hangul = hangul_decompose(cp)
    if hangul is not None:
        for child in hangul:
            full_decompose(child, table, out)
        return
    entry = table.get(cp)
    if entry is not None and entry[1] is not None:
        for child in entry[1]:
            full_decompose(child, table, out)
        return
    out.append(cp)


def parse_composition_exclusions():
    out = set()
    for line in (DATA / "CompositionExclusions.txt").read_text(encoding="utf-8").splitlines():
        stripped = strip_comment(line)
        if stripped:
            out.add(int(stripped, 16))
    return out


def emit_ccc_class(path, table):
    by_class = {}
    for cp, (ccc, _decomp) in table.items():
        if ccc != 0:
            by_class.setdefault(ccc, []).append((cp, cp))
    entries = []
    for ccc, ranges in sorted(by_class.items()):
        for lo, hi in coalesce(ranges):
            entries.append((lo, hi, ccc))
    entries.sort()
    lines = ["EVALUATE TRUE"]
    for lo, hi, ccc in entries:
        if lo == hi:
            lines.append(f"    WHEN LOOKUP-CP = {lo}")
        else:
            lines.append(f"    WHEN LOOKUP-CP >= {lo} AND LOOKUP-CP <= {hi}")
        lines.append(f"        MOVE {ccc} TO CCC-VAL")
    lines.append("END-EVALUATE.")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def emit_canonical_decomp(path, table):
    lines = ["EVALUATE LOOKUP-CP"]
    for cp in sorted(table):
        _ccc, canonical = table[cp]
        if canonical is None:
            continue
        full = []
        full_decompose(cp, table, full)
        # A codepoint whose full decomposition is itself carries no mapping.
        if full == [cp]:
            continue
        lines.append(f"    WHEN {cp}")
        lines.append(f"        MOVE {len(full)} TO DEC-LEN")
        for slot, child in enumerate(full, start=1):
            lines.append(f"        MOVE {child} TO DEC-CP ({slot})")
        lines.append("        MOVE 1 TO DEC-FOUND")
    lines.append("END-EVALUATE.")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def emit_composition(path, table, exclusions):
    ccc_of = {cp: ccc for cp, (ccc, _d) in table.items()}
    pairs = []
    for cp in sorted(table):
        _ccc, canonical = table[cp]
        if canonical is None or len(canonical) != 2:
            continue
        if cp in exclusions:
            continue
        if ccc_of.get(canonical[0], 0) != 0:
            continue
        pairs.append((canonical[0], canonical[1], cp))
    lines = ["EVALUATE TRUE"]
    for first, second, cp in pairs:
        lines.append(f"    WHEN COMP-A = {first} AND COMP-B = {second}")
        lines.append(f"        MOVE {cp} TO COMP-RESULT")
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
    ucd = parse_unicode_data()
    exclusions = parse_composition_exclusions()
    emit_ccc_class(OUT / "ccc_class.cpy", ucd)
    emit_canonical_decomp(OUT / "canonical_decomp.cpy", ucd)
    emit_composition(OUT / "canonical_compose.cpy", ucd, exclusions)
    print("generated COBOL Unicode lookup copybooks")


if __name__ == "__main__":
    main()
