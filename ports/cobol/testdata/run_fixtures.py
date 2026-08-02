#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "usec"
FIXTURES = ROOT / "testdata" / "fixtures" / "security"


def load(rel):
    with (FIXTURES / rel).open("r", encoding="utf-8") as f:
        return json.load(f)


def run(op, profile, mode, values):
    arg = ",".join(str(v) for v in values)
    proc = subprocess.run(
        [str(BIN), op, profile, mode, arg],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    action = None
    codes = []
    positions = {}
    input_values = []
    for line in proc.stdout.splitlines():
        parts = line.split(" ", 2)
        if not parts:
            continue
        if parts[0] == "ACTION":
            action = parts[1]
        elif parts[0] == "INPUT":
            input_values = [int(x) for x in parts[1].split(",") if x]
        elif parts[0] == "FINDING":
            code = parts[1]
            codes.append(code)
            positions[code] = [int(x) for x in parts[2].split(",") if x] if len(parts) > 2 else []
    return {"action": action, "codes": codes, "positions": positions, "input": input_values}


def run_lines(op, values):
    arg = ",".join(str(v) for v in values)
    proc = subprocess.run(
        [str(BIN), op, "gateway-header", "observe", arg],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return proc.stdout.splitlines()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def cps(text):
    return [ord(ch) for ch in text]


def check_policy():
    fixture = load("policy_contract.json")
    for case in fixture["cases"]:
        got = run("scan", case["profile"], case["mode"], case["input"])
        require(got["action"] == case["action"], f"{case['name']} action {got['action']} != {case['action']}")
        for code in case["required_findings"]:
            require(code in got["codes"], f"{case['name']} missing {code}; got {got['codes']}")


def check_decode():
    fixture = load("decode_contract.json")
    for case in fixture["cases"]:
        got = run("scan-utf8", case["profile"], case["mode"], case["input_bytes"])
        require(got["action"] == case["action"], f"{case['name']} action {got['action']} != {case['action']}")
        require(got["input"] == case["input"], f"{case['name']} input {got['input']} != {case['input']}")
        for code in case["required_findings"]:
            require(code in got["codes"], f"{case['name']} missing {code}; got {got['codes']}")
        for expected in case.get("required_positions", []):
            require(got["positions"].get(expected["code"]) == expected["positions"],
                    f"{case['name']} positions for {expected['code']} {got['positions'].get(expected['code'])} != {expected['positions']}")


def check_multiencoding_decode():
    fixture = load("decode_multiencoding_contract.json")
    ops = {
        "utf-16le": "scan-utf16le",
        "utf-16be": "scan-utf16be",
        "utf-32le": "scan-utf32le",
        "utf-32be": "scan-utf32be",
    }
    for case in fixture["cases"]:
        got = run(ops[case["encoding"]], case["profile"], case["mode"], case["input_bytes"])
        require(got["action"] == case["action"], f"{case['name']} action {got['action']} != {case['action']}")
        require(got["input"] == case["input"], f"{case['name']} input {got['input']} != {case['input']}")
        for code in case["required_findings"]:
            require(code in got["codes"], f"{case['name']} missing {code}; got {got['codes']}")
        for expected in case.get("required_positions", []):
            require(got["positions"].get(expected["code"]) == expected["positions"],
                    f"{case['name']} positions for {expected['code']} {got['positions'].get(expected['code'])} != {expected['positions']}")


def check_verdict():
    fixture = load("verdict_contract.json")
    for case in fixture["cases"]:
        expected = case["verdict"]
        got = run("scan", case["profile"], case["mode"], case["input"])
        require(got["action"] == expected["action"], f"{case['name']} action {got['action']} != {expected['action']}")
        require(got["input"] == expected["input"], f"{case['name']} input {got['input']} != {expected['input']}")
        for finding in expected["findings"]:
            code = finding["code"]
            require(code in got["codes"], f"{case['name']} missing {code}; got {got['codes']}")
            require(got["positions"].get(code) == finding["positions"],
                    f"{case['name']} positions for {code} {got['positions'].get(code)} != {finding['positions']}")


def check_detectors():
    detector_files = [
        "tag_block_payload.json",
        "variation_selector_payload.json",
        "zero_width_payload.json",
        "surrogate_reassembly.json",
        "bidi_control_balance.json",
        "noncharacter_control.json",
        "homoglyph_confusable.json",
        "mixed_script_admissibility.json",
        "rtl_injection.json",
        "covert_display_compound.json",
        "confusable_bidi_compound.json",
    ]
    for name in detector_files:
        fixture = load(f"detectors/{name}")
        family = fixture["family"]
        needle = f".{family}."
        for case in fixture["cases"]:
            got = run("scan", "gateway-header", "observe", case["input"])
            for code in case["required_findings"]:
                require(code in got["codes"], f"{name}/{case['name']} missing {code}; got {got['codes']}")
            if not case["required_findings"]:
                require(all(needle not in code for code in got["codes"]),
                        f"{name}/{case['name']} unexpected family {family}; got {got['codes']}")


HIS_BASE = "unicode.security.K.hash-input-stability."


def run_his(values, enc="-", rfc="-", audit="-", webhook="-"):
    def fmt(side):
        if isinstance(side, list):
            return ",".join(str(v) for v in side)
        return side

    arg = ",".join(str(v) for v in values)
    proc = subprocess.run(
        [str(BIN), "hash-input-stability", "gateway-header", "observe",
         arg, enc, rfc, fmt(audit), fmt(webhook)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    codes = []
    positions = {}
    for line in proc.stdout.splitlines():
        parts = line.split(" ", 2)
        if parts and parts[0] == "FINDING":
            code = parts[1]
            codes.append(code)
            positions[code] = [int(x) for x in parts[2].split(",") if x] if len(parts) > 2 else []
    return {"codes": codes, "positions": positions}


def check_hash_input_stability():
    # 1. Shared context-free fixture (the empty-Context vectors).
    fixture = load("detectors/hash_input_stability.json")
    for case in fixture["cases"]:
        got = run_his(case["input"])
        for code in case["required_findings"]:
            require(code in got["codes"],
                    f"his/{case['name']} missing {code}; got {got['codes']}")
        if not case["required_findings"]:
            require(all(".hash-input-stability." not in code for code in got["codes"]),
                    f"his/{case['name']} unexpected finding; got {got['codes']}")

    # 2. Context vectors transcribed verbatim from the Rust reference's
    #    `#[test]` module comment block. tag = HIS_BASE + suffix; None = clear.
    context_vectors = [
        # (name, values, kwargs, expected_tag, expected_positions)
        ("enc-utf16", [0x61, 0x62, 0x63], {"enc": "utf-16"}, "EncodingMismatch", [0]),
        ("enc-surrogate", [0x61, 0xD800, 0x62], {"enc": "utf-8"}, "EncodingMismatch", [1]),
        ("enc-out-of-range", [0x61, 0x110000, 0x62], {"enc": "utf-8"}, "EncodingMismatch", [1]),
        ("enc-utf8-upper", [0x61, 0x62, 0x63], {"enc": "UTF-8"}, None, None),
        ("enc-utf8-lower", [0x61, 0x62, 0x63], {"enc": "utf-8"}, None, None),
        ("enc-utf8-nodash-upper", [0x61, 0x62, 0x63], {"enc": "UTF8"}, None, None),
        ("enc-utf8-nodash-lower", [0x61, 0x62, 0x63], {"enc": "utf8"}, None, None),
        ("rfc-pgp4880", [0x61, 0x20], {"rfc": "pgp4880TrailingWhitespace"}, "SignedMessageRule", [1]),
        ("rfc-pgp9580-bare-lf", [0x61, 0x0A, 0x62], {"rfc": "pgp9580LineEnding"}, "SignedMessageRule", [1]),
        ("rfc-pgp9580-crlf-clear", [0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66],
         {"rfc": "pgp9580LineEnding"}, None, None),
        ("rfc-8785-decomposed", [0x0065, 0x0301], {"rfc": "rfc8785NfcRequirement"}, "SignedMessageRule", [0]),
        ("rfc-8259-control", [0x61, 0x01, 0x62], {"rfc": "rfc8259ControlChar"}, "SignedMessageRule", [1]),
        ("rfc-7515-plus", [0x41, 0x2B, 0x42], {"rfc": "rfc7515JwsBase64Url"}, "SignedMessageRule", [1]),
        ("rfc-7515-clean-clear", [0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39],
         {"rfc": "rfc7515JwsBase64Url"}, None, None),
        ("rfc-6376-double-space", [0x61, 0x20, 0x20, 0x62], {"rfc": "rfc6376DkimRelaxed"}, "SignedMessageRule", [2]),
        ("rfc-6376-single-space-clear", [0x61, 0x20, 0x62], {"rfc": "rfc6376DkimRelaxed"}, None, None),
        ("rfc-5751-bare-lf", [0x61, 0x0A, 0x62], {"rfc": "rfc5751SmimeLineEnding"}, "SignedMessageRule", [1]),
        ("audit-divergence", [0x61, 0x62, 0x64], {"audit": [0x61, 0x62, 0x63]}, "AuditLogReinterpretation", [2]),
        ("audit-identical-clear", [0x61, 0x62, 0x63], {"audit": [0x61, 0x62, 0x63]}, None, None),
        ("webhook-drift", [0x61, 0x62, 0x63], {"webhook": [0x61, 0x62, 0x64]}, "WebhookSignatureDrift", [2]),
        ("webhook-match-clear", [0x61, 0x62, 0x63], {"webhook": [0x61, 0x62, 0x63]}, None, None),
        ("priority-encoding-over-rfc", [0x0065, 0x0301, 0x0A],
         {"enc": "utf-16", "rfc": "pgp9580LineEnding"}, "EncodingMismatch", [0]),
        ("priority-webhook-over-audit", [0x61, 0x62, 0x63],
         {"webhook": [0x61, 0x62, 0x65], "audit": [0x61, 0x62, 0x66]}, "WebhookSignatureDrift", [2]),
        ("priority-rfc-over-trailing", [0x61, 0x20],
         {"rfc": "pgp4880TrailingWhitespace"}, "SignedMessageRule", [1]),
    ]
    for name, values, kwargs, tag, expected_pos in context_vectors:
        got = run_his(values, **kwargs)
        his_codes = [c for c in got["codes"] if ".hash-input-stability." in c]
        if tag is None:
            require(not his_codes, f"his-ctx/{name} expected clear; got {his_codes}")
        else:
            code = HIS_BASE + tag
            require(code in got["codes"], f"his-ctx/{name} missing {code}; got {got['codes']}")
            require(got["positions"].get(code) == expected_pos,
                    f"his-ctx/{name} positions {got['positions'].get(code)} != {expected_pos}")
    return len(fixture["cases"]), len(context_vectors)


AWD_BASE = "unicode.security.K.ai-watermark-detectability."


def run_awd(values, zwsp_tol="-", adv_tol="-"):
    arg = ",".join(str(v) for v in values)
    proc = subprocess.run(
        [str(BIN), "ai-watermark-detectability", "gateway-header", "observe",
         arg, str(zwsp_tol), str(adv_tol)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    codes = []
    positions = {}
    for line in proc.stdout.splitlines():
        parts = line.split(" ", 2)
        if parts and parts[0] == "FINDING":
            code = parts[1]
            codes.append(code)
            positions[code] = [int(x) for x in parts[2].split(",") if x] if len(parts) > 2 else []
    return {"codes": codes, "positions": positions}


def check_ai_watermark_detectability():
    # 1. Shared context-free fixture (the empty-Context vectors).
    fixture = load("detectors/ai_watermark_detectability.json")
    for case in fixture["cases"]:
        got = run_awd(case["input"])
        for code in case["required_findings"]:
            require(code in got["codes"],
                    f"awd/{case['name']} missing {code}; got {got['codes']}")
        if not case["required_findings"]:
            require(all(".ai-watermark-detectability." not in code for code in got["codes"]),
                    f"awd/{case['name']} unexpected finding; got {got['codes']}")

    # 2. The two Context-tolerance vectors from the Rust reference's `#[test]`
    #    module: `detect_zwsp_jittered_tolerant_fires` (zwsp tol 1 fires the
    #    modulo probe on a jittered progression) and
    #    `detect_with_context_default_matches_detect` (the empty Context agrees
    #    with bare `detect`).
    jittered = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65]
    got = run_awd(jittered, zwsp_tol=1)
    code = AWD_BASE + "Gpt5ZwspModulo"
    require(code in got["codes"],
            f"awd-ctx/zwsp-jittered-tolerant missing {code}; got {got['codes']}")

    nnbsp = [0x61, 0x202F, 0x62]
    default_ctx = run_awd(nnbsp, zwsp_tol=0, adv_tol=0)
    bare = run_awd(nnbsp)
    require(default_ctx["codes"] == bare["codes"],
            f"awd-ctx/default-matches codes {default_ctx['codes']} != {bare['codes']}")
    require(AWD_BASE + "NnbspBoundary" in default_ctx["codes"],
            f"awd-ctx/default-matches missing NnbspBoundary; got {default_ctx['codes']}")
    return len(fixture["cases"]), 2


EZWJ_BASE = "unicode.security.I.emoji-zwj-integrity."


def run_ezwj(values):
    arg = ",".join(str(v) for v in values)
    proc = subprocess.run(
        [str(BIN), "emoji-zwj-integrity", "gateway-header", "observe", arg],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    codes = []
    positions = {}
    for line in proc.stdout.splitlines():
        parts = line.split(" ", 2)
        if parts and parts[0] == "FINDING":
            code = parts[1]
            codes.append(code)
            positions[code] = [int(x) for x in parts[2].split(",") if x] if len(parts) > 2 else []
    return {"codes": codes, "positions": positions}


def check_emoji_zwj_integrity():
    # 1. The 12 shared context-free fixture vectors.
    fixture = load("detectors/emoji_zwj_integrity.json")
    for case in fixture["cases"]:
        got = run_ezwj(case["input"])
        for code in case["required_findings"]:
            require(code in got["codes"],
                    f"ezwj/{case['name']} missing {code}; got {got['codes']}")
        if not case["required_findings"]:
            require(all(".emoji-zwj-integrity." not in code for code in got["codes"]),
                    f"ezwj/{case['name']} unexpected finding; got {got['codes']}")

    # 2. The 11 spot-checks transcribed verbatim from the Rust reference's
    #    `#[test]` module (empty / ascii / plain-emoji / one-skintone /
    #    family-rgi / double-zwj / non-emoji-injection / skin-tone-overflow /
    #    man-laptop-registered / unregistered / grinning-laptop). tag = suffix
    #    or None for Clear; pos = expected positions or None to skip.
    spot = [
        ("empty", [], None, None),
        ("ascii", [0x48, 0x65, 0x6C, 0x6C, 0x6F], None, None),
        ("plain-emoji", [0x1F600], None, None),
        ("one-skintone", [0x1F44B, 0x1F3FB], None, None),
        ("family-rgi", [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466], None, None),
        ("double-zwj", [0x1F600, 0x200D, 0x200D, 0x1F600], "DoubleZWJ", [1]),
        ("non-emoji-injection", [0x1F600, 0x200D, 0x0061], "NonEmojiInjection", None),
        ("skin-tone-overflow", [0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF],
         "SkinToneOverflow", []),
        ("man-laptop-registered", [0x1F468, 0x200D, 0x1F4BB], None, None),
        ("unregistered", [0x1F468, 0x200D, 0x1F469], "UnregisteredSequence", None),
        ("grinning-laptop", [0x1F600, 0x200D, 0x1F4BB], "NonEmojiInjection", None),
    ]
    for name, values, tag, expected_pos in spot:
        got = run_ezwj(values)
        ez_codes = [c for c in got["codes"] if ".emoji-zwj-integrity." in c]
        if tag is None:
            require(not ez_codes, f"ezwj-spot/{name} expected clear; got {ez_codes}")
        else:
            code = EZWJ_BASE + tag
            require(code in got["codes"], f"ezwj-spot/{name} missing {code}; got {got['codes']}")
            if expected_pos is not None:
                require(got["positions"].get(code) == expected_pos,
                        f"ezwj-spot/{name} positions {got['positions'].get(code)} != {expected_pos}")

    # 3. Structural checks on the priority order: an over-length chain past the
    #    cap, a trailing-ZWJ injection, and DoubleZWJ outranking the
    #    unregistered catch-all.
    over = [0x1F468]
    for _ in range(8):
        over.append(0x200D)
        over.append(0x1F468)
    require(len(over) == 17, f"ezwj over-length vector wrong length {len(over)}")
    got = run_ezwj(over)
    require(EZWJ_BASE + "OverLength" in got["codes"],
            f"ezwj-struct/over-length missing OverLength; got {got['codes']}")
    require(got["positions"].get(EZWJ_BASE + "OverLength") == [],
            f"ezwj-struct/over-length positions {got['positions'].get(EZWJ_BASE + 'OverLength')} != []")

    trailing = run_ezwj([0x1F468, 0x200D])
    require(EZWJ_BASE + "NonEmojiInjection" in trailing["codes"],
            f"ezwj-struct/trailing-zwj missing NonEmojiInjection; got {trailing['codes']}")
    require(trailing["positions"].get(EZWJ_BASE + "NonEmojiInjection") == [1],
            f"ezwj-struct/trailing-zwj positions {trailing['positions'].get(EZWJ_BASE + 'NonEmojiInjection')} != [1]")

    beats = run_ezwj([0x1F468, 0x200D, 0x200D, 0x1F466])
    require(EZWJ_BASE + "DoubleZWJ" in beats["codes"],
            f"ezwj-struct/double-outranks-unregistered missing DoubleZWJ; got {beats['codes']}")

    return len(fixture["cases"]), len(spot), 3


RD_BASE = "unicode.security.D.renderer-divergence."


def run_rd(values):
    return run("renderer-divergence", "gateway-header", "observe", values)


def check_renderer_divergence():
    # 1. The 9 shared context-free fixture vectors.
    fixture = load("detectors/renderer_divergence.json")
    for case in fixture["cases"]:
        got = run_rd(case["input"])
        for code in case["required_findings"]:
            require(code in got["codes"],
                    f"rd/{case['name']} missing {code}; got {got['codes']}")
        if not case["required_findings"]:
            require(all(".renderer-divergence." not in code for code in got["codes"]),
                    f"rd/{case['name']} unexpected finding; got {got['codes']}")

    # 2. The 9 spot-checks transcribed verbatim from the Rust reference's
    #    `#[test]` module (empty / ascii / han clear, vs-variance,
    #    rgi-family-clear, unregistered-zwj, zalgo-combining-stack, fullwidth,
    #    mixed-direction). tag = suffix or None for Clear; pos = expected
    #    positions or None to skip.
    spot = [
        ("empty", [], None, None),
        ("ascii", [0x48, 0x65, 0x6C, 0x6C, 0x6F], None, None),
        ("han", [0x4E2D, 0x6587], None, None),
        ("vs-variance", [0x1F600, 0xFE0F], "VariationSelectorVariance", [1]),
        ("rgi-family-clear", [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466],
         None, None),
        ("unregistered-zwj", [0x1F468, 0x200D, 0x1F469], "UnregisteredZwjVariance", [1]),
        ("zalgo-combining-stack", [0x0061, 0x0301, 0x0302, 0x0303, 0x0304],
         "CombiningStackOverflow", [0]),
        ("fullwidth", [0xFF21], "FullwidthVariance", [0]),
        ("mixed-direction", [0x41, 0x42, 0x05D0, 0x05D1], "MixedDirectionVariance", []),
    ]
    for name, values, tag, expected_pos in spot:
        got = run_rd(values)
        rd_codes = [c for c in got["codes"] if ".renderer-divergence." in c]
        if tag is None:
            require(not rd_codes, f"rd-spot/{name} expected clear; got {rd_codes}")
        else:
            code = RD_BASE + tag
            require(code in got["codes"], f"rd-spot/{name} missing {code}; got {got['codes']}")
            if expected_pos is not None:
                require(got["positions"].get(code) == expected_pos,
                        f"rd-spot/{name} positions {got['positions'].get(code)} != {expected_pos}")

    # 3. Two structural checks on the priority order: a combining stack outranks
    #    a variation selector present later, and exactly three combining marks
    #    is below the stack threshold (no overflow).
    beats = run_rd([0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F])
    require(RD_BASE + "CombiningStackOverflow" in beats["codes"],
            f"rd-struct/combining-stack-beats-vs missing CombiningStackOverflow; got {beats['codes']}")

    three = run_rd([0x0061, 0x0301, 0x0302, 0x0303])
    require(RD_BASE + "CombiningStackOverflow" not in three["codes"],
            f"rd-struct/three-marks-below-threshold fired CombiningStackOverflow; got {three['codes']}")

    return len(fixture["cases"]), len(spot), 2


FD_BASE = "unicode.security.D.filename-disguise."


def run_fd(values):
    return run("filename-disguise", "gateway-header", "observe", values)


def check_filename_disguise():
    # 1. The 10 shared context-free fixture vectors.
    fixture = load("detectors/filename_disguise.json")
    for case in fixture["cases"]:
        got = run_fd(case["input"])
        for code in case["required_findings"]:
            require(code in got["codes"],
                    f"fd/{case['name']} missing {code}; got {got['codes']}")
        if not case["required_findings"]:
            require(all(".filename-disguise." not in code for code in got["codes"]),
                    f"fd/{case['name']} unexpected finding; got {got['codes']}")

    # 2. The 10 spot-checks transcribed verbatim from the Rust reference's
    #    `#[test]` module (empty / plain-txt / no-ext / tar.gz / hebrew clear,
    #    rlo-flip, isolate-flip, fullwidth-ext, combining-in-ext,
    #    triple-extension). tag = suffix or None for Clear; pos = expected
    #    positions or None to skip.
    spot = [
        ("empty", [], None, None),
        ("plain-txt", [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74],
         None, None),
        ("no-ext", [0x66, 0x6F, 0x6F], None, None),
        ("tar-gz", [0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A],
         None, None),
        ("hebrew", [0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74], None, None),
        ("rlo-flip", [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74,
                      0x2E, 0x65, 0x78, 0x65], "RloFlip", [8]),
        ("isolate-flip", [0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069],
         "RloFlip", None),
        ("fullwidth-ext", [0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25],
         "WidthClassExt", None),
        ("combining-in-ext", [0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65],
         "CombiningInExt", None),
        ("triple-extension", [0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A,
                              0x2E, 0x73, 0x69, 0x67], "MultipleExtensions", None),
    ]
    for name, values, tag, expected_pos in spot:
        got = run_fd(values)
        fd_codes = [c for c in got["codes"] if ".filename-disguise." in c]
        if tag is None:
            require(not fd_codes, f"fd-spot/{name} expected clear; got {fd_codes}")
        else:
            code = FD_BASE + tag
            require(code in got["codes"], f"fd-spot/{name} missing {code}; got {got['codes']}")
            if expected_pos is not None:
                require(got["positions"].get(code) == expected_pos,
                        f"fd-spot/{name} positions {got['positions'].get(code)} != {expected_pos}")

    # 3. One structural check on the priority order: a bidi format-control
    #    outranks a fullwidth extension present later.
    beats = run_fd([0x202E, 0x66, 0x2E, 0xFF25])
    require(FD_BASE + "RloFlip" in beats["codes"],
            f"fd-struct/bidi-beats-fullwidth missing RloFlip; got {beats['codes']}")

    return len(fixture["cases"]), len(spot), 1


def check_forms_and_bip39():
    cases = [
        ("forms", [], []),
        ("forms", [72, 101, 108, 108, 111], []),
        ("forms", [73], ["unicode.security.F.locale-case-inversion.TurkishCaseDivergence"]),
        ("forms", [304], ["unicode.security.F.locale-case-inversion.TurkishCaseDivergence"]),
        ("forms", [74, 768], ["unicode.security.F.locale-case-inversion.LithuanianCaseDivergence"]),
        ("forms", [101, 769], ["unicode.security.F.nfc-idempotence-witness.NonNfcForm"]),
        ("forms", [64257], ["unicode.security.F.nfc-idempotence-witness.NonNfkcCompatForm"]),
        ("forms", [65018], ["unicode.security.F.normalization-bomb.SingleCpBlowup"]),
        ("forms", [65019], ["unicode.security.F.normalization-bomb.NfkdHighExpansion"]),
        ("forms", [8066], ["unicode.security.F.normalization-bomb.NfdHighExpansion"]),
        ("bip39", [97, 98, 97, 110, 100, 111, 110, 32], ["unicode.security.K.bip39-canonical.TrailingWhitespace"]),
        ("bip39", [65, 98, 97, 110, 100, 111, 110], ["unicode.security.K.bip39-canonical.MixedCase"]),
        ("bip39", [97, 98, 97, 110, 100, 111, 110, 32, 32, 97, 98, 111, 117, 116], ["unicode.security.K.bip39-canonical.WhitespaceAnomaly"]),
        ("bip39", [64256], ["unicode.security.K.bip39-canonical.NonNFKD"]),
        ("bip39", [113, 122, 113, 122], ["unicode.security.K.bip39-canonical.WordlistMismatch"]),
    ]
    for op, values, required in cases:
        got = run(op, "gateway-header", "observe", values)
        for code in required:
            require(code in got["codes"], f"{op}/{values} missing {code}; got {got['codes']}")

    mnemonic = cps(" ".join(["abandon"] * 11 + ["about"]))
    valid = run("bip39", "gateway-header", "observe", mnemonic)
    require(
        all(".bip39-canonical." not in code for code in valid["codes"]),
        f"valid generated English BIP39 mnemonic should clear; got {valid['codes']}",
    )

    multilingual = run("bip39", "gateway-header", "observe", cps("abeja"))
    require(
        all(".bip39-canonical." not in code for code in multilingual["codes"]),
        f"generated multilingual BIP39 word should clear; got {multilingual['codes']}",
    )


SS_BASE = "unicode.security.F.stream-safe-violation."


def check_stream_safe_violation():
    # 1. The five shared detector vectors.
    fixture = load("detectors/stream_safe_violation.json")
    for case in fixture["cases"]:
        got = run("stream-safe-violation", "gateway-header", "observe", case["input"])
        for code in case["required_findings"]:
            require(code in got["codes"],
                    f"ss/{case['name']} missing {code}; got {got['codes']}")
        if not case["required_findings"]:
            require(all(".stream-safe-violation." not in code for code in got["codes"]),
                    f"ss/{case['name']} unexpected finding; got {got['codes']}")

    # 2. The 30/31 non-starter-run boundary (U+0301, CCC=230). 30 marks after a
    #    starter stays clear under strict `>`; 31 fires StreamSafeOverrun with
    #    base_pos = the run's first codepoint index (1). A bare 31-mark run
    #    (no leading starter) reports base_pos 0.
    acute = 0x0301
    overrun = SS_BASE + "StreamSafeOverrun"

    thirty = run("stream-safe-violation", "gateway-header", "observe",
                 [0x61] + [acute] * 30)
    require(all(".stream-safe-violation." not in c for c in thirty["codes"]),
            f"ss/thirty-boundary expected clear; got {thirty['codes']}")

    thirtyone = run("stream-safe-violation", "gateway-header", "observe",
                    [0x61] + [acute] * 31)
    require(overrun in thirtyone["codes"],
            f"ss/thirtyone missing {overrun}; got {thirtyone['codes']}")
    require(thirtyone["positions"].get(overrun) == [1],
            f"ss/thirtyone positions {thirtyone['positions'].get(overrun)} != [1]")

    bare = run("stream-safe-violation", "gateway-header", "observe", [acute] * 31)
    require(overrun in bare["codes"],
            f"ss/bare-run missing {overrun}; got {bare['codes']}")
    require(bare["positions"].get(overrun) == [0],
            f"ss/bare-run positions {bare['positions'].get(overrun)} != [0]")

    return len(fixture["cases"]) + 3


def check_generated_tables():
    variation = run("scan", "gateway-header", "observe", [35, 65038])
    require(
        all(".variation-selector-payload." not in code for code in variation["codes"]),
        f"generated variation table did not clear registered pair; got {variation['codes']}",
    )

    ignorable = run("scan", "gateway-header", "observe", [65, 847, 66])
    require(
        "unicode.security.C.zero-width-payload.BareZeroWidth" in ignorable["codes"],
        f"generated Default_Ignorable table missed U+034F; got {ignorable['codes']}",
    )

    scripts = run("scan", "gateway-header", "observe", [42958, 945])
    require(
        "unicode.security.I.mixed-script-admissibility.LatinGreek" in scripts["codes"],
        f"generated Scripts table missed non-ASCII Latin + Greek; got {scripts['codes']}",
    )

    rtl = run("scan", "gateway-header", "observe", [65, 68192, 66])
    require(
        "unicode.security.D.rtl-injection.StrongRTLInLTR" in rtl["codes"],
        f"generated bidi table missed Old South Arabian RTL; got {rtl['codes']}",
    )

    confusable = run("scan", "gateway-header", "observe", [8238, 42959])
    require(
        "unicode.security.X.confusable-bidi-compound.ConfusableInOverride" in confusable["codes"],
        f"generated confusables table missed U+A7CF source; got {confusable['codes']}",
    )


BLOB_VECTORS = [
    ("ascii", [65], True),
    ("empty", [], True),
    ("two-byte", [195, 169], True),
    ("three-byte", [226, 130, 172], True),
    ("four-byte", [240, 159, 152, 128], True),
    ("overlong-c0-80", [192, 128], False),
    ("surrogate-ed-a0-80", [237, 160, 128], False),
    ("truncated-two-byte", [195], False),
    ("lone-continuation", [169], False),
    ("beyond-max-f4-90", [244, 144, 128, 128], False),
]


def check_opaque_blob():
    count = 0
    for name, byts, valid in BLOB_VECTORS:
        lines = run_lines("is-utf8-blob", byts)
        require(len(lines) >= 1 and lines[0].startswith("BLOB "),
                f"opaque-blob/{name} malformed output {lines}")
        got = lines[0].split(" ", 1)[1]
        want = "valid" if valid else "invalid"
        require(got == want, f"opaque-blob/{name} got {got} want {want}")
        count += 1
    return count


def check_validated_utf8():
    count = 0
    for name, byts, valid in BLOB_VECTORS:
        lines = run_lines("validate-utf8", byts)
        require(len(lines) >= 1 and lines[0].startswith("VALIDATE "),
                f"validated-utf8/{name} malformed output {lines}")
        got = lines[0].split(" ", 1)[1]
        want = "valid" if valid else "invalid"
        require(got == want, f"validated-utf8/{name} got {got} want {want}")
        if valid:
            byte_lines = [ln for ln in lines if ln.startswith("BYTES")]
            require(len(byte_lines) == 1, f"validated-utf8/{name} missing BYTES echo {lines}")
            rest = byte_lines[0][len("BYTES"):].strip()
            echoed = [int(x) for x in rest.split(",") if x]
            require(echoed == byts,
                    f"validated-utf8/{name} echo {echoed} != input {byts}")
        else:
            require(all(not ln.startswith("BYTES") for ln in lines),
                    f"validated-utf8/{name} echoed bytes for invalid input {lines}")
        count += 1
    return count


def parse_grapheme_break_test(path):
    cases = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            body = raw.split("#", 1)[0].strip()
            if not body:
                continue
            cps = []
            boundaries = []
            for token in body.split():
                if token == "÷":
                    boundaries.append(len(cps))
                elif token == "×":
                    pass
                else:
                    cps.append(int(token, 16))
            cases.append((cps, boundaries))
    return cases


def check_grapheme():
    path = Path(__file__).resolve().parent / "GraphemeBreakTest.txt"
    cases = parse_grapheme_break_test(path)
    require(cases, "GraphemeBreakTest.txt produced no cases")
    count = 0
    for cps, expected in cases:
        lines = run_lines("grapheme", cps)
        bound_lines = [ln for ln in lines if ln.startswith("BOUNDARIES")]
        require(len(bound_lines) == 1, f"grapheme {cps} missing BOUNDARIES {lines}")
        rest = bound_lines[0][len("BOUNDARIES"):].strip()
        got = [int(x) for x in rest.split(",") if x]
        require(got == expected,
                f"grapheme {cps} boundaries {got} != expected {expected}")
        count += 1
    return count


def main():
    check_policy()
    check_decode()
    check_multiencoding_decode()
    check_verdict()
    check_detectors()
    his_fixture_count, his_context_count = check_hash_input_stability()
    awd_fixture_count, awd_context_count = check_ai_watermark_detectability()
    ezwj_fixture_count, ezwj_spot_count, ezwj_struct_count = check_emoji_zwj_integrity()
    rd_fixture_count, rd_spot_count, rd_struct_count = check_renderer_divergence()
    fd_fixture_count, fd_spot_count, fd_struct_count = check_filename_disguise()
    check_forms_and_bip39()
    ss_count = check_stream_safe_violation()
    check_generated_tables()
    blob_count = check_opaque_blob()
    validated_count = check_validated_utf8()
    grapheme_count = check_grapheme()
    print(f"opaque-blob checks: {blob_count}")
    print(f"validated-utf8 checks: {validated_count}")
    print(f"grapheme (GraphemeBreakTest.txt) checks: {grapheme_count}")
    print(f"hash-input-stability shared-fixture vectors: {his_fixture_count}")
    print(f"hash-input-stability context vectors: {his_context_count}")
    print(f"ai-watermark-detectability shared-fixture vectors: {awd_fixture_count}")
    print(f"ai-watermark-detectability context vectors: {awd_context_count}")
    print(f"stream-safe-violation checks: {ss_count}")
    print(f"emoji-zwj-integrity shared-fixture vectors: {ezwj_fixture_count}")
    print(f"emoji-zwj-integrity spot-checks: {ezwj_spot_count}")
    print(f"emoji-zwj-integrity structural checks: {ezwj_struct_count}")
    print(f"renderer-divergence shared-fixture vectors: {rd_fixture_count}")
    print(f"renderer-divergence spot-checks: {rd_spot_count}")
    print(f"renderer-divergence structural checks: {rd_struct_count}")
    print(f"filename-disguise shared-fixture vectors: {fd_fixture_count}")
    print(f"filename-disguise spot-checks: {fd_spot_count}")
    print(f"filename-disguise structural checks: {fd_struct_count}")
    print("ok: cobol unicode security fixture tests pass")


if __name__ == "__main__":
    main()
