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


def main():
    check_policy()
    check_decode()
    check_multiencoding_decode()
    check_verdict()
    check_detectors()
    check_forms_and_bip39()
    check_generated_tables()
    print("ok: cobol unicode security fixture tests pass")


if __name__ == "__main__":
    main()
