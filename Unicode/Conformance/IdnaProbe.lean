/-
  Unicode.Conformance.IdnaProbe

  Quick #eval-based probe of specific IdnaTestV2 rows to spot-check
  pipeline behaviour without paying for a full 6389-row native_decide
  pass. Each #eval runs `toUnicode` / `toAscii` / `toAsciiTransitional`
  on a hand-picked input and dumps the `Map.Result` for inspection.
-/

import Unicode.Idna.Process

namespace Unicode.Conformance.IdnaProbe

open Unicode.Idna.Process

-- ────────────────────────────────────────────────────────────────────────────
-- Row 295: `xn--u-ccb` → decodes to non-NFC `u + COMBINING DIAERESIS`
-- Expected: toUnicode output = [117, 776], errors = true (V1)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 295 toU = {toUnicode #[120, 110, 45, 45, 117, 45, 99, 99, 98]}"
#eval s!"row 295 toA = {toAscii #[120, 110, 45, 45, 117, 45, 99, 99, 98]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 312: `xn--xn--a--gua.pt` → decodes to malicious xn--... form
-- Expected: toUnicode errors = true (V2, V4)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 312 toU = {toUnicode #[120, 110, 45, 45, 120, 110, 45, 45, 97, 45, 45, 103, 117, 97, 46, 112, 116]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 296: `a⒈com` (a + U+2488 + com) — U+2488 is Disallowed
-- Expected: toUnicode errors = true (V7 marker; my P1/V6 fires)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 296 toU = {toUnicode #[97, 0x2488, 99, 111, 109]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 9: `0à.א` (LTR digit + Hebrew letter) — Bidi domain, label 1 starts with EN
-- Expected: toUnicode errors = true (B1)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 9 toU = {toUnicode #[48, 224, 46, 1488]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 158: `a.b.c.d.` with fullwidth dots — trailing empty label after mapping
-- Expected: toUnicode errors = false; toAscii errors = true (A4_1)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 158 toU = {toUnicode #[97, 46, 98, 65294, 99, 12290, 100, 65377]}"
#eval s!"row 158 toA = {toAscii #[97, 46, 98, 65294, 99, 12290, 100, 65377]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 90: `。` (U+3002) → maps to '.' alone — leading + trailing empty after mapping
-- Expected: toUnicode errors = true
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 90 toU = {toUnicode #[12290]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 140: `àˇ.א` — "à" + CARON (B6: NSM at end of LTR label)
-- Expected: toUnicode errors = true (B6)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 140 toU = {toUnicode #[224, 711, 46, 1488]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 153: `a‌b` — ZWNJ joiner without context
-- Expected: toUnicode errors = true (C1)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 153 toU = {toUnicode #[97, 0x200C, 98]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 543: `$` — disallowed by STD3 ASCII rules (not LDH)
-- Expected: toUnicode errors = true (U1)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 543 toU = {toUnicode #[36]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 545: `(4).four` — parens are not LDH
-- Expected: toUnicode errors = true (U1)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 545 toU = {toUnicode #[40, 52, 41, 46, 102, 111, 117, 114]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 302: `xn--0.pt` — Punycode decode of "0" is suspicious
-- Expected: toUnicode errors = true (P4)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 302 toU = {toUnicode #[120, 110, 45, 45, 48, 46, 112, 116]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 304: `xn--a-Ä.pt` — invalid xn-- input (non-ASCII inside)
-- Expected: toUnicode errors = true (P4)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 304 toU = {toUnicode #[120, 110, 45, 45, 97, 45, 196, 46, 112, 116]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 128: `à.א0٠א` — Bidi domain, RTL label has both EN (0) and AN (٠)
-- Expected: toUnicode errors = true (B4: no mixed EN/AN in RTL)
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 128 toU = {toUnicode #[224, 46, 1488, 48, 1632, 1488]}"

-- ────────────────────────────────────────────────────────────────────────────
-- Row 153 toAsciiTransitional: `a‌b` → "ab" with NO error (transitional drops ZWNJ)
-- Expected: toAsciiT output = "ab", errors = false ([])
-- ────────────────────────────────────────────────────────────────────────────
#eval s!"row 153 toAT = {toAsciiTransitional #[97, 0x200C, 98]}"

end Unicode.Conformance.IdnaProbe
